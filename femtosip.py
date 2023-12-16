#!/usr/bin/env python3

#   FemtoSIP -- A minimal SIP client
#   Copyright (C) 2017-2023  Andreas Stöckel
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.

import collections
import hashlib
import socket
import select
import random
import re
import time
import logging

# Create the logger
logger = logging.getLogger('femtosip')

###############################################################################
# Helper functions                                                            #
###############################################################################

def format_sip_header_field(key):
    """
    Brings SIP header fields to a canonical form. E.g. 'content-length' becomes
    'Content-Length', cseq becomes 'CSeq' and call-id becomes 'Call-ID'.
    """
    if isinstance(key, bytes) or isinstance(key, bytearray):
        key = str(key, 'ascii')
    key = key.lower()

    # Special cases
    if key == 'call-id':
        return 'Call-ID'
    elif key == 'cseq':
        return 'CSeq'
    elif key == 'www-authenticate':
        return 'WWW-Authenticate'

    # Generic case
    res = ''
    for i in range(len(key)):
        if i == 0 or key[i - 1] == '-':
            res += key[i].upper()
        else:
            res += key[i]
    return res


###############################################################################
# Digest handling (see RFC 7616)                                              #
###############################################################################

class DigestTokenizer:
    def __init__(self):
        self.buf = ""
        self.tokens = []
        self.status = 0

    def emit(self, special=None):
        if self.buf or (self.status != 0):
            self.tokens.append((False, self.buf))
        if special is not None:
            self.tokens.append((True, special))
        self.buf = ""

    def feed(self, data, last=True):
        STATUS_INITIAL = 0
        STATUS_IN_QUOTES = 1
        STATUS_IN_QUOTES_ESCAPE = 2

        for i in range(len(data)):
            is_ws = data[i].isspace()
            if self.status == STATUS_INITIAL:
                if is_ws:
                    self.emit()
                elif (data[i] == '=') or (data[i] == ","):
                    self.emit(data[i])
                elif data[i] == "\"":
                    self.emit()
                    self.status = STATUS_IN_QUOTES
                else:
                    self.buf += data[i]
            elif self.status == STATUS_IN_QUOTES:
                if data[i] == "\"":
                    self.emit()
                    self.status = STATUS_INITIAL
                elif data[i] == "\\":
                    self.status = STATUS_IN_QUOTES_ESCAPE
                else:
                    self.buf += data[i]
            elif self.status == STATUS_IN_QUOTES_ESCAPE:
                self.buf += data[i]
                self.status = STATUS_IN_QUOTES

        if last:
            self.emit()

        return self.tokens

    @staticmethod
    def tokenize(data):
        return DigestTokenizer().feed(data)


def parse_digest(data):
    ST_INITIAL, ST_KEY, ST_EQ, ST_VALUE, ST_COMMA = 0, 1, 2, 3, 4
    tokens = DigestTokenizer.tokenize(data)
    status, fields, key = ST_INITIAL, {}, None
    for token in tokens:
        if status == ST_INITIAL:
            if token[0] or token[1].lower() != "digest":
                return None
        elif status == ST_KEY:
            if token[0]:
                return None
            key = token[1].lower()
        elif status == ST_EQ:
            if (not token[0]) or (token[1] != "="):
                return None
        elif status == ST_VALUE:
            if token[0]:
                return None
            fields[key] = token[1]
        elif status == ST_COMMA:
            if (not token[0]) or (token[1] != ","):
                return None
        status = max(1, (status + 1) % 5) # Wrap around back to ST_KEY
    return fields


def digest_response(user, password, realm, nonce, method, uri):
    ha1 = hashlib.md5()
    ha1.update(
        user.encode('utf-8') + b':' +
        realm.encode('utf-8') + b':' +
        password.encode('utf-8')
    )

    ha2 = hashlib.md5()
    ha2.update(
        method.upper().encode('utf-8') + b':' +
        uri.encode('utf-8')
    )

    res = hashlib.md5()
    res.update(
        ha1.hexdigest().lower().encode('ascii') + b':' +
        nonce.encode('utf-8') + b':' +
        ha2.hexdigest().lower().encode('ascii')
    )
    return res.hexdigest().lower()


##############################################################################
# SIP response (i.e., HTTP-like header) parser                               #
##############################################################################

class ResponseParser:
    """
    Parses HTTP-like response headers (such as responses from a SIP server).
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self._had_lf = False
        self._n_linebreaks = 0
        self._status = 0
        self._key = bytearray()
        self._value = bytearray()
        self._content_length = 0
        self._skip_ws = True

        self.protocol = bytearray()
        self.code = bytearray()
        self.message = bytearray()
        self.fields = collections.OrderedDict()
        self.body = bytearray()

    def feed(self, data, callback):
        """
        Parses the given bytes/bytearray and calls the given callback with each
        parsed response. First and single parameter to the callback function is
        this parser instance. Access the protocol, code, message, fields and
        body member variables for the parsed content.
        """
        response = [False]

        def call_callback():
            # Convert the message code to an integer
            try:
                self.code = int(str(self.code, 'ascii'))
            except:
                logger.error('Received invalid response code')
                self.code = -1

            # Convert the protocol and the message to a string
            try:
                self.protocol = str(self.protocol, 'ascii')
                self.message = str(self.message, 'ascii')
            except:
                logger.error('Invalid protocol or message')

            # Convert the body to "bytes"
            self.body = bytes(self.body)

            # Call the callback
            response[0] = True
            self._status = STATUS_INITIAL
            callback(self)

        STATUS_INITIAL = 0
        STATUS_PROTOCOL = 1
        STATUS_CODE = 2
        STATUS_MESSAGE = 3
        STATUS_HEADER_KEY = 4
        STATUS_HEADER_VALUE = 5
        STATUS_BODY = 6

        # Iterate over the initial bytes and assemble the result
        i = 0
        while i < len(data):
            # Skip whitespace if requested
            is_ws = (data[i] == b' '[0] or data[i] == b'\t'[0])
            if self._skip_ws and is_ws:
                i += 1
                continue
            self._skip_ws = False

            # Re-initialise
            if self._status == STATUS_INITIAL:
                self.reset()
                self._status = STATUS_PROTOCOL
                continue

            # Handle linebreaks
            if self._status != STATUS_BODY:
                # Handle '\r'
                if data[i] == b'\r'[0]:
                    self._had_lf = True
                    i += 1
                    continue

                # Handle '\n\r'
                if data[i] == b'\n'[0] and self._had_lf:
                    # Go to the next state if a line-feed is found
                    if self._status < STATUS_HEADER_KEY:
                        self._status = STATUS_HEADER_KEY
                    elif (self._status == STATUS_HEADER_KEY or
                          self._status == STATUS_HEADER_VALUE):
                        if len(self._key) > 0:
                            try:
                                key = format_sip_header_field(self._key)
                                if key == 'Content-Length':
                                    try:
                                        self._content_length = int(self._value)
                                    except:
                                        logger.error('Received invalid Content-Length')
                                        self._content_length = 0
                                self.fields[key] = bytes(self._value.strip())
                            except:
                                logger.error('Invalid header key')
                                raise
                        self._key = bytearray()
                        self._value = bytearray()
                        self._status = STATUS_HEADER_KEY

                    # Count linebreaks, body starts with the second linebreak
                    self._n_linebreaks += 1
                    if self._n_linebreaks == 2:
                        self._status = STATUS_BODY

                    # We've handled this character, continue
                    i += 1
                    continue

                # This is not a linebreak, reset the linebreak data
                self._had_lf = False
                self._n_linebreaks = 0

            # Switch between fields in the first response line
            if self._status < STATUS_MESSAGE and is_ws:
                self._skip_ws = True
                self._status += 1
                continue

            # Switch betwen states
            if self._status == STATUS_PROTOCOL:
                self.protocol.append(data[i])
            elif self._status == STATUS_CODE:
                self.code.append(data[i])
            elif self._status == STATUS_MESSAGE:
                self.message.append(data[i])
            elif self._status == STATUS_HEADER_KEY:
                if (data[i] == b':'[0]):
                    i += 1
                    self._skip_ws = True
                    self._status = STATUS_HEADER_VALUE
                    continue
                self._key.append(data[i])
            elif self._status == STATUS_HEADER_VALUE:
                self._value.append(data[i])
            elif self._status == STATUS_BODY:
                if self._content_length > 0:
                    self.body.append(data[i])
                    self._content_length -= 1
                if self._content_length == 0:
                    i += 1
                    call_callback()
                    continue

            # Increase the read pointer by one
            i += 1

        # Explicitly call the callback if this is the end of the data
        if self._status == STATUS_BODY and self._content_length == 0:
            call_callback()

        # Return true if the callback has been called
        return response[0]


###############################################################################
# Main SIP state-machine                                                      #
###############################################################################

class SIP:
    """
    The SIP class implements a minimal, incomplete, and likely broken SIP 
    endpoint that is capable of initiating a phone call to a third party 
    (without any NAT traversal).
    """

    ALLOW = 'INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO'

    def __init__(self, user, password, gateway, port, display_name=None, local_ip = None, protocol = "tcp"):
        # Copy the parameters
        self.user = user
        self.password = password
        self.local_ip, self.local_port = local_ip, None # Allow IP to be specified. Enables use on WAN.
        self.gateway = gateway
        self.port = port
        self.display_name = display_name
        self.protocol = protocol

        # Initilise the session parameters
        self.seq = 0
        self.session_id = self.make_random_digits(4)
        self.session_version = self.make_random_digits(4)

    @staticmethod
    def make_sip_packet(method, uri, fields, data=b''):
        """
        The sip_packet method assembles a single sip_packet consisting of a
        request method, request uri, header fields, and some payload data.
        The ContentLength header field is automatically added to the header
        depending on the given payload data. Returns a bytes instance containg
        the bytes that should be sent to the server.

        method: is the request method. Will be converted to upper-case and
                encoded as ascii.
        uri: is the request URI that will be appended to the method. Will be 
             converted to ascii.
        fields: is a dict containing the header fields as key-value pairs.
        data: is optional payload data. Must by a bytes object.
        """
        res = (method.upper().encode('ascii') + b' ' +
             uri.encode('ascii') + b' SIP/2.0\r\n')
        for key, value in fields.items():
            res += format_sip_header_field(key).encode('ascii') + b': ' + value.encode('utf-8') + b'\r\n'
        res += b'Content-Length: ' + str(len(data)).encode('ascii') + b'\r\n\r\n'
        res += data
        return res

    @staticmethod
    def make_random_digits(len=10):
        res = ''
        for i in range(len):
            res += str(random.randint(1 if i == 0 else 0, 9))
        return res

    def make_branch(self):
        return 'z9hG4bK' + self.make_random_digits(10)

    def make_from_field(self, remote_host, tag):
        from_field = '<sip:' + self.user + '@' + remote_host + '>;tag=' + tag

        if self.display_name:
            from_field = '"' + self.display_name + '" ' + from_field

        return from_field

    def make_invite_sip_packet(self,
            remote_id, remote_host,
            branch, tag, call_id, seq, realm=None, nonce=None):
        # Assemble the request uri
        uri = 'sip:' + remote_id + '@' + remote_host

        # Assemble the header fields
        fields = collections.OrderedDict()
        fields['Via'] = (
            'SIP/2.0/' + self.protocol.upper() + ' ' + self.local_ip_header + ':' + str(self.port) +
            ';rport;branch=' + branch)
        fields['From'] = self.make_from_field(remote_host, tag)
        fields['To'] = (
            '<sip:' + remote_id + '@' + remote_host + '>')
        fields['Call-ID'] = str(call_id)
        fields['CSeq'] = str(seq) + ' INVITE'
        fields['Contact'] = (
            '<sip:' + self.user + '@' + self.local_ip_header +
            ':' + str(self.local_port) + ';transport=' + self.protocol.lower() + '>')
        fields['Content-Type'] = 'application/sdp'
        fields['Allow'] = self.ALLOW
        fields['Max-Forwards'] = '70'

        if (not realm is None) and (not nonce is None):
            fields['Authorization'] = (
                'Digest username=\"' + self.user + "\", " +
                          "realm=\"" + realm + "\", " +
                          "nonce=\"" + nonce + "\", " +
                            "uri=\"" + uri + "\", " +
                       "response=\"" + digest_response(
                            self.user, self.password,
                            realm, nonce, 'INVITE', uri) + "\", " +
                      "algorithm=\"MD5\"")

        return self.make_sip_packet('INVITE', uri, fields)


    def make_cancel_sip_packet(self, remote_id, remote_host, branch, tag, call_id, seq):
        # Assemble the request uri
        uri = 'sip:' + remote_id + '@' + remote_host

        # Assemble the header fields
        fields = collections.OrderedDict()
        fields['Via'] = (
            'SIP/2.0/' + self.protocol.upper() + ' ' + self.local_ip_header + ':' + str(self.port) +
            ';rport;branch=' + branch)
        fields['From'] = self.make_from_field(remote_host, tag)
        fields['To'] = (
            '<sip:' + remote_id + '@' + remote_host + '>')
        fields['Call-ID'] = str(call_id)
        fields['CSeq'] = str(seq) + ' CANCEL'
        fields['Max-Forwards'] = '70'

        return self.make_sip_packet('CANCEL', uri, fields)

    def make_bye_sip_packet(self, remote_id, remote_host, branch, tag, remote_tag, call_id, seq):
        # Assemble the request uri
        uri = 'sip:' + remote_id + '@' + remote_host

        # Assemble the header fields
        fields = collections.OrderedDict()
        fields['Via'] = (
            'SIP/2.0/' + self.protocol.upper() + ' ' + self.local_ip_header + ':' + str(self.port) +
            ';rport;branch=' + branch)
        fields['From'] = self.make_from_field(remote_host, tag)
        fields['To'] = (
            '<sip:' + remote_id + '@' + remote_host + '>;tag=' + remote_tag)
        fields['Call-ID'] = str(call_id)
        fields['CSeq'] = str(seq) + ' BYE'
        fields['Max-Forwards'] = '70'

        return self.make_sip_packet('BYE', uri, fields)

    def make_socket(self):
        if self.protocol.lower() == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.protocol.lower() == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif self.protocol.lower() == "udp6":
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        elif self.protocol.lower() == "tcp6":
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            raise Exception('Unsupported protocol.')
        sock.connect((self.gateway,self.port))
        if self.local_ip:
            self.local_port = sock.getsockname()[1]
        else:
            self.local_ip, self.local_port = sock.getsockname()[0:2]
        sock.setblocking(0)

        return sock

    def call(self, remote_id, delay=15.0, timeout=1.0):
        # Generate a call_id and increase the sequence number
        self.seq += 1
        tag = self.make_random_digits()
        call_id = self.make_random_digits()

        # Object containing the state of the s
        state = {
            'done': False,
            'status': 'send_invite',
            'tries': 0,
            'realm': None,
            'nonce': None,
            'last_request': time.time(),
            'delay_start': 0,
            'remote_tag': None,
        }

        def error(msg):
            logger.error(msg)
            state['done'] = True

        # Function advancing the state machine
        def handle_response(res):
            logger.info('response: ' + res.protocol + ' ' +
                        str(res.code) + ' ' + res.message)

            # Handle the individual response codes
            if res.code == 401:
                # Increment the number of tries
                state['tries'] += 1

                # Abort if we get more than one authentication error in a row
                if state['tries'] > 1:
                    error('Authentication failed. Check password and username.')
                    return

                # Read realm and nonce
                if not 'WWW-Authenticate' in res.fields:
                    error('Did not find "WWW-Authenticate" field')
                    return
                auth = str(res.fields['WWW-Authenticate'], 'ascii')
                auth_fields = parse_digest(auth)
                if (auth_fields is None) or ('realm' not in auth_fields) or ('nonce' not in auth_fields):
                    error('Could not parse "WWW-Authenticate" header, authentication methods other than digest are not supported.')
                state['realm'] = auth_fields['realm']
                state['nonce'] = auth_fields['nonce']

                # Try again
                self.seq += 1
                if state['status'].startswith('done_'):
                    state['status'] = state['status'][5:]
            elif res.code == 100 or res.code == 101:
                # Ignore this response, everything is fine
                pass
            elif res.code == 183 or res.code == 180:
                if not 'From' in res.fields:
                    error('Did not find "To" field')
                    return
                state['status'] = 'delay' # Phones are ringing, wait
                state['delay_start'] = time.time()
            elif res.code == 603: # Decline
                state['done'] = True
            elif res.code == 200:
                if state['status'] == 'delay':
                    self.seq += 1
                    state['remote_tag'] = str(res.fields['To'].split(b';', 2)[-1].split(b'=', 2)[-1], 'ascii')
                    state['status'] = 'send_bye'
                if state['status'] == 'done_send_bye':
                    state['done'] = True
            elif res.code == 487 and state['status'] == 'done_send_cancel':
                state['done'] = True
            elif res.code >= 400:
                error('Unhandled error.')
                state['done'] = True

        writebuf = bytearray()
        with self.make_socket() as sock:
            # IPv6 heuristics
            self.protocol = self.protocol[:3]
            self.local_ip_header = '[' + self.local_ip + ']' if ':' in self.local_ip else self.local_ip
            self.gateway_header = '[' + self.gateway + ']' if ':' in self.gateway else self.gateway

            while not state['done']:
                now = time.time()
                try:
                    if state['status'] == 'send_invite':
                        logger.info('request: INVITE sip:'
                            + remote_id + '@' + self.gateway_header)
                        branch = self.make_branch()
                        writebuf += self.make_invite_sip_packet(
                                remote_id, self.gateway_header,
                                branch, tag, call_id, self.seq,
                                state['realm'], state['nonce'])
                        state['status'] = 'done_send_invite'
                    elif state['status'] == 'send_cancel':
                        logger.info('request: CANCEL sip:'
                            + remote_id + '@' + self.gateway_header)
                        writebuf += self.make_cancel_sip_packet(
                                remote_id, self.gateway_header,
                                branch, tag, call_id, self.seq)
                        state['status'] = 'done_send_cancel'
                    elif state['status'] == 'send_bye':
                        logger.info('request: BYE sip:'
                            + remote_id + '@' + self.gateway_header)
                        branch = self.make_branch()
                        writebuf += self.make_bye_sip_packet(
                                remote_id, self.gateway_header,
                                branch, tag, state['remote_tag'],
                                call_id, self.seq)
                        state['status'] = 'done_send_bye'
                    elif state['status'] == 'delay':
                        if now - state['delay_start'] > delay:
                            state['status'] = 'send_cancel'
                    elif now - state['last_request'] > timeout:
                        error('Timeout while waiting for server response')

                    # Check whether we can read or write from the socket
                    can_read, can_write, in_error = \
                        select.select([sock], [sock], [sock], 10e-3)
                    if len(in_error) > 0:
                        error('Socket error')
                    else:
                        if len(can_read) > 0:
                            readbuf = sock.recv(4096)
                            ResponseParser().feed(readbuf, handle_response)
                        if len(can_write) > 0 and len(writebuf) > 0:
                            state['last_request'] = time.time()
                            sent = sock.send(writebuf)
                            if sent == 0:
                                error('Error while writing to socket')
                            writebuf = writebuf[sent:]
                except KeyboardInterrupt:
                    if state['status'] == 'delay':
                        state['status'] = 'send_cancel'
                    else:
                        state['done'] = True


#
# Main program
#

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='A microscopic SIP client that can be used to ring a ' + 
                    'phone.')
    parser.add_argument('--gateway', required=True,
        help='Hostname or IP address of the SIP server')
    parser.add_argument('--port', default=5060, type=int,
        help='Port of the SIP server (default 5060)')
    parser.add_argument('--user', required=True,
        help='Username used for authentication at the SIP server')
    parser.add_argument('--password', default='',
        help='Password used in conjunction with the user for authentication ' +
             'at the SIP server. (default '')')
    parser.add_argument('--displayname', default=None,
        help='Alter the displayed caller name. (defaults to SIP configuration)')
    parser.add_argument('--localip', default=None)
    parser.add_argument('--protocol', default="tcp", 
        help='supported protocols: IPv4: udp/tcp, IPv6: udp6/tcp6')
    parser.add_argument('--call', required=True,
        help='Phone number of the endpoint that will be called')
    parser.add_argument('--delay', default=15.0, type=float,
        help='Pause in seconds until the call is canceled (default 15.0)')
    parser.add_argument('--timeout', default=1.0, type=float,
        help='Period in seconds the SIP server must respond within (default 1.0)')

    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)
    sip = SIP(args.user, args.password, args.gateway, args.port, args.displayname, args.localip, args.protocol)
    sip.call(args.call, args.delay, args.timeout)
