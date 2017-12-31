#!/usr/bin/env python3

#   MicroSIP -- A microscopic SIP client
#   Copyright (C) 2017  Andreas Stöckel
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

import argparse
import collections
import hashlib
import os
import socket
import select
import random
import re
import sys
import time

def format_sip_header_field(key):
    '''
    Brings SIP header fields to a canonical form.
    '''
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
                sys.stderr.write('Received invalid response code\n')
                self.code = -1

            # Convert the protocol and the message to a string
            try:
                self.protocol = str(self.protocol, 'ascii')
                self.message = str(self.message, 'ascii')
            except:
                sys.stderr.write('Invalid protocol or message\n')

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
                                        sys.stderr.write('Received invalid content-length\n')
                                        self._content_length = 0
                                self.fields[key] = bytes(self._value.strip())
                            except:
                                sys.stderr.write('Invalid header key\n')
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


class SIP:
    """
    The SIP class implements a minimal, incomplete, and likely broken SIP 
    endpoint that is capable of initiating a phone call to a third party 
    (without any NAT traversal).
    """

    ALLOW = 'INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO'

    def __init__(self, user, password, gateway, port):
        # Copy the parameters
        self.user = user
        self.password = password
        self.local_ip, self.local_port = None, None # To be read dynamically
        self.gateway = gateway
        self.port = port

        # Initilise the session parameters
        self.seq = 0
        self.seed = os.urandom(32)
        self.session_id = self.make_random_digits(4);
        self.session_version = self.make_random_digits(4);
        self.media_port = 7078 + random.randint(0, 100)

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
        res = '';
        for i in range(len):
            res += str(random.randint(1 if i == 0 else 0, 9))
        return res

    def make_tag(self):
        return self.make_random_digits(10)

    def make_branch(self):
        return 'z9hG4bK' + self.make_random_digits(10)

    def make_invite_sip_packet(self,
            remote_id, remote_host,
            branch, tag, call_id, seq, realm=None, nonce=None):
        # Assemble the request uri
        uri = 'sip:' + remote_id + '@' + remote_host;

        # Assemble the header fields
        fields = collections.OrderedDict()
        fields['Via'] = (
            'SIP/2.0/TCP ' + self.local_ip + ':' + str(self.port) +
            ';rport;branch=' + branch)
        fields['From'] = (
            '<sip:' + self.user + '@' + remote_host + '>;tag=' + tag)
        fields['To'] = (
            '<sip:' + remote_id + '@' + remote_host + '>')
        fields['Call-ID'] = str(call_id)
        fields['CSeq'] = str(seq) + ' INVITE'
        fields['Contact'] = (
            '<sip:' + self.user + '@' + self.local_ip +
            ':' + str(self.local_port) + ';transport=tcp>')
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
        uri = 'sip:' + remote_id + '@' + remote_host;

        # Assemble the header fields
        fields = collections.OrderedDict()
        fields['Via'] = (
            'SIP/2.0/TCP ' + self.local_ip + ':' + str(self.port) +
            ';rport;branch=' + branch)
        fields['From'] = (
            '<sip:' + self.user + '@' + remote_host + '>;tag=' + tag)
        fields['To'] = (
            '<sip:' + remote_id + '@' + remote_host + '>')
        fields['Call-ID'] = str(call_id)
        fields['CSeq'] = str(seq) + ' CANCEL'
        fields['Max-Forwards'] = '70'

        return self.make_sip_packet('CANCEL', uri, fields)

    def make_socket(self):
        sock = socket.create_connection((self.gateway, self.port))
        sock.setblocking(0)
        self.local_ip, self.local_port = sock.getsockname()[0:2]
        return sock

    def call(self, remote_id, delay=10.0):
        # Generate a call_id and increase the sequence number
        self.seq += 1
        tag = self.make_tag()
        call_id = self.make_random_digits(10)

        # Object containing the state of the s
        state = {
            'done': False,
            'status': 'send_invite',
            'tries': 0,
            'realm': None,
            'nonce': None,
            'delay_start': 0,
            'ack_stack': []
        }

        def error(msg):
            sys.stderr.write('Error: ' + msg)
            state['done'] = True

        # Function advancing the state machine
        def handle_response(res):
            # Debug message
            sys.stderr.write('Response: '
                + res.protocol + ' '
                + str(res.code) + ' '
                + res.message + '\n')

            if res.code == 401:
                # Increment the number of tries
                state['tries'] += 1

                # Abort if we get more than one authentication error in a row
                if state['tries'] > 1:
                    error('Authentication failed. Check password and username.\n')
                    return

                # Read realm and nonce
                if not 'WWW-Authenticate' in res.fields:
                    error('Did not find "WWW-Authenticate" field')
                    return
                auth = str(res.fields['WWW-Authenticate'], 'ascii');
                match = re.match(
                    r'^[Dd]igest\s+realm="([^"]*)"\s*,\s*nonce="([^"]*)"$',
                    auth)
                if not res:
                    error('Could not parse "WWW-Authenticate" header, authentication methods other than digest are not supported.')
                state['realm'] = match.group(1)
                state['nonce'] = match.group(2)

                # Ack nowledge the error
                state['ack_stack'].append(res.fields)

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
            elif res.code == 200: # OK
                if state['status'] == 'done_send_cancel':
                    state['done'] = True
                else:
                    state['status'] = 'send_cancel'
            elif res.code == 603: # Decline
                state['status'] = 'send_cancel'
            elif res.code == 487:
                state['done'] = True
            elif res.code >= 400:
                error('Unhandled error.\n')
                state['done'] = True

        writebuf = bytearray()
        with self.make_socket() as sock:
            while not state['done']:
                if state['status'] == 'send_invite':
                    sys.stderr.write('Request : INVITE sip:'
                        + remote_id + '@' + self.gateway + '\n')
                    branch = self.make_branch()
                    writebuf += self.make_invite_sip_packet(
                            remote_id, self.gateway,
                            branch, tag, call_id, self.seq,
                            state['realm'], state['nonce'])
                    state['status'] = 'done_send_invite'
                elif state['status'] == 'send_cancel':
                    sys.stderr.write('Request : CANCEL sip:'
                        + remote_id + '@' + self.gateway + '\n')
                    writebuf += self.make_cancel_sip_packet(
                            remote_id, self.gateway,
                            branch, tag, call_id, self.seq)
                    state['status'] = 'done_send_cancel'
                elif state['status'] == 'delay':
                    if time.time() - state['delay_start'] > delay:
                        state['status'] = 'send_cancel'

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
                        sent = sock.send(writebuf)
                        if sent == 0:
                            error('Error while writing to socket')
                        writebuf = writebuf[sent:]


if __name__ == '__main__':
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
    parser.add_argument('--display', default='',
        help='Displayed caller id. If empty, the username is used.')
    parser.add_argument('--call', required=True,
        help='Phone number of the endpoint that will be called.')
    parser.add_argument('--delay', default=10.0, type=float,
        help='Pause in seconds until the call is canceled (default 10.0)')

    args = parser.parse_args()

    sip = SIP(args.user, args.password, args.gateway, args.port)
    sip.call(args.call, args.delay)

