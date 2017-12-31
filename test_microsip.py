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

import microsip

REAL_WORLD_RESPONSE = (
    b"\x53\x49\x50\x2f\x32\x2e\x30\x20\x34\x30\x31\x20\x55\x6e\x61\x75" +
    b"\x74\x68\x6f\x72\x69\x7a\x65\x64\x0d\x0a\x56\x69\x61\x3a\x20\x53" +
    b"\x49\x50\x2f\x32\x2e\x30\x2f\x54\x43\x50\x20\x31\x39\x32\x2e\x31" +
    b"\x36\x38\x2e\x31\x37\x38\x2e\x36\x39\x3a\x35\x30\x36\x30\x3b\x72" +
    b"\x70\x6f\x72\x74\x3d\x33\x37\x36\x38\x36\x3b\x62\x72\x61\x6e\x63" +
    b"\x68\x3d\x7a\x39\x68\x47\x34\x62\x4b\x31\x38\x34\x37\x37\x34\x35" +
    b"\x32\x35\x31\x0d\x0a\x46\x72\x6f\x6d\x3a\x20\x3c\x73\x69\x70\x3a" +
    b"\x54\x75\x65\x72\x6b\x6c\x69\x6e\x67\x65\x6c\x40\x66\x72\x69\x74" +
    b"\x7a\x2e\x62\x6f\x78\x3e\x3b\x74\x61\x67\x3d\x34\x33\x35\x34\x36" +
    b"\x32\x37\x38\x39\x0d\x0a\x54\x6f\x3a\x20\x3c\x73\x69\x70\x3a\x2a" +
    b"\x2a\x36\x31\x31\x40\x66\x72\x69\x74\x7a\x2e\x62\x6f\x78\x3e\x3b" +
    b"\x74\x61\x67\x3d\x39\x31\x46\x43\x37\x31\x37\x46\x46\x44\x45\x42" +
    b"\x45\x43\x31\x31\x0d\x0a\x43\x61\x6c\x6c\x2d\x49\x44\x3a\x20\x31" +
    b"\x39\x33\x39\x33\x31\x31\x31\x37\x33\x0d\x0a\x43\x53\x65\x71\x3a" +
    b"\x20\x32\x30\x20\x49\x4e\x56\x49\x54\x45\x0d\x0a\x57\x57\x57\x2d" +
    b"\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65\x3a\x20\x44\x69" +
    b"\x67\x65\x73\x74\x20\x72\x65\x61\x6c\x6d\x3d\x22\x66\x72\x69\x74" +
    b"\x7a\x2e\x62\x6f\x78\x22\x2c\x20\x6e\x6f\x6e\x63\x65\x3d\x22\x46" +
    b"\x32\x43\x30\x31\x45\x32\x39\x38\x42\x32\x34\x46\x35\x36\x39\x22" +
    b"\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x46\x52" +
    b"\x49\x54\x5a\x21\x4f\x53\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d" +
    b"\x4c\x65\x6e\x67\x74\x68\x3a\x20\x30\x0d\x0a\x0d\x0a")

def assert_response(parser, protocol, code, message, body, fields):
    assert(parser.protocol == protocol)
    assert(parser.code == code)
    assert(parser.message == message)
    assert(parser.body == body)
    assert(len(parser.fields) == len(fields))
    for key, value in fields.items():
        assert(key in parser.fields)
        assert(parser.fields[key] == fields[key])


def test_real_world_response():
    n_callback_called = [0]
    def callback(parser):
        n_callback_called[0] += 1
        assert_response(parser, 'SIP/2.0', 401, 'Unauthorized', b'', {
            'Via': b'SIP/2.0/TCP 192.168.178.69:5060;rport=37686;branch=z9hG4bK1847745251',
            'From': b'<sip:Tuerklingel@fritz.box>;tag=435462789',
            'To': b'<sip:**611@fritz.box>;tag=91FC717FFDEBEC11',
            'Call-ID': b'1939311173',
            'CSeq': b'20 INVITE',
            'WWW-Authenticate': b'Digest realm="fritz.box", nonce="F2C01E298B24F569"',
            'User-Agent': b'FRITZ!OS',
            'Content-Length': b'0',
        })

    parser = microsip.ResponseParser()
    parser.feed(REAL_WORLD_RESPONSE, callback)

    assert(n_callback_called[0] == 1)


def test_response_with_body():
    n_callback_called = [0]
    def callback(parser):
        n_callback_called[0] += 1
        assert_response(parser, 'SIP/2.0', 200, 'OK', b'0123456789', {
            'Foo': b'Bar',
            'Content-Length': b'10',
        })

    parser = microsip.ResponseParser()
    parser.feed(b'SIP/2.0 200 OK\r\nFoo: Bar\r\nContent-Length: 10\r\n\r\n0123456789', callback)
    assert(n_callback_called[0] == 1)

    parser.feed(b'SIP/2.0 200 OK\r\nFoo: Bar\r\nContent-Length: 10\r\n\r\n0123456789', callback)
    assert(n_callback_called[0] == 2)

    parser.feed(b'SIP/2.0 200 OK\r\nFoo: Bar\r\nContent-Length: 10\r\n\r\n0123456789SIP/2.0 200 OK\r\nFoo: Bar\r\nContent-Length: 10\r\n\r\n0123456789', callback)
    assert(n_callback_called[0] == 4)

    parser.feed(b'SIP/2.0 200 OK\r\nFoo: Bar\r', callback)
    assert(n_callback_called[0] == 4)
    parser.feed(b'\nContent-Length: 10\r\n\r\n0123456789', callback)
    assert(n_callback_called[0] == 5)


def test_message_with_spaces():
    n_callback_called = [0]
    def callback(parser):
        n_callback_called[0] += 1
        assert_response(parser, 'SIP/2.0', 200, 'Foo Bar', b'', {})

    parser = microsip.ResponseParser()
    parser.feed(b'SIP/2.0 200 Foo Bar\r\n\r\n', callback)
    assert(n_callback_called[0] == 1)


test_real_world_response()
test_response_with_body()
test_message_with_spaces()

