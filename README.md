# FemtoSIP ‒ A minimal SIP client

*FemtoSIP* is a minimal, incomplete, and utterly broken Python SIP
implementation with the sole purpose to ring a phone for a certain period of
time. This is quite handy for certain home automation tasks, such as signaling
someone ringing at the door.

## How to use

*FemtoSIP* solely depends on Python 3 which is present on most Linux
installations and available for other platforms as well. To use the program,
clone this Git repository and execute the `femtosip.py` program. Alternatively,
instead of using Git, you can [just download `femtosip.py`](https://raw.githubusercontent.com/astoeckel/femtosip/master/femtosip.py).

```sh
# Clone the program and go into the femtosip directory
git clone https://github.com/astoeckel/femtosip
cd femtosip

# Execute femtosip.py
python3 femtosip.py \
    --gateway 192.168.1.1 \       # IP address or hostname of the SIP server
    --user SIP_USER \             # SIP username
    --password SIP_PASSWORD \     # SIP password
    --call '**9' \                # Which phone number to call
    --delay 15.0                  # How long to wait til hanging up
```

If everything works, you should get an output which looks like this:
```
2018-01-01 11:41:42,749 request: INVITE sip:**9@192.168.1.1
2018-01-01 11:41:42,760 response: SIP/2.0 401 Unauthorized
2018-01-01 11:41:42,760 request: INVITE sip:**9@192.168.1.1
2018-01-01 11:41:42,772 response: SIP/2.0 100 Trying
2018-01-01 11:41:42,816 response: SIP/2.0 183 Session Progress
2018-01-01 11:41:57,816 request: CANCEL sip:**9@192.168.1.1
2018-01-01 11:41:57,828 response: SIP/2.0 487 Request Cancelled
2018-01-01 11:41:57,829 response: IP/2.0 200 OK
```

## Compatibility

This code was hacked together in a few hours and tested with the following SIP
servers

* AVM FRITZ!Box Fon WLAN 7390
* linphone 3.6.1 (libexosip2/3.6)

It is not guaranteed to work with any other server. Especially, it uses a TCP
connection for SIP, which is not supported by all endpoints.


## License

```
FemtoSIP -- A minimal SIP client
Copyright (C) 2017-2018  Andreas Stöckel

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
