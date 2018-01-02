#!/usr/bin/env python3

#   FemtoSIP -- A minimal SIP client
#   Copyright (C) 2017-2018  Andreas Stöckel
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

# Command line arguments
import argparse
parser = argparse.ArgumentParser(
    description='A program for the Raspberry PI calling the given SIP phone ' +
                'number whenever a alling edge on the given GPIO pin is ' + 
                'detected.')
parser.add_argument('--gateway', required=True,
    help='Hostname or IP address of the SIP server')
parser.add_argument('--port', default=5060, type=int,
    help='Port of the SIP server (default 5060)')
parser.add_argument('--user', required=True,
    help='Username used for authentication at the SIP server')
parser.add_argument('--password', default='',
    help='Password used in conjunction with the user for authentication ' +
         'at the SIP server. (default '')')
parser.add_argument('--call', required=True,
    help='Phone number of the endpoint that will be called.')
parser.add_argument('--delay', default=15.0, type=float,
    help='Pause in seconds until the call is canceled (default 15.0)')
parser.add_argument('--gpio', default=27, type=int,
    help='GPIO pin which is configured as input (default 27)')

args = parser.parse_args()

# Setup logging for this program
import logging
logger = logging.getLogger('rpi_sip_doorbell')
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

# Setup the specified GPIO pin as input
import RPi.GPIO as GPIO
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
GPIO.setup(args.gpio, GPIO.IN)

# Setup an asynchronous callback
got_event = { 'value': False }
def gpio_event_callback(_):
    # Do some software low-pass filtering
    int value = 0.0
    for i in range(0, 32):
        if GPIO.value(args.gpio):
            value += 1.0
        value *= 0.9
        time.sleep(5e-3)
    if value > 24.0:
        logger.info('Door gong triggered.')
        got_event['value'] = True

GPIO.add_event_detect(args.gpio, GPIO.FALLING,
                      callback=gpio_event_callback,
                      bouncetime = 200)

# Setup the SIP client
import femtosip
sip = femtosip.SIP(args.user, args.password, args.gateway, args.port)

# Loop eternally and trigger a call whenever an event is detected
import time
try:
    logger.info('rpi_sip_doorbell.py ready')
    while True:
        time.sleep(0.1)
        if got_event['value']:
            logger.info('Detected door ring event, initiating SIP call.')
            sip.call(args.call, args.delay)
            logger.info('SIP call ended.')
            got_event['value'] = False
except KeyboardInterrupt:
    logger.info('Program interrupted, exiting')

