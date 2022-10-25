#!/usr/bin/env python3

import argparse
import json
import sys
from lib import CODES
from lib import ipaapi

parser = argparse.ArgumentParser()

parser.add_argument("--host", help="host to connect to", required=True)
parser.add_argument("--username", help="host to connect to", required=True)
parser.add_argument("--password", help="host to connect to", required=True)
parser.add_argument("--api-version", help="host to connect to", default="2.245")
parser.add_argument(
        "--disable-ssl-check",
        help="Disables SSL verification",
        action='store_false'
)

args = parser.parse_args()

freeipa_server_baseurl = 'https://{}/'.format(args.host)

try:
    API = ipaapi(
            args.host,
            args.username,
            args.password,
            args.disable_ssl_check
    )
except Exception as e:
    print(e)

data_return = API.login()
if not data_return:
    print('CRIT: Login failed, check service or username and password')
    sys.exit(CODES.STATUS_CRIT)

print('OK: Service is working as expected.')
sys.exit(CODES.STATUS_OK)
