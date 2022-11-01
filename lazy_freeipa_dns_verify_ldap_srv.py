#!/usr/bin/env python3

import argparse
import json
import sys
import datetime
from lib import CODES
from lib import ipaapi
from lib import ipadns

parser = argparse.ArgumentParser()

parser.add_argument("--domain", help="host to connect to", required=True)
parser.add_argument("--username", help="host to connect to", required=True)
parser.add_argument("--password", help="host to connect to", required=True)
parser.add_argument("--api-version", help="host to connect to", default="2.245")
parser.add_argument(
        "--disable-ssl-check",
        help="Disables SSL verification",
        action='store_false'
)

args = parser.parse_args()

try:
    DNS = ipadns(
            domain=args.domain
    )
except Exception as e:
    print(e)

all_dcs = DNS.get_all_dcs()
first_host = all_dcs[0]

try:
    API = ipaapi(
            first_host,
            args.username,
            args.password,
            args.disable_ssl_check
    )
except Exception as e:
    print(e)

freeipa_server_baseurl = 'https://{}/'.format(first_host)
data_return = API.login()
if not data_return:
    print('CRIT: Login failed, check service or username and password')
    sys.exit(CODES.STATUS_CRIT)

config_return = API.config_show()
ipa_masters = config_return['result']['result']['ipa_master_server']
check = all(item in all_dcs for item in ipa_masters)

if check is True:
    print('OK: DNS records appear to be correct')
    sys.exit(CODES.STATUS_OK)
else:
    print('CRIT: DNS appears to be missing LDAP SRV records for replicas.')
    sys.exit(CODES.STATUS_CRIT)
