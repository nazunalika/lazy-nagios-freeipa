#!/usr/bin/env python3

import argparse
import json
import sys
import datetime
from lib import CODES
from lib import monitorldap

parser = argparse.ArgumentParser()

parser.add_argument("--domain", help="IPA Domain", required=True)
parser.add_argument("--binddn", help="Full bind dn of the user (eg cn=Directory Manager)", required=True)
parser.add_argument("--password", help="Bind password", required=True)
parser.add_argument("--server", help="Replica to contact", required=True)
parser.add_argument(
        "--disable-ssl-check",
        help="Disables SSL verification",
        action='store_false'
)

args = parser.parse_args()
server = args.server

# Verify that the user can login or that the domain controller is up
login_check = monitorldap(server, args.domain, args.binddn, args.password)
if login_check._conn is None:
    print('Unable to contact {}'.format(server))
    sys.exit(CODES.STATUS_UNKNOWN)

if login_check._conn is False:
    print('Bind DN or Bind Password invalid')
    sys.exit(CODES.STATUS_CRIT)
