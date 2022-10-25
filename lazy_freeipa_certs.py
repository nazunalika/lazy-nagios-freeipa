#!/usr/bin/env python3

import argparse
import json
import sys
import datetime
from lib import CODES
from lib import ipaapi

parser = argparse.ArgumentParser()

parser.add_argument("--host", help="host to connect to", required=True)
parser.add_argument("--username", help="host to connect to", required=True)
parser.add_argument("--password", help="host to connect to", required=True)
parser.add_argument("--api-version", help="host to connect to", default="2.245")
parser.add_argument("--span", help="span of time", default=30, type=int)
parser.add_argument("--verbose", help="Verbose mode", action='store_true')
parser.add_argument(
        "--disable-ssl-check",
        help="Disables SSL verification",
        action='store_false'
)

args = parser.parse_args()

freeipa_server_baseurl = 'https://{}/'.format(args.host)
verbose = args.verbose
time_span = args.span
start = datetime.datetime.now()
end = start + datetime.timedelta(+time_span)

params = {
        'validnotafter_from': start.strftime('%Y-%m-%d'),
        'validnotafter_to': end.strftime('%Y-%m-%d'),
        'all': True,
}

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

cert_return = API.cert_find(params)
if cert_return['result']['count'] != 0:
    print('CRIT: %s IPA certificates will expire in the next %i days' % (
        cert_return['result']['count'], time_span)
    )
    if verbose:
        for result in cert_return['result']['result']:
            print('Cert: %s - Validate until: %s' %(result['subject'],
                                                    result['valid_not_after']))
    sys.exit(CODES.STATUS_CRIT)

print('OK: IPA Certs Valid')
sys.exit(0)
