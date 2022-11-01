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
    sys.exit(CODES.STATUS_CRIT)

all_dcs = DNS.get_all_dcs()
first_host = all_dcs[0]

all_dcs_ldap = DNS.get_all_ldap_srv()
all_dcs_krb_tcp = DNS.get_all_tcp_krb_srv()
all_dcs_krb_udp = DNS.get_all_udp_krb_srv()
all_dcs_krb_master_tcp = DNS.get_all_tcp_krb_master_srv
all_dcs_krb_master_udp = DNS.get_all_udp_krb_master_srv
all_dcs_kpasswd_tcp = DNS.get_all_tcp_krb_kpasswd_srv()
all_dcs_kpasswd_udp = DNS.get_all_udp_krb_kpasswd_srv()
kerberos_realm_status = DNS.get_krb_text_record

try:
    API = ipaapi(
            first_host,
            args.username,
            args.password,
            args.disable_ssl_check
    )
except Exception as e:
    print(e)
    sys.exit(CODES.STATUS_CRIT)

freeipa_server_baseurl = 'https://{}/'.format(first_host)
data_return = API.login()
if not data_return:
    print('CRIT: Login failed, check service or username and password')
    sys.exit(CODES.STATUS_CRIT)

config_return = API.config_show()
ipa_masters = config_return['result']['result']['ipa_master_server']

# At a minimum, these records are required
check_ldap_srv = all(item in all_dcs for item in ipa_masters)
check_krb_tcp_srv = all(item in all_dcs for item in ipa_masters)
check_krb_udp_srv = all(item in all_dcs for item in ipa_masters)
check_krb_master_tcp_srv = all(item in all_dcs for item in ipa_masters)
check_krb_master_udp_srv = all(item in all_dcs for item in ipa_masters)
check_kpasswd_tcp_srv = all(item in all_dcs for item in ipa_masters)
check_kpasswd_udp_srv = all(item in all_dcs for item in ipa_masters)
check_krb_realm_txt = kerberos_realm_status

if not check_ldap_srv:
    print('CRIT: DNS appears to be missing LDAP SRV records for replicas.')
    sys.exit(CODES.STATUS_CRIT)

falses = []
if not check_ldap_srv:
    falses.append('ldap_srv')
if not check_krb_tcp_srv:
    falses.append('krb_srv_tcp')
if not check_krb_udp_srv:
    falses.append('krb_srv_udp')
if not check_krb_master_tcp_srv:
    falses.append('krb_master_srv_tcp')
if not check_krb_master_udp_srv:
    falses.append('krb_master_srv_udp')
if not check_kpasswd_tcp_srv:
    falses.append('kpasswd_srv_tcp')
if not check_kpasswd_udp_srv:
    falses.append('kpasswd_srv_udp')
if not check_krb_realm_txt:
    falses.append('krb_realm_txt')

if len(falses) == 0:
    print('OK: DNS appears to be good')
    sys.exit(CODES.STATUS_OK)
else:
    FALSE_STRING = ', '.join(falses)
    print('CRIT: The following records are broken: {}'.format(FALSE_STRING))
    sys.exit(CODES.STATUS_CRIT)
