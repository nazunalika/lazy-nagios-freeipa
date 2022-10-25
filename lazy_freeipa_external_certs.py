#!/usr/bin/env python3

import argparse
import socket
import ssl
import sys
import datetime
from cryptography import x509
from lib import CODES

parser = argparse.ArgumentParser()

parser.add_argument("--host", help="host to connect to", required=True)
parser.add_argument("--within-days", help="days before expiration for warning", default=14, type=int)

args = parser.parse_args()

hostname = args.host
expiration_time = args.within_days
critical_time = 7
start = datetime.datetime.now()
#end = start + datetime.timedelta(+time_span)

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

try:
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tsock:
            data = tsock.getpeercert(True)
            pem_data = ssl.DER_cert_to_PEM_cert(data)
            cert_data = x509.load_pem_x509_certificate(str.encode(pem_data))
            not_valid_after = cert_data.not_valid_after
            not_valid_before = cert_data.not_valid_before
            days_till_expire_http = not_valid_after - start
except Exception as e:
    print(e)
    sys.exit(CODES.STATUS_UNKNOWN)

try:
    with socket.create_connection((hostname, 636)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tsock:
            data = tsock.getpeercert(True)
            pem_data = ssl.DER_cert_to_PEM_cert(data)
            cert_data = x509.load_pem_x509_certificate(str.encode(pem_data))
            not_valid_after = cert_data.not_valid_after
            not_valid_before = cert_data.not_valid_before
            days_till_expire_ldap = not_valid_after - start

except Exception as e:
    print(e)
    sys.exit(CODES.STATUS_UNKNOWN)

if (days_till_expire_http <= expiration_time) or (days_till_expire_ldap <= expiration_time):
    print('WARN: Certificates are expiring in less than {} days'.format(expiration_time))
    sys.exit(CODES.STATUS_WARN)

if (days_till_expire_http <= critical_time) or (days_till_expire_ldap <= critical_time):
    print('CRIT: Certificates are expiring in less than {} days'.format(critical_time))
    sys.exit(CODES.STATUS_CRIT)

print('OK: Certificates are good.')
sys.exit(CODES.STATUS_OK)
