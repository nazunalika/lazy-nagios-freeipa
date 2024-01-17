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
parser.add_argument("--warning", help="Warning Limit", type=int)
parser.add_argument("--critical", help="Critical Limit", type=int)
parser.add_argument("--mode", help="Greater or lesser than", choices=['greater', 'lesser'])
# pylint: disable=line-too-long
parser.add_argument("--type", help="Monitoring Attribute Type", required=True,
                    choices=[
                        'version',                # version of 389ds
                        'threads',                # number of active threads
                        'currentconnections',     # current connections
                        'totalconnections',       # total connections handled since dirsrv started
                        'dtablesize',             # Number of file descriptors available
                        'readwaiters',            # Number of threads waiting to read data from a client
                        'opsinitiated',           # Number of ops the server has initiated since dirsrv started
                        'opscompleted',           # Number of ops the server has completed since dirsrv started
                        'entriessent',            # Number of entries sent to clients since dirsrv started
                        'bytessent',              # Number of bytes sent to clients since dirsrv started
                        'currenttime',            # Current time of this run
                        'starttime',              # Time when dirsrv started
                        'backends',               # Number of backends (databases)
                        'readonly',               # The userRoot is readonly (0 is no, 1 is yes)
                        'entrycachehits',         # Total number of successful entry cache lookups
                        'entrycachetries',        # Total number of entry cache lookups since dirsrv started
                        'entrycachehitratio',     # Ratio that indicates the number of entry cache tries to successful entry cache lookups
                        'currententrycachecount', # Number of entries currently present in the entry cache
                        'currententrycachesize',  # The maximum size (bytes) of directory entries currently present in the entry cache
                        'maxentrycachesize',      # The maximum size (bytes) of directory entries that can be maintained in the entry cache
                        'dncachehitratio',        # Ratio that indicates the number of DN cache tries to successful DN cache lookups
                        'dncachehits',            # Total number of successful DN cache lookups
                        'dncachetries',           # Total number of DNs cache lookups since dirsrv started
                        'currentdncachecount',    # Number of entries currently present in the DN cache
                        'currentdncachesize',     # Total size (bytes) of directory entries currently present in the DN cache
                        'maxdncachesize'          # Maximum size (bytes) of directory entries that can be maintained in the DN cache
                        ])
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

requested_data = getattr(login_check, args.type)[0][1][args.type][0].decode()

# Some attributes are informational only. Asking for these should skip
# everything else.
if args.type in ['version', 'currenttime', 'starttime', 'nbackends', 'readonly', 'maxentrycachesize', 'maxdncachesize']:
    print(f"{requested_data}")
    sys.exit(CODES.STATUS_OK)

# warning and critical MUST be specified in cases that don't match above
if not args.warning or not args.critical or not args.mode:
    print("ERROR: You must provide a WARNING, CRITICAL, and MODE values. See --help")
    sys.exit(CODES.STATUS_DEPENDENT)

if args.mode == "lesser" and args.critical >= args.warning:
    print("ERROR: Using lesser mode, warning should be greater than critical")
    sys.exit(CODES.STATUS_UNKNOWN)
if args.mode == "greater" and args.warning >= args.critical:
    print("ERROR: Using greater mode, warning should be lesser than critical")
    sys.exit(CODES.STATUS_UNKNOWN)

# The rest of the attributes are int
int_data = int(requested_data)
if args.mode == "greater":
    if int_data < args.warning:
        print(f"OK: {args.type} at {str(int_data)}")
        sys.exit(CODES.STATUS_OK)
    # disabling this check. the chained causes problems
    # pylint: disable=chained-comparison
    elif int_data >= args.warning and int_data < args.critical:
        print(f"WARN: {args.type} at {str(int_data)}")
        sys.exit(CODES.STATUS_WARN)
    else:
        print(f"CRIT: {args.type} at {str(int_data)}")
        sys.exit(CODES.STATUS_CRIT)
elif args.mode == "lesser":
    if int_data > args.warning:
        print(f"OK: {args.type} at {str(int_data)}")
        sys.exit(CODES.STATUS_OK)
    # disabling this check. the chained causes problems
    # pylint: disable=chained-comparison
    elif int_data <= args.warning and int_data > args.critical:
        print(f"WARN: {args.type} at {str(int_data)}")
        sys.exit(CODES.STATUS_WARN)
    else:
        print(f"CRIT: {args.type} at {str(int_data)}")
        sys.exit(CODES.STATUS_CRIT)

# If we don't get through the rest, exit as unknown just in case.
# In majority of cases, this shouldn't be hit
sys.exit(CODES.STATUS_UNKNOWN)
