#!/usr/bin/env python3

import argparse
import json
import sys
import datetime
from lib import CODES
from lib import ipaldap
from lib import ipadns

parser = argparse.ArgumentParser()

parser.add_argument("--domain", help="IPA Domain", required=True)
parser.add_argument("--binddn", help="Full bind dn of the user (eg cn=Directory Manager)", required=True)
parser.add_argument("--password", help="Bind password", required=True)
parser.add_argument("--initial-master", help="Initial replica to contact", required=False)
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

# This is the lazy way to do it. DNS should be correct. This was better than
# forcing a separate user and bind dn option, because perhaps someone may use
# a "sysaccount" for some operations (or directory manager, which goes against
# all recommendations).
all_dcs = DNS.get_all_dcs()

if args.initial_master:
    server_to_check = args.initial_master
else:
    server_to_check = all_dcs[0]

if server_to_check not in all_dcs:
    print('Initial master does not exist in DNS so it is not considered a master')
    sys.exit(CODES.STATUS_DEPENDENT)

# Verify that the user can login or that the domain controller is up
login_check = ipaldap(server_to_check, args.domain, args.binddn, args.password)
if login_check._conn is None:
    print('Unable to contact {}'.format(server_to_check))
    sys.exit(CODES.STATUS_UNKNOWN)

if login_check._conn is False:
    print('Bind DN or Bind Password invalid')
    sys.exit(CODES.STATUS_CRIT)

# Gather all LDAP data
server_dict = {}
results = {}
for host in all_dcs:
    server_dict[host] = ipaldap(host, args.domain, args.binddn, args.password)

# Number of users/groups/etc not in sync are a WARN if under 5, CRIT if over.
#users = [getattr(server, 'users') for server in server_dict.values()]
#groups = [getattr(server, 'ugroups') for server in server_dict.values()]
# Conflicts are a CRIT
# Ghosts are a CRIT

def is_consistent():
    """
    Checks consistency and reports back
    """
    result_dict = {}
    conflicts = [getattr(server, 'conflicts') for server in server_dict.values()]
    ghosts = [getattr(server, 'ghosts') for server in server_dict.values()]
    healths = [getattr(server, 'healthy_agreements') for server in server_dict.values()]
    if conflicts.count(conflicts[0]) == len(conflicts) and len(conflicts[0]) == 0:
        result_dict['conflicts'] = True
    else:
        result_dict['conflicts'] = False

    if ghosts.count(ghosts[0]) == len(ghosts) and ghosts[0] == 0:
        result_dict['ghosts'] = True
    else:
        result_dict['ghosts'] = False

    if healths.count(healths[0]) == len(healths) and healths[0]:
        result_dict['healths'] = True
    else:
        result_dict['healths'] = False

    return result_dict

consistency_dict = is_consistent()

unhealthy = []
if not consistency_dict['conflicts']:
    unhealthy.append('conflicts')
if not consistency_dict['ghosts']:
    unhealthy.append('ghosts')
if not consistency_dict['healths']:
    unhealthy.append('healths')

if len(unhealthy) == 0:
    print('IPA Domain is OK!')
    sys.exit(CODES.STATUS_OK)
else:
    print('IPA Domain has issues with the following: ' + ', '.join(unhealthy))
    sys.exit(CODES.STATUS_CRIT)
