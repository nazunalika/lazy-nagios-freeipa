#!/usr/bin/env python3
"""
init lib
"""

import json
import logging
import requests
import ldap
import dns.resolver

class CODES:
    """
    Nagios exit codes
    """
    STATUS_OK = 0
    STATUS_WARN = 1
    STATUS_CRIT = 2
    STATUS_UNKNOWN = 3
    STATUS_DEPENDENT = 4

class ipadns(object):
    """
    DNS Class Wrapper for Nagios
    """
    def __init__(self, domain=None, host=None):
        """
        Start up the module
        """
        self.domain = domain
        self.host = host

    def get_all_dcs(self):
        """
        Gets all the DC's from DNS
        """
        print()

class ipaldap(object):
    """
    LDAP Class Wrapper for Nagios
    """

class ipaapi(object):
    """
    IPA Class Wrapper for Nagios
    """
    def __init__(self, server, login_user, login_password, sslverify=True):
        """
        Start up the module
        """
        self.server = server
        self.sslverify = sslverify
        self.log = logging.getLogger(__name__)
        self.session = requests.Session()
        self.login_user = login_user
        self.login_password = login_password

    def login(self):
        """
        Performs a login
        """
        rv = None
        ipaurl = 'https://{0}/ipa/session/login_password'.format(self.server)
        header = {
                'referer': ipaurl,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'text/plain'
        }
        login = {'user': self.login_user, 'password': self.login_password}
        rv = self.session.post(ipaurl,
                               headers=header,
                               data=login,
                               verify=self.sslverify
        )

        if rv.status_code != 200:
            self.log.warning('Failed to login with {0} to {1}'.format(
                self.login_user,
                self.server)
            )
            rv = None
        else:
            self.log.info('Logged in as {0}'.format(self.login_user))

        return rv

    def make_request(self, pdict):
        """
        Starts the request to the IPA API
        """
        results = None
        ipaurl = 'https://{0}/ipa'.format(self.server)
        session_url = '{0}/session/json'.format(ipaurl)
        header = {
                'referer': ipaurl,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
        }

        data = {
                'id': 0,
                'method': pdict['method'],
                'params': [pdict['item'], pdict['params']]
        }

        self.log.debug('Making request {0} to {1}'.format(
            pdict['method'],
            session_url)
        )

        request = self.session.post(session_url, headers=header,
                                    data=json.dumps(data),
                                    verify=self.sslverify
        )

        results = request.json()

        return results

    def make_request_no_item(self, pdict):
        """
        Starts the request to the IPA API
        """
        results = None
        ipaurl = 'https://{0}/ipa'.format(self.server)
        session_url = '{0}/session/json'.format(ipaurl)
        header = {
                'referer': ipaurl,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
        }

        data = {
                'id': 0,
                'method': pdict['method'],
                'params': [[], pdict['params']]
        }

        self.log.debug('Making request {0} to {1}'.format(
            pdict['method'],
            session_url)
        )

        request = self.session.post(session_url, headers=header,
                                    data=json.dumps(data),
                                    verify=self.sslverify
        )

        results = request.json()

        return results


    def cert_find(self, params={}, sizelimit=40000):
        """
        Finds certificates in a simple manner. This does not work for external
        CA's
        """
        m = {'method': 'cert_find/1', 'params': params}
        results = self.make_request_no_item(m)
        return results
