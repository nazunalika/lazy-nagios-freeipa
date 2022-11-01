#!/usr/bin/env python3
"""
init lib
"""

import json
import logging
import string
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
        self.realm = domain.upper()
        self.host = host
        self.python_module_version = dns.__version__

    def get_all_ldap_srv(self):
        """
        Gets all the DC's from DNS
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_ldap._tcp.' + self.domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_ldap._tcp.' + self.domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_krb_text_record(self):
        """
        Verifies if TXT record exists for realm

        This record must be a single TXT record and must be "REALM" (yes, that
        realm must be in double quotes)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kerberos.' + self.domain, 'TXT')
        else:
            answers = dns.resolver.resolve('_kerberos.' + self.domain, 'TXT')

        TXTRECS = []
        for data in answers:
            TXTRECS.append(str(data))

        if len(TXTRECS) >= 1:
            return False

        if TXTRECS[0] == '"' + self.realm + '"':
            return True
        else:
            return False

    def get_all_udp_krb_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kerberos._udp.' + self.domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kerberos._udp.' + self.domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_tcp_krb_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kerberos._tcp.' + self.domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kerberos._tcp.' + self.domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_udp_krb_master_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kerberos-master._udp.' + self.domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kerberos-master._udp.' + self.domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_tcp_krb_master_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kerberos-master._tcp.' + self.domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kerberos-master._tcp.' + self.domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_udp_krb_kpasswd_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kpasswd._udp.' + self.domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kpasswd._udp.' + self.domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_tcp_krb_kpasswd_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kpasswd._tcp.' + self.domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kpasswd._tcp.' + self.domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_dcs(self):
        """
        Gets all the DC's from DNS

        All DC's should have a LDAP SRV record.
        """
        all_dcs = self.get_all_ldap_srv()

        return all_dcs

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

    def config_show(self, params={}):
        """
        Gets the general configuration of the IPA domain
        """
        m = {'method': 'config_show/1', 'params': params}
        results = self.make_request_no_item(m)
        return results
