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
    def __init__(self, server, domain, login_user, login_password, sslverify=True):
        """
        Start up the module
        """
        # Users
        self.users = None
        self.susers = None
        self.pusers = None
        # Hosts and services
        self.hosts = None
        self.services = None
        # Groups
        self.ugroups = None
        self.hgroups = None
        self.ngroups = None
        # Policies
        self.hbac = None
        self.sudo = None
        # Net
        self.zones = None
        self.certs = None
        # LDAP specific
        self.conflicts = None
        self.ghosts = None
        self.bind = None
        self.replicas = None
        self.healthy_agreements = None
        # AD
        self.msdcs = None

        # Login
        self.login_user = login_user
        self.domain = domain
        self.basedn = 'dc=' + self.domain.replace('.', ',dc=')
        self.binddn = 'uid=' + self.login_user + ',cn=users,cn=accounts,' + self.basedn
        self.bindpw = login_password
        self.url = 'ldaps://' + server
        self.short_hostname = server.replace('.{}'.format(domain), '')
        self.conn = self._get_conn()

        if not self.conn:
            return

        self.fqdn = self._get_fqdn()
        self.short_hostname = self.fqdn.replace('.{}'.format(domain), '')
        context = self._get_context()
        if self.basedn != context:
            return

    @staticmethod
    def _get_ldap_msg(err):
        """
        LDAP Message Service
        """
        msg = err
        if hasattr(err, 'message'):
            msg = err.message
            if 'desc' in err.message:
                msg = err.message['desc']
            elif hasattr(err, 'args'):
                msg = err.args[0]['desc']
        return msg

    def _get_conn(self):
        """
        LDAP Connection ervice
        """
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        try:
            lconn = ldap.initialize(self.url)
            lconn.set_option(ldap.OPT_NETWORK_TIMEOUT, 3)
            lconn.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
            lconn.simple_bind_s(self.binddn, self.bindpw)
        except(
            ldap.SERVER_DOWN,
            ldap.NO_SUCH_OBJECT,
            ldap.INVALID_CREDENTIALS,
        ):
            return False

        return lconn

    def _search(self, base, lfilter, attrs=None, scope=ldap.SCOPE_SUBTREE):
        """
        LDAP Search Function - Everything uses this
        """
        try:
            return self.conn.search_s(base, scope, lfilter, attrs)
        except (ldap.NO_SUCH_OBJECT, ldap.SERVER_DOWN) as err:
            print(err)
            return False
        except ldap.REFERRAL:
            exit(1)

    def _get_context(self):
        """
        LDAP Context Service
        """
        results = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-defaultnamingcontext'],
            scope=ldap.SCOPE_BASE
        )

        if not results and type(results) is not list:
            res = None
        else:
            dn, attrs = results[0]
            res = attrs['nsslapd-defaultnamingcontext'][0].decode('utf-8')

        return res

    def _get_fqdn(self):
        """
        Get the FQDN of the host we're looking for
        """
        results = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-localhost'],
            scope=ldap.SCOPE_BASE
        )

        if not results and type(results) is not list:
            res = None
        else:
            dn, attrs = results[0]
            res = attrs['nsslapd-localhost'][0].decode('utf-8')

        return res

    # All user types
    def _get_users(self):
        results = self._search(
                'cn=users,cn=accounts,{}'.format(self.basedn),
                '(objectClass=person)'
        )
        return results

    def _get_stage_users(self):
        results = self._search(
                'cn=staged users,cn=accounts,cn=provisioning,{}'.format(self.basedn),
                '(objectClass=person)'
        )
        return results

    def _get_preserved_users(self):
        results = self._search(
                'cn=deleted users,cn=accounts,cn=provisioning,{}'.format(self.basedn),
                '(objectClass=person)'
        )
        return results

    # Groups
    def _get_user_groups(self):
        results = self._search(
                'cn=groups,cn=accounts,{}'.format(self.basedn),
                '(objectClass=ipausergroup)'
        )
        return results

    def _get_host_groups(self):
        results = self._search(
                'cn=hostgroups,cn=accounts,{}'.format(self.basedn),
                '(objectClass=ipahostgroup)'
        )
        return results

    def _count_netgroups(self):
        results = self._search(
                'cn=ng,cn=alt,{}'.format(self.basedn),
                '(ipaUniqueID=*)',
                None,
                scope=ldap.SCOPE_ONELEVEL
        )
        return results

    # Hosts and services
    def _get_hosts(self):
        results = self._search(
                'cn=computers,cn=accounts,{}'.format(self.basedn),
                '(fqdn=*)'
        )
        return results

    def _get_services(self):
        results = self._search(
                'cn=services,cn=accounts,{}'.format(self.basedn),
                '(krbprincipalname=*)'
        )
        return results

    def _get_hbac_rules(self):
        results = self._search(
                'cn=hbac,{}'.format(self.basedn),
                '(ipaUniqueID=*)',
                scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_sudo_rules(self):
        results = self._search(
                'cn=sudorules,cn=sudo,{}'.format(self.basedn),
                '(ipaUniqueID=*)',
                scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_dns_zones(self):
        results = self._search(
                'cn=dns,{}'.format(self.basedn),
                '(|(objectClass=idnszone)(objectClass=idnsforwardzone))',
                scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_certificates(self):
        results = self._search(
                'ou=certificateRepository,ou=ca,o=ipaca',
                '(certStatus=*)',
                ['subjectName'],
                scope=ldap.SCOPE_ONELEVEL
        )
        return results

    # LDAP Related stuff
    def _get_ldap_conflicts(self):
        results = self._search(
                self.basedn,
                '(|(nsds5ReplConflict=*)(&(objectclass=ldapsubentry)(nsds5ReplConflict=*)))',
                ['nsds5ReplConflict']
        )

        return results

    def _get_ghost_replicas(self):
        results = self._search(
                self.basedn,
                '(&(objectclass=nstombstone)(nsUniqueId=ffffffff-ffffffff-ffffffff-ffffffff))',
                ['nscpentrywsi']
        )
        r = 0
        if type(results) == list and len(results) > 0:
            dn, attrs = results[0]
            for attr in attrs['nscpentrywsi']:
                if 'replica ' in str(attr) and 'ldap' not in str(attr):
                    r += 1
        return r

    def _get_anon_bind(self):
        results = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-allow-anonymous-access'],
            scope=ldap.SCOPE_BASE
        )
        dn, attrs = results[0]
        state = attrs['nsslapd-allow-anonymous-access'][0].decode('utf-8')

        if state in ['on', 'off', 'rootdse']:
            r = str(state).upper()
        else:
            r = 'ERROR'

        return r

    def _get_ms_adtrust(self):
        record = '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.{}'.format(self.domain)
        r = False
        try:
            answers = dns.resolver.resolve(record, 'SRV')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return r

        for answer in answers:
            if self.fqdn in answer.to_text():
                r = True
                return r

        return r

    def _replication_agreements(self):
        msg = []
        healthy = True
        suffix = self.basedn.replace('=', '\\3D').replace(',', '\\2C')
        results = self._search(
                'cn=replica,cn={},cn=mapping tree,cn=config'.format(suffix),
                '(objectClass=*)',
                ['nsDS5ReplicaHost', 'nsds5replicaLastUpdateStatus'],
                scope=ldap.SCOPE_ONELEVEL
        )

        for result in results:
            dn, attrs = result
            host = attrs['nsDS5ReplicaHost'][0].decode('utf-8')
            host = host.replace('.{}'.format(self.domain), '')
            status = attrs['nsds5replicaLastUpdateStatus'][0].decode('utf-8')
            status = status.replace('Error ', '').partition(' ')[0].strip('()')
            if status not in ['0', '18']:
                healthy = False
            msg.append('{} {}'.format(host, status))

        r1 = '\n'.join(msg)
        r2 = healthy
        return r1, r2

    # All Properties (aka the variables we need to set)

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
