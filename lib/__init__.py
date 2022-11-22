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
        self._domain = domain
        self.realm = domain.upper()
        self.host = host
        self.python_module_version = dns.__version__

    def get_all_ldap_srv(self):
        """
        Gets all the DC's from DNS
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_ldap._tcp.' + self._domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_ldap._tcp.' + self._domain, 'SRV')

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
            answers = dns.resolver.query('_kerberos.' + self._domain, 'TXT')
        else:
            answers = dns.resolver.resolve('_kerberos.' + self._domain, 'TXT')

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
            answers = dns.resolver.query('_kerberos._udp.' + self._domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kerberos._udp.' + self._domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_tcp_krb_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kerberos._tcp.' + self._domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kerberos._tcp.' + self._domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_udp_krb_master_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kerberos-master._udp.' + self._domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kerberos-master._udp.' + self._domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_tcp_krb_master_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kerberos-master._tcp.' + self._domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kerberos-master._tcp.' + self._domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_udp_krb_kpasswd_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kpasswd._udp.' + self._domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kpasswd._udp.' + self._domain, 'SRV')

        list_of_dcs = []
        for data in answers:
            list_of_dcs.append(str(data.target).rstrip('.'))

        return list_of_dcs

    def get_all_tcp_krb_kpasswd_srv(self):
        """
        Gets all the DC's from DNS (kerb)
        """
        if self.python_module_version.split('.')[0] == "1":
            answers = dns.resolver.query('_kpasswd._tcp.' + self._domain, 'SRV')
        else:
            answers = dns.resolver.resolve('_kpasswd._tcp.' + self._domain, 'SRV')

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
    def __init__(self, server, domain, bind_user, login_password, sslverify=True):
        """
        Start up the module
        """
        # Users
        self._users = None
        self._susers = None
        self._pusers = None
        # Hosts and services
        self._hosts = None
        self._services = None
        # Groups
        self._ugroups = None
        self._hgroups = None
        self._ngroups = None
        # Policies
        self._hbac = None
        self._sudo = None
        # Net
        self._zones = None
        self._certs = None
        # LDAP specific
        self._conflicts = None
        self._ghosts = None
        self._anonbind = None
        self._replicas = None
        self._healthy_agreements = None
        # AD
        self._msdcs = None

        # Login
        self._domain = domain
        self._basedn = 'dc=' + self._domain.replace('.', ',dc=')
        #self._binddn = 'uid=' + self.login_user + ',cn=users,cn=accounts,' + self._basedn
        self._binddn = bind_user
        self._bindpw = login_password
        self._url = 'ldaps://' + server
        self._short_hostname = server.replace('.{}'.format(domain), '')
        self._conn = self._get_conn()

        if self._conn is False:
            return None

        self._fqdn = self._get_fqdn()
        if self._fqdn is None:
            # WARNING: If the account cannot read cn=config, we will fall back
            # to the server name provided. This may or may not be a good idea.
            self._fqdn = server

        self._short_hostname = self._fqdn.replace('.{}'.format(domain), '')

        context = self._get_context()
        if self._basedn != context:
            return None

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
        LDAP Connection service
        """
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        try:
            lconn = ldap.initialize(self._url)
            lconn.set_option(ldap.OPT_NETWORK_TIMEOUT, 3)
            lconn.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
            lconn.simple_bind_s(self._binddn, self._bindpw)
        except(ldap.SERVER_DOWN):
            return None
        except(ldap.NO_SUCH_OBJECT):
            return None
        except(ldap.INVALID_CREDENTIALS):
            return False

        return lconn

    def _search(self, base, lfilter, attrs=None, scope=ldap.SCOPE_SUBTREE):
        """
        LDAP Search Function - Everything uses this
        """
        try:
            return self._conn.search_s(base, scope, lfilter, attrs)
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

        if (not results and type(results) is not list) or len(results) == 0:
            # falling back
            #res = self._basedn
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

        if (not results and type(results) is not list) or len(results) == 0:
            # falling back
            res = None
        else:
            dn, attrs = results[0]
            res = attrs['nsslapd-localhost'][0].decode('utf-8')

        return res

    # All user types
    def _get_users(self):
        results = self._search(
                'cn=users,cn=accounts,{}'.format(self._basedn),
                '(objectClass=person)'
        )
        return results

    def _get_stage_users(self):
        results = self._search(
                'cn=staged users,cn=accounts,cn=provisioning,{}'.format(self._basedn),
                '(objectClass=person)'
        )
        return results

    def _get_preserved_users(self):
        results = self._search(
                'cn=deleted users,cn=accounts,cn=provisioning,{}'.format(self._basedn),
                '(objectClass=person)'
        )
        return results

    # Groups
    def _get_user_groups(self):
        results = self._search(
                'cn=groups,cn=accounts,{}'.format(self._basedn),
                '(objectClass=ipausergroup)'
        )
        return results

    def _get_host_groups(self):
        results = self._search(
                'cn=hostgroups,cn=accounts,{}'.format(self._basedn),
                '(objectClass=ipahostgroup)'
        )
        return results

    def _count_netgroups(self):
        results = self._search(
                'cn=ng,cn=alt,{}'.format(self._basedn),
                '(ipaUniqueID=*)',
                None,
                scope=ldap.SCOPE_ONELEVEL
        )
        return results

    # Hosts and services
    def _get_hosts(self):
        results = self._search(
                'cn=computers,cn=accounts,{}'.format(self._basedn),
                '(fqdn=*)'
        )
        return results

    def _get_services(self):
        results = self._search(
                'cn=services,cn=accounts,{}'.format(self._basedn),
                '(krbprincipalname=*)'
        )
        return results

    def _get_hbac_rules(self):
        results = self._search(
                'cn=hbac,{}'.format(self._basedn),
                '(ipaUniqueID=*)',
                scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_sudo_rules(self):
        results = self._search(
                'cn=sudorules,cn=sudo,{}'.format(self._basedn),
                '(ipaUniqueID=*)',
                scope=ldap.SCOPE_ONELEVEL
        )
        return results

    def _get_dns_zones(self):
        results = self._search(
                'cn=dns,{}'.format(self._basedn),
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
                self._basedn,
                '(|(nsds5ReplConflict=*)(&(objectclass=ldapsubentry)(nsds5ReplConflict=*)))',
                ['nsds5ReplConflict']
        )

        return results

    def _get_ghost_replicas(self):
        results = self._search(
                self._basedn,
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
        record = '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.{}'.format(self._domain)
        r = False
        try:
            answers = dns.resolver.resolve(record, 'SRV')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return r

        for answer in answers:
            if self._fqdn in answer.to_text():
                r = True
                return r

        return r

    def _replication_agreements(self):
        msg = []
        healthy = True
        suffix = self._basedn.replace('=', '\\3D').replace(',', '\\2C')
        results = self._search(
                'cn=replica,cn={},cn=mapping tree,cn=config'.format(suffix),
                '(objectClass=*)',
                ['nsDS5ReplicaHost', 'nsds5replicaLastUpdateStatus'],
                scope=ldap.SCOPE_ONELEVEL
        )

        for result in results:
            dn, attrs = result
            host = attrs['nsDS5ReplicaHost'][0].decode('utf-8')
            host = host.replace('.{}'.format(self._domain), '')
            status = attrs['nsds5replicaLastUpdateStatus'][0].decode('utf-8')
            status = status.replace('Error ', '').partition(' ')[0].strip('()')
            if status not in ['0', '18']:
                healthy = False
            msg.append('{} {}'.format(host, status))

        r1 = '\n'.join(msg)
        r2 = healthy
        return r1, r2

    # All Properties (aka the variables we need to set)
    @property
    def users(self):
        if not self._users:
            self._users = self._get_users()
        return self._users

    @property
    def susers(self):
        if not self._susers:
            self._susers = self._get_stage_users()
        return self._susers

    @property
    def pusers(self):
        if not self._pusers:
            self._pusers = self._get_preserved_users()
        return self._pusers

    @property
    def hosts(self):
        if not self._hosts:
            self._hosts = self._get_hosts()
        return self._hosts

    @property
    def services(self):
        if not self._services:
            self._services = self._get_services()
        return self._services

    @property
    def ugroups(self):
        if not self._ugroups:
            self._ugroups = self._get_user_groups()
        return self._ugroups

    @property
    def hgroups(self):
        if not self._hgroups:
            self._hgroups = self._get_host_groups()
        return self._hgroups

    @property
    def ngroups(self):
        if not self._ngroups:
            self._ngroups = self._count_netgroups()
        return self._ngroups

    @property
    def hbac(self):
        if not self._hbac:
            self._hbac = self._get_hbac_rules()
        return self._hbac

    @property
    def sudo(self):
        if not self._sudo:
            self._sudo = self._get_sudo_rules()
        return self._sudo

    @property
    def zones(self):
        if not self._zones:
            self._zones = self._get_dns_zones()
        return self._zones

    @property
    def certs(self):
        if not self._certs:
            self._certs = self._get_certificates()
        return self._certs

    @property
    def conflicts(self):
        if not self._conflicts:
            self._conflicts = self._get_ldap_conflicts()
        return self._conflicts

    @property
    def ghosts(self):
        if not self._ghosts:
            self._ghosts = self._get_ghost_replicas()
        return self._ghosts

    @property
    def bind(self):
        if not self._anonbind:
            self._anonbind = self._get_anon_bind()
        return self._anonbind

    @property
    def msdcs(self):
        if not self._msdcs:
            self._msdcs = self._get_ms_adtrust()
        return self._msdcs

    @property
    def replicas(self):
        if not self._replicas:
            self._replicas, self._healthy_agreements = self._replication_agreements()
        return self._replicas

    @property
    def healthy_agreements(self):
        if not self._healthy_agreements:
            self._replicas, self._healthy_agreements = self._replication_agreements()
        return self._healthy_agreements

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
