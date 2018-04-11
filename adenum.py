#!/usr/bin/env python3
import sys
import socket
import logging
import hashlib
import argparse

# non-std
import ldap3
import socks
import dns.query

# local modules
import plugins
from lib.utils import *
from lib.names import *
from lib.adldap import *
from lib.config import *
from lib.convert import *
from lib.connection import *

DESCRIPTION = 'Enumerate ActiveDirectory users, groups, computers, and password policies'

logger = logging.getLogger(__name__)

'''
= SUMMARY =

This script is basically a python implementation of the windows "net" command.
It provides enumeration of users, groups, and password policies by performing
LDAP queries against an Active Directory domain controller.

= INSTALLATION =

You'll need to install ldap3 and dnspython:
    pip3 install ldap3 dnspython

You will also need either smbclient or pysmb to read the default password policy
from the SYSVOL share.

= EXAMPLES =

NOTE: If your system is not configured to use the name server for
the domain, you must specify the domain controller with -s or the
domain's name server with --name-server. In nearly all AD domains,
the domain controller acts as the name server. Domains specified
with -d must be fully qualified.

List password policies. Non-default policies may require higher privileges.
    python3 adenum.py -u USER -P -d mydomain.local policy

List all users and groups
    python3 adenum.py -u USER -P -d mydomain.local users
    python3 adenum.py -u USER -P -d mydomain.local groups

List domain admins
    python3 adenum.py -u USER -P -d mydomain.local group "domain admins"

List domain joined computers. Add -r and -u to resolve hostnames and get uptime (SMB2 only).
    python3 adenum.py -u USER -P -d mydomain.local computers

= TODO =
1. Find a better workaround for AD 1000 results limit on DCs that don't support paging
2. Prioritize name resolution methods that work

= RESOURCES =

All defined AD attributes
https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx
'''

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter)
    user_parser = parser.add_mutually_exclusive_group()
    user_parser.add_argument('-u', '--username', default='', help='may specify DOMAIN\\USER. default is null user')
    user_parser.add_argument('--anonymous', action='store_true', help='anonymous access')
    parser.add_argument('-p', '--password', default=hashlib.new('md4', b'').hexdigest(), help='password')
    parser.add_argument('--nthash', action='store_true', help='password is an NTLM hash')
    parser.add_argument('-P', dest='prompt', action='store_true', help='prompt for password')
    parser.add_argument('--proxy', help='socks5 proxy: eg 127.0.0.1:8888')
    parser.add_argument('-s', '--server', help='domain controller address or name')
    parser.add_argument('-d', '--domain', help='user domain. may be different than domain of --server (trusts)')
    parser.add_argument('--timeout', type=int, default=TIMEOUT, help='timeout for network operations')
    parser.add_argument('--threads', type=int, default=20, help='name resolution/smbinfo worker count. default 20')
    parser.add_argument('--port', type=int, help='default 389 or 636 with --tls. 3268 for global catalog')
    parser.add_argument('--smb-port', dest='smb_port', default=445, type=int, help='default 445')
    parser.add_argument('--smbclient', action='store_true', help='force use of smbclient over pysmb')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('-v', '--version', type=int, choices=[1,2,3], default=3, help='specify ldap version')
    parser.add_argument('--debug', action='store_true', help='implies --verbose')
    parser.add_argument('--name-server', dest='name_server', help='specify name server for domain')
    parser.add_argument('--dn', action='store_true', help='list distinguished names of AD objects')
    parser.add_argument('--insecure', action='store_true', help='ignore invalid tls certs')
    #parser.add_argument('--cert', help='')
    #parser.add_argument('--auth', default='ntlm', type=str.lower, choices=['ntlm', 'kerb'], help='auth type')
    parser.set_defaults(search_base=None)
    parser.set_defaults(server_domain=None) # domain of server being queried
    parser.set_defaults(server_fqdn=None)
    parser.set_defaults(handler=None)

    tls_group = parser.add_mutually_exclusive_group()
    tls_group.add_argument('--tls', action='store_true', help='initiate connection with TLS')
    tls_group.add_argument('--start-tls', dest='starttls', action='store_true',  help='use START_TLS')

    subparsers = parser.add_subparsers(help='choose an action')
    plugin_list = plugins.load_plugins(subparsers)
    args = parser.parse_args()

    socket.setdefaulttimeout(args.timeout)

    if args.debug:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter('[%(levelname)s] %(filename)s:%(lineno)s %(message)s'))
        for n in [__name__, 'plugins', 'lib']:
            l = logging.getLogger(n)
            l.setLevel(logging.DEBUG)
            l.addHandler(h)
    elif args.verbose:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        for n in [__name__, 'plugins', 'lib']:
            l = logging.getLogger(n)
            l.setLevel(logging.INFO)
            l.addHandler(h)

    for p in plugin_list:
        logger.debug('Loaded Plugin: '+p.PLUGIN_NAME)

    if args.proxy:
        proxy_host, proxy_port = args.proxy.split(':')
        logger.debug('Setting SOCKS5 proxy: {}:{}'.format(proxy_host, int(proxy_port)))
        socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port), True)
        socket.socket = socks.socksocket
        dns.query.socket_factory = socks.socksocket

    if args.server and not is_addr(args.server):
        # resolve DC hostname
        args.server = get_addr_by_host(args.server, args.name_server, args.timeout) or get_host_by_name(args.server)
        if not args.server:
            print('Error: Failed to resolve DC hostname')
            sys.exit()

    if args.username.find('\\') != -1:
        if args.domain:
            args.username = args.username.split('\\')[-1]
        else:
            args.domain, args.username = args.username.split('\\')

    if not args.domain or args.domain.count('.') == 0:
        logger.debug('Checking for domain name')
        args.domain = None
        fqdn = None
        if not args.server:
            if args.name_server:
                fqdn = get_fqdn_by_addr(args.name_server, args.name_server, args.timeout)
            else:
                if os.path.exists('/etc/resolv.conf'):
                    for line in [l.strip() for l in open('/etc/resolv.conf')]:
                        if line.startswith('domain '):
                            args.domain = line.split(' ')[1]
                            logger.debug('Found domain in resolv.conf: '+args.domain)
                            break
        else:
            fqdn = get_fqdn_by_addr(args.server, args.name_server, args.timeout)
            if not fqdn and args.server != args.name_server:
                # try query against the domain controller
                fqdn = get_fqdn_by_addr(args.server, args.server, args.timeout)
                if not fqdn:
                    logger.debug('Querying LDAP for domain')
                    info = get_dc_info(args)
                    args.domain = info['rootDomainNamingContext'][3:].lower().replace(',dc=', '.')
        if fqdn:
            args.domain = fqdn.split('.', maxsplit=1)[-1]
        if not args.domain:
            print('Error: Failed to get domain. Try supplying one with --domain.')
            sys.exit()
        logger.info('Found domain: '+args.domain)

    # determine port if not specified
    if not args.port:
        if args.tls:
            args.port = 636
        else:
            args.port = 389

    if not args.server:
        # attempt to find a DC
        logger.info('Looking for domain controller for '+args.domain)
        try:
            args.server = get_domain_controllers_by_dns(args.domain, args.name_server, args.timeout)[0]['address']
        except:
            print('Error: Failed to find a domain controller')
            sys.exit()
        logger.info('Found a domain controller for {} at {}'.format(args.domain, args.server))

    # get search base. should be root of DC being queried
    args.server_fqdn = addr_to_fqdn(args.server, [args.name_server, args.server], port=args.smb_port, timeout=args.timeout)
    if args.server_fqdn:
        args.hostname = args.server_fqdn.split('.', maxsplit=1)[0]
        args.server_domain = args.server_fqdn.split('.', maxsplit=1)[-1]
        args.search_base = 'dc='+args.server_domain.replace('.', ',dc=')
    else:
        print('Error: unable to determine domain for '+args.server)
        sys.exit()

    logger.debug('DC         {} ({})'.format(args.hostname, args.server))
    logger.debug('Port       '+str(args.port))
    logger.debug('Username   {}\\{}'.format(args.domain, args.username))
    logger.debug('SearchBase '+args.search_base)
    logger.debug('NameServer '+ (args.name_server or 'default'))
    if not is_private_addr(args.server) and not args.insecure:
        raise Warning('Aborting due to public LDAP server. use --insecure to override')

    conn = get_connection(args)

    if not conn.bound:
        print('Error: failed to bind')
        sys.exit()
    logger.debug('WHOAMI '+(conn.extend.standard.who_am_i() or ''))

    if args.handler:
        args.handler(args, conn)
    conn.unbind()
