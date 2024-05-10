import logging

import ad.dc
import ad.connection
from ad.convert import sid_to_str
from net.name import get_addr_by_host

logger = logging.getLogger(__name__)

PLUGIN_NAME= 'dcinfo'
PLUGIN_INFO = 'retrieve DC info'
g_parser = None

FUNC_LEVELS = {
        0:'2000',
        1:'2003_Mixed_Domains',
        2:'2003',
        3:'2008',
        4:'2008r2',
        5:'2012',
        6:'2012r2',
        7:'2016',
    }

def get_parser():
    return g_parser

def handler(args, conn):
    servers = ad.dc.get_domain_controllers_by_ldap(ad.connection.get(args), args.search_base, args.name_server, args.server, args.timeout)
    for s in servers:
        for hn in s['hostname']:

            logger.debug('Connecting to DC {}'.format(s))
            try:
                raddr = get_addr_by_host(hn, name_server=args.name_server, ad_server=args.server)
                r = ad.dc.get_info(args, ad.connection.get(args, raddr))
            except:
                logger.error('DC connection failed: {}'.format(hn))
                continue
            print('address                         ', raddr)
            print('dnsHostName                     ', hn)
            print('supportedLDAPVersions           ', ', '.join(map(str, r['supportedLDAPVersion'])))
            print('searchBase                      ', r['search_base'])
            print('domainControllerFunctionality   ', FUNC_LEVELS[r['domainControllerFunctionality']])
            print('domainFunctionality             ', FUNC_LEVELS[r['domainFunctionality']])
            print('forestFunctionality             ', FUNC_LEVELS[r['forestFunctionality']])
            print('SID                             ', sid_to_str(s['sid']))
            print()


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help=PLUGIN_INFO)
        g_parser.set_defaults(handler=handler)
    return g_parser

