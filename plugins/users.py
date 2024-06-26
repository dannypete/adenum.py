import logging

import ad.group
import ad.user
from ad.convert import sid_to_str, dn_to_cn
from .user import print_user
from net.adschema import ADSchemaObjectCategory

logger = logging.getLogger(__name__)

PLUGIN_NAME = 'users'
PLUGIN_INFO = 'list privileged users'
g_parser = None

def handler(args, conn):
    if args.privileged:
        # see https://adsecurity.org/?p=3658 and https://adsecurity.org/?p=3700
        priv_groups = [
            'domain admins', 'enterprise admins', 'administrators',
            'account operators',
            'schema admins',
            'backup operators', # bypass file permissions
            'dnsadmins',        # load dll on dc
            'rodc Admins',
            'server operators',
            'print operators'   # driver loading
        ]
        groups = set()
        for g in ad.group.get_all(conn):
            if g['dn'].split(',', maxsplit=1)[0][3:].lower() in priv_groups:
                groups.add(g['dn'])
        for g in sorted(groups):
            logger.debug('Getting users in "{}"'.format(g))
            members = ad.group.get_users(conn, g)
            if len(members) == 0:
                continue
            print('=', g if args.dn else dn_to_cn(g), '=')
            for u in members:
                if args.dn:
                    print(u['dn'])
                else:
                    try:
                        print(u['attributes']['userPrincipalName'][0].split('@')[0])
                    except:
                        print(u['attributes'].get('samAccountName', [dn_to_cn(u['dn'])])[0])
            print()

        print('= AdminSDHolder =')
        # these accounts have protected ACLs that are periodically overwritten by the AdminSDHolder ACLs
        # ref: https://adsecurity.org/?p=1906
        for u in conn.searchg(conn.default_search_base, f'(&(objectCategory={ADSchemaObjectCategory.USER})(adminCount=1))', attributes=['userPrincipalName', 'samAccountName']):
            if args.dn:
                print(u['dn'])
            else:
                try:
                    print(u['attributes']['userPrincipalName'][0].split('@')[0])
                except:
                    print(u['attributes'].get('samAccountName', [dn_to_cn(u['dn'])])[0])
    else:
        users = ad.user.get_all(conn, active_only=args.active)
        for u in users:
            if args.basic:
                if 'dn' in u:
                    if args.dn:
                        print(u['dn'])
                    else:
                        sid = ''
                        try:
                            sid = sid_to_str(u['attributes']['objectSid'][0])
                        except:
                            pass
                        try:
                            print('{} {}'.format(u['attributes']['userPrincipalName'][0].split('@')[0], sid))
                            #print(u['attributes']['userPrincipalName'][0])
                        except:
                            name = u['attributes'].get('samAccountName', None)
                            if not name:
                                name = u['dn']
                            print('{} {}'.format(name, sid))
            else:
                print_user(u, conn, args)

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list all users')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('-p', '--privileged', action='store_true', help=PLUGIN_INFO)
        g_parser.add_argument('--basic', action='store_true', help='get basic user info')
        g_parser.add_argument('-a', '--active', action='store_true', help='get active users only')
    return g_parser
