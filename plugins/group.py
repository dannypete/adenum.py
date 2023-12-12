import logging

import ad.group
from ad.convert import dn_to_cn

logger = logging.getLogger(__name__)

PLUGIN_NAME='group'
g_parser = None

def get_parser():
    return g_parser


def handler(args, conn):
    groups = args.group
    for group in set(groups):
        title_str = f"Group Name: {group}"
        print(f"{title_str}")
        members = ad.group.get_users(conn, group)
        for u in members:
            if args.dn:
                print(u.get('dn', u))
            else:
                try:
                    print(u['attributes']['userPrincipalName'][0].split('@')[0])
                except:
                    print(dn_to_cn(u['dn']))
        print()


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='get group info')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('group', help='group to search', nargs='*')
        g_parser.add_argument('-m', '--members', help='retrieve group members')
    return g_parser
