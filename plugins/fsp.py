import ldap3
import logging

from net.adschema import ADSchemaObjectClass

logger = logging.getLogger(__name__)

PLUGIN_NAME = 'fsp'
PLUGIN_INFO = 'list foreignSecurityPrincipals'
g_parser = None

def handler(args, conn):
    response = conn.searchg(
        args.search_base,
        f'(objectClass={ADSchemaObjectClass.FOREIGN_SECURITY_PRINCIPAL})',
        search_scope=ldap3.SUBTREE,
        attributes=[])
    for r in response:
        print(r['dn'])

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help=PLUGIN_INFO)
        g_parser.set_defaults(handler=handler)
    return g_parser
