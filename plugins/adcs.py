import ad.computer
from net.name import get_addr_by_host
from ad.convert import gt_to_str
from net.adschema import ADSchemaObjectCategory

PLUGIN_NAME = 'adcs'
PLUGIN_INFO = 'retrieve information about Active Directory Certificate Servers (AD CS).'
g_parser = None

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help=PLUGIN_INFO)
        g_parser.set_defaults(handler=handler)
    return g_parser

def handler(args, conn):
    response = list(conn.searchg('cn=Configuration,'+conn.default_search_base,
                                 f'(objectCategory={ADSchemaObjectCategory.PKI_ENROLLMENT_SERVICE})',
                                 attributes=['*']))
    
    for result in response:
        hostname = result['attributes']['dNSHostName'][0]
        ip = get_addr_by_host(hostname, args.name_server, args.server)
        attrs = ad.computer.get(conn, hostname, attributes=['operatingSystem', 'operatingSystemVersion', 'objectSid'])['attributes']
        print_adc(result, ip=ip, os=attrs['operatingSystem'][0], osversion=attrs['operatingSystemVersion'][0])

def print_adc(entry, ip, os, osversion):
    attributes = entry.get('attributes')
    output = \
f"""DNS Hostname             {','.join(attributes.get('dNSHostName'))}
IP Address               {ip}
Operating System         {os}
OS Version               {osversion}
Distinguished Name       {entry.get('dn', attributes.get('distinguishedName', []))}
Canonical Name           {','.join(attributes.get('cn', []))}
Display Name             {','.join(attributes.get('displayName', []))}
Certificate Templates    {','.join(attributes.get('certificateTemplates', []))}
CA Certificate DN        {','.join(attributes.get('cACertificateDN', []))}
Created At               {gt_to_str(attributes.get('whenCreated')[0])}
Last Changed             {gt_to_str(attributes.get('whenChanged')[0])}
"""
    print(output)
