from ad.convert import gt_to_str

PLUGIN_NAME = 'adcs'
PLUGIN_INFO = '''
retrieve information about Active Directory Certificate Servers (AD CS).
'''
g_parser = None

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help=PLUGIN_INFO.strip())
        g_parser.set_defaults(handler=handler)
    return g_parser

def handler(args, conn):
    response = list(conn.searchg('cn=Configuration,'+conn.default_search_base,
                                 '(objectCategory=pKIEnrollmentService)',
                                 attributes=['*']))
    
    for result in response:
        print_adc(result)

def print_adc(entry):
    attributes = entry.get('attributes')
    output = \
f"""DNS Hostname             {','.join(attributes.get('dNSHostName'))}
Distinguished Name       {entry.get('dn', attributes.get('distinguishedName', []))}
Canonical Name           {','.join(attributes.get('cn', []))}
Display Name             {','.join(attributes.get('displayName', []))}
Certificate Templates    {','.join(attributes.get('certificateTemplates', []))}
CA Certificate DN        {','.join(attributes.get('cACertificateDN', []))}
Created At               {gt_to_str(attributes.get('whenCreated')[0])}
Last Changed             {gt_to_str(attributes.get('whenChanged')[0])}
Object GUID              {attributes.get('objectGUID', None)}

"""
    print(output)
