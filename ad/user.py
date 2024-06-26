import logging

import ad.group
from .convert import gid_from_sid, escape
from net.adschema import ADSchemaObjectCategory

logger = logging.getLogger(__name__)

USER_ATTRIBUTES=[
    #'msexchhomeservername',
    #'usncreated',
    'whenCreated',
    'whenChanged',
    'memberOf',
    'groupMembershipSAM',
    'accountExpires',
    'msDS-UserPasswordExpiryTimeComputed',
    'displayName',
    'primaryGroupID',
    #'homeDirectory',
    'lastLogonTimestamp',
    'lastLogon',
    'lastLogoff',
    'logonWorkstation',
    'otherLoginWorkstations',
    'scriptPath',
    'userWorkstations',
    'displayName',
    'mail',
    'title',
    'sAMAccountName',
    'lockouttime',
    'lockoutduration',
    'description',
    'pwdlastset',
    'logoncount',
    'logonHours',
    'name',
    #'usnchanged',
    #'allowedAttributes',
    'admincount',
    'badpasswordtime',
    'badPwdCount',
    'info',
    'distinguishedname',
    'userPrincipalName',
    'givenname',
    'middleName',
    'lastlogontimestamp',
    'useraccountcontrol',
    'objectGUID',
    'objectSid',
    'nTSecurityDescriptor',
]

def get_all(conn, active_only=False):
    ''' get all domain users '''
    attrs = list(USER_ATTRIBUTES)
    filt = f'(objectCategory={ADSchemaObjectCategory.USER})'
    if active_only:
        filt = f'(&(objectCategory={ADSchemaObjectCategory.USER})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    return conn.searchg(conn.default_search_base, filt, attributes=attrs)

def get_dn(conn, user):
    response = conn.searchg(
        conn.default_search_base,
        f'(&(objectCategory={ADSchemaObjectCategory.USER})(|(userPrincipalName={escape(user)}@*)(cn={escape(user)})(samAccountName={escape(user)})))')
    return list(response)[0]['dn']

def get_info(conn, user):
    user_dn = get_dn(conn, user)
    return conn.searchg(
        conn.default_search_base,
        f'(&(objectCategory={ADSchemaObjectCategory.USER})(distinguishedName={escape(user_dn)}))',
        attributes=list(USER_ATTRIBUTES)
    )

def get_groups(conn, user):
    ''' get all groups for user, domain and local. see groupType attribute to check domain vs local.
    user should be a dn. '''
    response = list(conn.searchg(
        conn.default_search_base,
        f'(&(objectCategory={ADSchemaObjectCategory.USER})(distinguishedName={escape(user)}))',
        attributes=['memberOf', 'primaryGroupID']))
    group_dns = response[0]['attributes']['memberOf']

    # get primary group which is not included in the memberOf attribute
    pgid = response[0]['attributes']['primaryGroupID']
    if pgid:
        pgid = int(pgid[0])
    else:
        pgid = None
    groups = list(ad.group.get_all(conn))
    for g in groups:
        # Builtin group SIDs are returned as str's, not bytes
        if type(g['attributes']['objectSid'][0]) == str:
            g['attributes']['objectSid'][0] = g['attributes']['objectSid'][0].encode()
    logger.debug(groups)
    gids = [gid_from_sid(g['attributes']['objectSid'][0]) for g in groups]
    logger.debug(gids)
    if pgid is not None:
        group_dns.append(groups[gids.index(pgid)]['dn'])
    group_dns = list(map(str.lower, group_dns))
    return [g for g in groups if g['dn'].lower() in group_dns]
