import socket
import logging
import ipaddress
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from config import TIMEOUT

logger = logging.getLogger(__name__)

def get_resolvers(name_server=None, ad_server=None, timeout=TIMEOUT):
    resolvers = []
    # use nameserver if provided
    if name_server:
        ns_resolver = dns.resolver.Resolver()
        ns_resolver.nameservers = [name_server]
        resolvers.append(ns_resolver)
    
    # use configured system resolution
    resolvers.append(dns.resolver)

    # use AD server if provided as last resort
    if ad_server:
        ad_resolver = dns.resolver.Resolver()
        ad_resolver.nameservers = [ad_server]
        resolvers.append(ad_resolver)

    for r in resolvers:
        r.timeout = timeout
        r.lifetime = timeout
    return resolvers

def get_host_by_name(host):
    logger.debug('Resolving {} via default'.format(host))
    try:
        return socket.gethostbyname(host)
    except:
        pass
    return None

def get_addrs_by_host(host, name_server=None, ad_server=None, timeout=TIMEOUT):
    ''' return list of addresses for the host '''
    resolvers = get_resolvers(name_server, ad_server, timeout)

    for resolver in resolvers:
        try:
            answer = resolver.resolve(host, tcp=True)
            logger.debug('Resolved {} to {} via {}'.format(host, ', '.join([a.address for a in answer]),
                                                        getattr(resolver, "nameservers", [None])[0] or 'default DNS'))
            return [a.address for a in answer]
        except Exception:
            logger.debug('Name resolution failed for {} via {}'.format(host, getattr(resolver, "nameservers", [None])[0]
                                                                        or 'default'))

    return []
    

def get_addr_by_host(host, name_server=None, ad_server=None, timeout=TIMEOUT):
    addrs = get_addrs_by_host(host, name_server, ad_server, timeout)
    return addrs[0] if len(addrs) else host

def get_fqdn_by_addr(addr, name_server=None, ad_server=None, timeout=TIMEOUT):
    resolvers = get_resolvers(name_server, ad_server, timeout)
    arpa = dns.reversename.from_address(addr)

    for resolver in resolvers:
        try:
            answer = resolver.resolve(arpa, rdtype=dns.rdatatype.PTR, rdclass=dns.rdataclass.IN, tcp=True)
            logger.debug('Resolved {} to {} via {}'.format(arpa, str(answer[0])[:-1], 
                                                           getattr(resolver, "nameservers", [None])[0] or 'default'))
            return str(answer[0])[:-1]
        except Exception:
            logger.debug('Name resolution failed for {} via {}'.format(arpa, getattr(resolver, "nameservers", [None])[0] or 'default'))
    return None
    

def get_host_by_addr(addr, name_server=None, ad_server=None, timeout=TIMEOUT):
    fqdn = get_fqdn_by_addr(addr, name_server, ad_server, timeout)
    if fqdn:
        return fqdn.split('.', maxsplit=1)[0]
    return None
