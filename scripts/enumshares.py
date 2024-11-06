#!/usr/bin/env python3

# builtin modules
import sys
import logging
import binascii
import argparse
import concurrent.futures
import ipaddress

# pysmb
import smb.base
import smb.ntlm
import smb.smb_structs
import smb.SMBConnection

logger = logging.getLogger(__name__)

class MyMD4Class():
    ''' class to add pass-the-hash support to pysmb '''
    @staticmethod
    def new():
        return MyMD4Class()
    def update(self, p):
        self.nthash = binascii.unhexlify(p.decode('utf-16-le'))
        logger.debug("NTHASH: {}".format(self.nthash))
    def digest(self):
        return self.nthash


def parse_host_with_share(host):
    host_addr = None
    sharename = None
    sharepath = None
    host = host.strip()
    if host.startswith("\\\\"):
        host = host[2:]

    splitted = host.split("\\", 2)
    if len(splitted) >= 1:
        host_addr = splitted[0]
    if len(splitted) >= 2 and splitted[1] != '':
        sharename = splitted[1]
    if len(splitted) == 3:
        sharepath = splitted[2]
        if not sharepath.startswith("\\"):
            sharepath = "\\" + sharepath
        if sharepath.endswith("\\"):
            sharepath = sharepath[:-1]

    return host_addr, sharename, sharepath


def crawl_share(conn, share, sharepath, timeout, max_depth=None):
    dirs = [sharepath]
    start_depth = len(sharepath.split('\\'))
    while len(dirs) > 0:
        path = dirs.pop(0)
        logger.debug("Enumerating path \\\\{}\\{}{}".format(conn.remote_name, share, path))
        if max_depth is not None:
            if len(path.split("\\")) - start_depth >= max_depth:
                logger.debug("Depth of {} reached for path '{}'".format(max_depth, path))
                continue
            else:
                logger.debug("Depth of {} not reached yet for path '{}'".format(max_depth, path))

        try:
            for f in conn.listPath(share, path, timeout=timeout):
                if f.isDirectory:
                    if f.filename not in args.exclude:
                        newdir = path + '\\' + f.filename
                        logger.debug("Adding '{}' to paths to enumerate".format(newdir))
                        dirs.append(newdir)
                else:
                    sys.stdout.write('\\\\{}\\{}{}\\{}\n'.format(conn.remote_name, share, path, f.filename))
        except smb.smb_structs.OperationFailure as e:
            logger.debug('Error listing {}\\{}: {} {} (adenum writer\' note: probably a normal permissions error)'.format(share, path, type(e).__name__, e.message))
        except Exception as e:
            logger.error('Error listing {}\\{}. This is an unexpected error; you might want to rerun the script'.format(share, path, str(e).split('\n')[0]))
            raise


def enum_thread(args, host, sharename=None, sharepath=None, max_depth=None):
    logger.debug('Connecting to {} as {}\\{}'.format(host, args.domain or '', args.username))

    if sharename is not None:
        shares = [sharename]
    else:
        conn = smb.SMBConnection.SMBConnection(args.username, args.password, 'adenum', host, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
        conn.connect(host, port=args.smb_port)
        shares = [s.name for s in conn.listShares() if s.type == smb.base.SharedDevice.DISK_TREE]   
        conn.close()

    logger.debug("Shares to enumerate for {}:  {}".format(host, shares))

    for s in shares:
        if s in args.exclude:
            logger.debug('Skipping excluded dir: '+s)
            continue
        logger.debug('Crawling share ' + s)
        conn = smb.SMBConnection.SMBConnection(args.username, args.password, 'adenum', host, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
        conn.connect(host, port=args.smb_port, timeout=args.timeout)
        crawl_share(conn, s, sharepath if sharepath is not None else '', max_depth, timeout=args.timeout)
        conn.close()


def enum_shares(args):
    if args.nthash:
        logger.debug('passing the NTLM hash')
        smb.ntlm.MD4 = MyMD4Class.new

    hosts = list(args.hosts)

    if args.filename:
        logger.debug("Opening {} for hosts to use in enumeration".format(args.filename))
        for line in open(args.filename):
            line = line.strip()
            if line != '': 
                hosts.append(line)

    if args.host_cidr:
        # check for CIDR, then expand
        logger.debug("Expanding any hosts provided as CIDR")
        newhosts = []
        for host in hosts:
            try:
                # try to parse the host as a CIDR network
                host_expanded = [str(ip) for ip in ipaddress.ip_network(host,strict=False)]
                newhosts.extend(host_expanded)
                logger.debug("Expanded CIDR host to {} hosts".format(len(host_expanded)))
            except ValueError:
                # thrown if the host couldn't be parsed as an ipnetwork. assuming its a hostname
                newhosts.append(host)
                logger.debug("{} did not parse to an IP address or CIDR network, so using it as is".format(host))

        hosts = newhosts

    # remove any duplicates
    hosts = set(hosts)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as e:
        futures = []
        for host in hosts:
            hostaddr, sharename, sharepath = parse_host_with_share(host)
            logger.debug("Host '{}' parsed into: address:{}, share:{}, sharepath:{}".format(host, hostaddr, sharename, sharepath))
            if hostaddr is None:
                logger.debug("Skipping empty host: {}".format(host))
                continue
            futures.append(e.submit(enum_thread, args, hostaddr, sharename, sharepath, args.max_depth))
        
        concurrent.futures.wait(futures)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', required=True, help='username')
    parser.add_argument('-p', '--password', required=True, help='password')
    parser.add_argument('-d', '--domain', default='.', help='AD domain')
    parser.add_argument('-w', '--workers', default=1, type=int, help='worker threads')
    parser.add_argument('--nthash', action='store_true', help='password is the nthash')
    parser.add_argument('-f', '--filename', help='file of hosts')
    parser.add_argument('hosts', nargs='*', help='hosts to enumerate. a share, and optionally path in that share, may be provided e.g. 10.20.30.40\\share$\\path')
    parser.add_argument('--smb-port', dest='smb_port', type=int, default=445, help='SMB port. default 445')
    #parser.add_argument('--proxy', help='socks5 proxy: eg 127.0.0.1:8888')
    parser.add_argument('--debug', action='store_true', help='enable debug output')
    parser.add_argument('-x', '--exclude', action='append', help='full share path to exclude from crawling', default=[])
    parser.add_argument('--max-depth', type=int, help='max depth of shares to crawl', default=None)
    parser.add_argument('--host-cidr', action='store_true', help='hosts are passed using CIDR (cannot be used in conjunction with a provided host share path)', default=False)
    parser.add_argument('-t', '--timeout', help='connection timeout', type=int, default=30)
    args = parser.parse_args()

    args.exclude.append('.')
    args.exclude.append('..')
    args.exclude = set(args.exclude)

    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('[%(levelname)s] %(filename)s:%(lineno)s %(message)s'))
    for n in [__name__]:
        l = logging.getLogger(n)
        l.setLevel(logging.DEBUG if args.debug else logging.NOTSET)
        l.addHandler(h)
    logger.debug(args)
    logger.info("Domain: {}".format(args.domain))
    logger.info("User: {}".format(args.username))
    logger.info("Host(s): {}".format(args.hosts))
    logger.info("Hosts file: {}".format(args.filename))
    logger.info("Port: {}".format(args.smb_port))
    logger.info("Worker count: {}".format(args.workers))
    logger.info("Exclusions: {}".format(args.exclude))
    logger.info("Max Depth: {}".format(args.max_depth or 'N/A'))
    logger.info("Hosts with CIDR: {}".format(args.host_cidr))

    enum_shares(args)
