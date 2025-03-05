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
    logger.debug("Starting `crawl_share()` with initial values: \
                 dirs={}, share={}, sharepath={}, maxdepth={}, startdepth={}"
                 .format(dirs, share, sharepath, max_depth, start_depth))
    while len(dirs) > 0:
        path = dirs.pop(0)
        logger.debug("Enumerating path \\\\{}\\{}{}".format(conn.remote_name, share, path))
        if max_depth is not None:
            if len(path.split("\\")) - start_depth >= max_depth:
                logger.info("Reached specified max_depth ({}) on host ({})'s path '{}'".format(max_depth, conn.remote_name, path))
                continue
            else:
                logger.debug("Depth of {} not reached yet for path '{}'".format(max_depth, path))

        try:
            for f in conn.listPath(share, path, timeout=timeout):
                if f.filename in args.exclude:
                    continue

                if f.isDirectory:
                    newdir = path + '\\' + f.filename
                    logger.debug("Adding '{}' to paths to enumerate".format(newdir))
                    dirs.append(newdir)
                    sys.stdout.write('\\\\{}\\{}{}\\{}\\\n'.format(conn.remote_name, share, path, f.filename))
                else:
                    sys.stdout.write('\\\\{}\\{}{}\\{}\n'.format(conn.remote_name, share, path, f.filename))
        except smb.smb_structs.OperationFailure as e:
            logger.info('Error listing "\\\\{}\\{}{}\\" (this is probably a normal file/permissions error): \
                        errorName="{}" errorMessage="{}"'.format(conn.remote_name, share, path, type(e).__name__, e.message))
        except (smb.base.SMBTimeout, TimeoutError):
            logger.error("Connection to {} timed out while crawling {}. Aborting".format(conn.remote_name, path))
            raise
        except Exception as e:
            logger.error('Unexpected error listing {}\\{}. \
                         You might want to rerun the script with --debug and report to maintainer'
                         .format(share, path, str(e).split('\n')[0]))
            logger.debug(type(e))
            raise


def enum_thread(args, host, sharename=None, sharepath=None, max_depth=None):
    
    if sharename is not None:
        logger.debug("Enumerating specified share {} on {}".format(sharename, host))
        shares = [sharename]
    else:
        conn = smb.SMBConnection.SMBConnection(args.username, args.password, 'adenum', host, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
        try:
            logger.debug('Connecting to {} as {}\\{}'.format(host, args.domain or '', args.username))
            conn_result = conn.connect(host, port=args.smb_port, timeout=args.timeout)
            if conn_result == False:
                logger.error("Failed to authenticate to host {}. Skipping it...".format(host))
                conn.close()
                return -1
            logger.debug("Enumerating any available shares on {}".format(host))
            shares = [s.name for s in conn.listShares(timeout=args.timeout) if s.type == smb.base.SharedDevice.DISK_TREE]   
            logger.debug("Found the following shares for enumerating on {}: {}".format(host, shares))
            conn.close()
        except (smb.base.SMBTimeout, TimeoutError):
            logger.error("Connection to {} timed out while looking for shares to enumerate. Aborting".format(host))
            conn.close()
            return -1
        except Exception as e:
            logger.error("Encountered unknown error connecting to {}: {}".format(host, e))
            logger.debug(type(e))
            conn.close()
            return -1

    for s in shares:
        if s in args.exclude:
            logger.debug('Skipping excluded dir: '+s)
            continue
        logger.debug('Crawling share ' + s)
        conn = smb.SMBConnection.SMBConnection(args.username, args.password, 'adenum', host, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
        try:
            conn_result = conn.connect(host, port=args.smb_port, timeout=args.timeout)
        except (smb.base.SMBTimeout, TimeoutError):
            logger.error("Connection to {} timed out while crawling its shares. Aborting".format(host))
            conn.close()
            return -1
        except Exception as e:
            logger.error("Encountered unknown error connecting to {}: {}".format(host, e))
            logger.debug(type(e))
            conn.close()
            return -1

        if conn_result == True:
            logger.debug("Successfully connected to share '{}' of {}".format(s, host))
            crawl_share(conn=conn, share=s, sharepath=sharepath if sharepath is not None else '', max_depth=max_depth, timeout=args.timeout)
        else:
            logger.debug("Failed to authenticate to host {}. \
                         Did the user get locked out or password reset? \
                         (This is an unusual place for this fail to occur in the code)"
                         .format(s, host))
            conn.close()
            return -1
        
        conn.close()
        return 0


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
    parser.add_argument('-w', '--workers', default=5, type=int, help='worker threads')
    parser.add_argument('--nthash', action='store_true', help='password is the nthash')
    parser.add_argument('-f', '--filename', help='file of hosts')
    parser.add_argument('hosts', nargs='*', help='hosts to enumerate. \
                        a share, and optionally path in that share, may be provided e.g. 10.20.30.40\\share$\\path')
    parser.add_argument('--smb-port', dest='smb_port', type=int, default=445, help='SMB port. default 445')
    #parser.add_argument('--proxy', help='socks5 proxy: eg 127.0.0.1:8888')
    parser.add_argument('--verbose', '-v', action='store_true', help='more output')
    parser.add_argument('--debug', action='store_true', help='enable debug output (implies verbose)')
    parser.add_argument('-x', '--exclude', action='append', help='path string/substring to exclude from crawling \
                        (use multiple times e.g., "-x EXCLUDE_1 ... -x EXCLUDE_n" for multiple exclusions)', default=[])
    parser.add_argument('--max-depth', type=int, help='max depth to crawl within share (default: no max)', default=None)
    parser.add_argument('--host-cidr', action='store_true', help='hosts are passed using CIDR \
                        (cannot be used in conjunction with a provided host share path)', default=False)
    parser.add_argument('-t', '--timeout', help='connection timeout', type=int, default=10)
    args = parser.parse_args()

    # prevent cyclical paths
    args.exclude.append('.')
    args.exclude.append('..')
    args.exclude = set(args.exclude)

    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('[%(levelname)s] %(filename)s:%(lineno)s %(message)s'))
    for n in [__name__]:
        l = logging.getLogger(n)
        if args.verbose:
            l.setLevel(logging.INFO)
        elif args.debug:
            l.setLevel(logging.DEBUG)
        else:
            l.setLevel(logging.NOTSET)
        l.addHandler(h)
    logger.debug(args)

    enum_shares(args)
