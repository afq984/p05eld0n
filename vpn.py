#!/usr/bin/env python3
"""
SPDX-License-Identifier: MIT
"""

import socket
import functools
import itertools
import http.server
import html
import hashlib
import signal
import secrets
import urllib.parse
import random
import subprocess
import ipaddress
import os
import sys
import pwd
import grp
import argparse
import contextlib


eprint = functools.partial(print, file=sys.stderr)


def get_public_address():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(('8.8.8.8', 0))
        return s.getsockname()[0]


def wg_genkey():
    return subprocess.check_output(['wg', 'genkey'], text=True).rstrip()


def wg_pubkey(key):
    return subprocess.check_output(['wg', 'pubkey'], input=key,
                                   text=True).rstrip()


def wg_genpsk():
    return subprocess.check_output(['wg', 'genpsk'], text=True).rstrip()


def write_config(config, file):
    if isinstance(config, dict):
        config = config.items()
    for i, (section, options) in enumerate(config):
        if i:
            file.write('\n')
        file.write(f'[{section}]\n')
        for key, value in options.items():
            file.write(f'{key}={value}\n')


def read_config(file):
    section = None
    config = {}
    for lineno, line in enumerate(file, 1):
        line = line.rstrip()
        if not line:
            continue
        if line.startswith('#'):
            continue
        if line.startswith('['):
            assert line.endswith(']'), lineno
            section = config[line[1:-1]] = {}
        else:
            key, eq, value = line.partition('=')
            assert eq, lineno
            section[key] = value
    return config


@contextlib.contextmanager
def awopen(filename, *args, **kwargs):
    yield open(filename + '+', *args, **kwargs)
    os.rename(filename + '+', filename)


def setdefaultfunc(mapping, key, func):
    if key not in mapping:
        return mapping.setdefault(key, func())


def init_peer(userconfig, network, used_addresses):
    if 'Address' not in userconfig:
        for _ in range(10):
            address = network[random.randrange(1, network.num_addresses - 1)]
            if address not in used_addresses:
                userconfig['Address'] = address
                used_addresses.add(address)
                break
        else:
            raise Exception('Cannot find a random address')

    userconfig.setdefault('AllowedIPs', '')
    userconfig.setdefault('AllowedInterfaces', '')
    setdefaultfunc(userconfig, 'PrivateKey', wg_genkey)
    setdefaultfunc(userconfig, 'PresharedKey', wg_genpsk)


def init(users):
    try:
        with open('vpn.conf') as file:
            config = read_config(file)
    except FileNotFoundError:
        config = {}

    vpn = config.setdefault('VPN', {})
    vpn.setdefault('Name', 'wg0')
    setdefaultfunc(vpn, 'EndpointIP', get_public_address)
    vpn.setdefault('EndpointPort', '443')
    setdefaultfunc(
        vpn, 'Address', lambda:
        str(ipaddress.IPv4Address(random.randrange(256**3) +
                                  (10 << 24))) + '/16'
    )
    setdefaultfunc(vpn, 'PrivateKey', wg_genkey)

    used_addresses = {ipaddress.ip_address(vpn['Address'].partition('/')[0])}
    network = ipaddress.ip_network(vpn['Address'], strict=False)

    for user in users:
        init_peer(config.setdefault(user, {}), network, used_addresses)

    with awopen('vpn.conf', 'w') as file:
        write_config(config, file)
    eprint('Initialized vpn.conf')


def check_config(config):
    valid_VPN = {'Name', 'EndpointIP', 'EndpointPort', 'Address', 'PrivateKey'}
    valid_user = {'Address', 'AllowedIPs', 'AllowedInterfaces', 'PrivateKey', 'PresharedKey'}
    for user, userconfig in config.items():
        if user == 'VPN':
            valid_keys = valid_VPN
        else:
            valid_keys = valid_user
        for key in userconfig.keys() - valid_keys:
            eprint(f'Warning: [{user}] contains invalid option: {key}')


def generate(root='/'):
    os.umask(0o077)

    with open('vpn.conf') as file:
        config = read_config(file)
    check_config(config)
    wgx = config['VPN']['Name']
    vpnaddr = ipaddress.ip_interface(config['VPN']['Address'])

    sdnetworkdir = os.path.join(root, 'etc', 'systemd', 'network')
    os.makedirs(sdnetworkdir, exist_ok=True)

    netdevfile = os.path.join(sdnetworkdir, f'99-{wgx}.netdev')
    netdevconfig = [
        ('NetDev', {
            'Name': wgx,
            'Kind': 'wireguard',
        }),
        ('WireGuard', {
            'ListenPort': config['VPN']['EndpointPort'],
            'PrivateKey': config['VPN']['PrivateKey'],
        }),
    ]
    for user, userconfig in config.items():
        if user == 'VPN':
            continue
        netdevconfig.append((
            'WireGuardPeer', {
                'PublicKey': wg_pubkey(userconfig['PrivateKey']),
                'PresharedKey': userconfig['PresharedKey'],
                'AllowedIPs': ipaddress.ip_interface(userconfig['Address']).ip,
            }
        ))
    with awopen(netdevfile, 'w') as file:
        write_config(netdevconfig, file)
    eprint('Generated', netdevfile)

    networkfile = os.path.join(sdnetworkdir, f'99-{wgx}.network')
    with awopen(networkfile, 'w') as file:
        write_config(
            {
                'Match': {
                    'Name': wgx,
                },
                'Network': {
                    'Address': ipaddress.ip_network(vpnaddr.ip),
                    'IPForward': '1',
                },
                'Route': {
                    'Gateway': vpnaddr.ip,
                    'Destination': vpnaddr.network,
                }
            },
            file,
        )
    eprint('Generated', networkfile)

    nftablesfile = os.path.join(root, 'etc', 'nftables.conf')
    with awopen(nftablesfile, 'w') as file:
        file.write('table ip nat\n')
        file.write('\tchain pre {\n')
        file.write('\t\ttype nat hook prerouting priority filter; policy accept;\n')
        file.write('\t}\n')
        file.write('\n')
        file.write('\tchain post {\n')
        file.write('\t\ttype nat hook postrouting priority filter; policy accept;\n')
        file.write(f'\t\tiifname "{wgx}" ip daddr {vpnaddr.ip} masquerade  # debug\n')
        for user, userconfig in config.items():
            if user == 'VPN':
                continue
            useraddr = ipaddress.ip_interface(userconfig['Address'])
            formatter = f'\t\tiifname "{wgx}" ip saddr {useraddr.ip}{{}} masquerade  # user {user}\n'
            if interfaces := userconfig.get('AllowedInterfaces', ''):
                for interface in split_comma(interfaces):
                    if interface == 'all':
                        file.write(formatter.format(''))
                    else:
                        file.write(formatter.format(f' oifname "{interface}"'))
            if allowed_ips := userconfig.get('AllowedIPs', '').strip():
                ranges = ', '.join(flatten_address_range(allowed_ips))
                file.write(formatter.format(f' daddr {{ {ranges} }}'))
            netdevconfig.append((
                'WireGuardPeer', {
                    'PublicKey': wg_pubkey(userconfig['PrivateKey']),
                    'PresharedKey': userconfig['PresharedKey'],
                    'AllowedIPs': ipaddress.ip_network(userconfig['Address'].partition('/')[0]),
                }
            ))
        file.write('\t}\n')
        file.write('}\n')
    eprint('Generated', nftablesfile)


def split_comma(s):
    return filter(None, map(str.strip, str.split(s, ',')))


def flatten_address_range(raw_address_range):
    first, to, last = raw_address_range.partition('-')
    if not to:
        return first
    if last.isdigit():
        assert 0 <= int(last) < 256
        last = ipaddress.IPv4Address((int(ipaddress.IPv4Address(first)) & 0xffffff00) | int(last))
    return f'{first}-{last}'


def parse_address_ranges(raw_address_ranges):
    for raw_address_range in split_comma(raw_address_ranges):
        first, to, last = flatten_address_range(raw_address_range).partition('-')
        if to:
            yield from ipaddress.summarize_address_range(
                ipaddress.ip_address(first), ipaddress.ip_address(last),
            )
        else:
            yield ipaddress.ip_network(first)


def guess_allowed_ips(interfaces):
    interfaces = set(interfaces)
    for line in subprocess.check_output(['ip', 'route'], text=True).splitlines():
        parts = line.split()
        interface = parts[parts.index('dev') + 1]
        if parts[:2] == ['default', 'via']:
            network = ipaddress.IPv4Network((0, 0))
        else:
            network = ipaddress.ip_network(parts[0])
        if interface in interfaces or 'all' in interfaces:
            yield network


def temp_serve(content, filename, serve_timeout):
    if os.getuid() == 0:
        os.setgroups([])
        os.setgid(grp.getgrnam('nobody').gr_gid)
        os.setuid(pwd.getpwnam('nobody').pw_uid)

    secret_path = secrets.token_urlsafe(32)
    entry_content = f'''<!doctype html>
<html><head>
<title>Link expires after 1 day or downloading</title>
<style>body {{ font-family: monospace; }}</style>
</head><body>
<h3>{html.escape(filename)}</h3>
<p><a href=
"/{secret_path}/{html.escape(filename)}"
>Download</a></p>
<dl>
<dt>size</dt><dd>{len(content)}</dd>
<dt>sha1</dt><dd>{hashlib.sha1(content).hexdigest()}</dd>
<dt>sha256</dt><dd>{hashlib.sha256(content).hexdigest()}</dd>
</dl>
</body></html>
'''.encode()
    class RequestHandler(http.server.BaseHTTPRequestHandler):
        done = lambda: ()

        def do_GET(self):
            cleanpath = urllib.parse.urlparse(self.path).path
            if cleanpath == f'/{secret_path}/':
                self.handle_entry()
            elif cleanpath == f'/{secret_path}/{filename}':
                self.send_file()
            else:
                self.send_error(http.HTTPStatus.NOT_FOUND)

        def handle_entry(self):
            self.send_response(http.HTTPStatus.OK)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', len(entry_content))
            self.end_headers()
            self.wfile.write(entry_content)

        def send_file(self):
            self.send_response(http.HTTPStatus.OK)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
            self.done()

    with http.server.ThreadingHTTPServer(('', 0), RequestHandler) as server:
        RequestHandler.done = server.shutdown
        def handle_signal(signum, frame):
            server.shutdown()
        signal.signal(signal.SIGALRM, handle_signal)
        signal.alarm(serve_timeout)
        address, port = server.server_address
        print(f'http://localhost:{port}/{secret_path}/')
        print(f'http://{get_public_address()}:{port}/{secret_path}/')
        server.serve_forever()


def wgquick(user, serve, serve_timeout):
    with open('vpn.conf') as file:
        config = read_config(file)
    check_config(config)
    vpn = config['VPN']
    userconfig = config[user]
    pingaddr = ipaddress.ip_interface(vpn['Address']).ip
    address = userconfig['Address']
    privkey = userconfig['PrivateKey']
    pubkey = wg_pubkey(vpn['PrivateKey'])
    psk = userconfig['PresharedKey']
    allowed_ips = ', '.join(map(str,
        ipaddress.collapse_addresses(itertools.chain(
            [pingaddr],
            guess_allowed_ips(split_comma(userconfig.get('AllowedInterfaces', ''))),
            parse_address_ranges(userconfig.get('AllowedIPs', '')),
        ))
    ))
    endpoint_ip = vpn['EndpointIP']
    endpoint_port = vpn['EndpointPort']
    configtext = f'''\
# wg-{user}.conf
# ping {pingaddr} to test

[Interface]
Address={address}
PrivateKey={privkey}

[Peer]
PublicKey={pubkey}
PresharedKey={psk}
AllowedIPs={allowed_ips}
Endpoint={endpoint_ip}:{endpoint_port}
'''
    print(end=configtext)
    if serve:
        print('-' * 79)
        temp_serve(configtext.encode(), f'wg-{user}.conf', serve_timeout)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_init = subparsers.add_parser('init')
    parser_init.add_argument('users', nargs='*')
    parser_init.set_defaults(func=init)

    parser_generate = subparsers.add_parser('generate')
    parser_generate.add_argument('--root', default='/')
    parser_generate.set_defaults(func=generate)

    parser_wgquick = subparsers.add_parser('wgquick')
    parser_wgquick.add_argument('user')
    parser_wgquick.add_argument('--serve', action='store_true')
    parser_wgquick.add_argument(
        '--serve-timeout', help='timeout for temporary server', default=86400, type=int)
    parser_wgquick.set_defaults(func=wgquick)

    args = parser.parse_args()
    if 'func' not in args:
        parser.print_usage()
    else:
        opts = vars(args)
        func = opts.pop('func')
        func(**opts)


if __name__ == '__main__':
    main()
