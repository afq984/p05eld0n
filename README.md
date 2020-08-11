VPN configuration generator for WireGuard to work with systemd-networkd, nftables and wg-quick.

## Usage

1.  Install systemd-networkd and nftables.
2.  Run <code>./vpn init <i>[USERNAME]...</i></code> to populate the configuration file.
3.  Update the configuration file as desired.
4.  Run `./vpn generate` to generate configuration files for systemd-networkd and nftables.
5.  `systemctl restart systemd-networkd nftables`
6.  Run <code>./vpn wgquick <i>USERNAME</i></code> to generate wg-quick configuration files for a specific user.
    Add `--serve` to temporarily serve the generated file over HTTP on a random address.

## Configuration (`vpn.conf`)

### `[VPN]` section

*   `Name` -- name of the WireGuard device
*   `EndpointIP` -- the public IP of the VPN service
*   `EndpointPort` -- the public UDP port of the VPN service
*   `Address` -- the CIDR address of the wireguard network

### <code>[<i>username</i>]</code> section

*   `Address` -- the IP address of the client in the wireguard network
*   `AllowedInterfaces` -- `,` separated network interfaces to grant access to this user.
    The special string `all` grants access to all interfaces.
*   `AllowedIPs` -- `,` separated IP ranges that the user is allowed to connect to.
    *   `10.0.0.1`: single IP
    *   `10.0.0.1-10.0.0.24`: multiple IP addresses
    *   `10.0.0.1-24`: equivalent to above
    *   `10.0.0.1-1.24`: too complex so not allowed
    *   `10.0.0.0/24`: equivalent to `10.0.0.0-255`

##
