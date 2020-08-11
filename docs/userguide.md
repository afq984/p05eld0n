# Acquire the VPN configuration file

You should be given a configuration file named wg-<i>username</i>.conf


# Software Installation

Install WireGuard. Follow the instructions at:
https://www.wireguard.com/install/


# Linux usage instructions

Start:

```
sudo wg-quick up ./wg-username.conf
```

Stop:

```
sudo wg-quick down ./wg-username.conf
```


# Other platform usage instructions

Feed the configuration file to the GUI program.

# Testing

You should be able to ping the peer's address if you connected to the VPN successfully.
