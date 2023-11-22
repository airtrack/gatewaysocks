gatewaysocks
============

Relay TCP/UDP to SOCKS5.

    ---------------------------------       ----------------       ------------------
    | Nintendo Switch/Other devices | ----> | gatewaysocks | ----> |  socks5 proxy  |
    |    10.6.0.2/255.255.255.0     | ----> |   10.6.0.1   | ----> | 127.0.0.1:1080 |
    ---------------------------------       ----------------       ------------------

Usage
-----

Prepare a socks5 proxy(e.g. [stunnel](https://github.com/airtrack/stunnel)), which should support TCP/UDP proxy.

Run `gatewaysocks` as root.

    ./gatewaysocks [-s socks5-address(e.g. 127.0.0.1:1080)] [-i interface(e.g. en0)] [--gateway-ip ip(e.g. 10.6.0.1)] [--subnet-mask mask(e.g. 255.255.255.0)]

By default, socks5 address is `127.0.0.1:1080`, gateway address is `10.6.0.1`, subnet mask is `255.255.255.0`.

Change console(e.g. Nintendo Switch) setting, set IP to `10.6.0.2` or others in the subnet `10.6.0.1/255.255.255.0`, set gateway to `10.6.0.1`, set subnet mask to `255.255.255.0`, change DNS(e.g. `8.8.8.8`).

Status
------
`gatewaysocks` was just tested on macOS(M1 chip).
