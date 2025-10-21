# Gatewaysocks

Relay TCP/UDP to SOCKS5.

```
    ---------------------------------       ----------------       ------------------
    |                               |       |              |       |                |
    |        Nintendo Switch        | ----> | gatewaysocks | ----> |  socks5 proxy  |
    |    (iPad or other devices)    |       |              |       |                |
    |     10.6.0.2/255.255.255.0    | ----> |   10.6.0.1   | ----> | 127.0.0.1:1080 |
    |                               |       |              |       |                |
    ---------------------------------       ----------------       ------------------
```

* basic TCP/UDP/ARP protocol implementation
* CUBIC congeston controller implementation for TCP
* async/await implementation

# Usage

Prepare a socks5 proxy(e.g. [stunnel](https://github.com/airtrack/stunnel)), which should support TCP/UDP proxy.

Run `gatewaysocks` as root.

***IMPORTANT*** change the limit of open files to be large enough, e.g. `ulimit -n 100000`.

```sh
./gatewaysocks \
    [-s socks5-address(e.g. 127.0.0.1:1080)] \
    [-i interface(e.g. en0)] \
    [--gateway-ip ip(e.g. 10.6.0.1)] \
    [--subnet-mask mask(e.g. 255.255.255.0)]
```

By default:

* socks5 address is `127.0.0.1:1080`
* gateway address is `10.6.0.1`
* subnet mask is `255.255.255.0`.

Change device's network settings:

1. change the IP to an IP in the subnet `10.6.0.1/255.255.255.0`
2. change the gateway to `10.6.0.1`
3. change the subnet mask to `255.255.255.0`
4. change the DNS(e.g. `8.8.8.8`)

# Status
`gatewaysocks` was tested on macOS(Apple silicon) and Linux.

# Work with stunnel and autoproxy

* [stunnel](https://github.com/airtrack/stunnel)
* [autoproxy](https://github.com/airtrack/autoproxy)

```
    ----------------                 -------------                        -------------
    |              |                 |           |                        |           |
    | gatewaysocks | --- TCP/UDP --> | autoproxy | ------- TCP/UDP -----> |  stunnel  |
    |              |                 |           |    |                   |           |
    ----------------                 -------------    |                   -------------
           ^                               ^          |
           |                               |          |                   -------------
           |                               |          |                   |           |
           |                               |          |--- TCP/UDP -----> |  direct   |
           |                               |                              |           |
           |                               |                              -------------
    -----------------             ------------------
    |    devices    |             |   set system   |
    |  in the same  |             | proxy settings |
    |    router     |             |  to autoproxy  |
    -----------------             ------------------
```
