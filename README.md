# Wiresneak

- Ever wanted to write a simple static config the way [Wireguard](https://wireguard.com/) allows you to?
- Ever got stuck with Wireguard because you don't have a public IP address and didn't wanna port forward?
- Ever heard of [Iroh](https://iroh.computer/)'s p2p technology but can't find a simple project that doesn't add a ton of access control features on top of a simple IP tunnel (*and thus force you to designate at least one machine for coordination*)?

Well, I know I have.

## What's in this project?

This project is meant to be very simple - nothing more. It assumes you know how to properly organize a firewall and that don't need to manage access control in the tunnel.
It assumes you already know who is allowed to connect to whom and that you will simply manage this with a list of allowed IPs in the configuration file.
It assumes you have a way to create/generate these configuration files for all of your machines and to deploy them.

It does not assume that you will only need 1 tunnel. It does not assume you want magic DNS over this tunnel. It assumes you simply want an IP tunnel between 2 or more devices that automatically performs NAT traversal.

This project is a very small piece of glue around `tun-rs` and `iroh`, only filtering based on public key and ip addresses similar to Wireguard's cryptorouting. Use at your own risk.

**It has only been designed for and tested on Linux.**
