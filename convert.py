#!/usr/bin/env python
"""Generate a systemd service unit from a wiresneak TOML config.

Usage: gen_service.py /etc/wiresneak/guinea.toml [-o OUTPUT]
"""
import argparse
import sys
import tomllib
from pathlib import Path

TEMPLATE = """\
[Unit]
After=network.target
Description=wiresneak tunnel for interface {name}
Wants=network.target

[Service]
ExecStart=/usr/bin/wiresneakd serve {config} {name}
{post}ExecStartPost=/usr/bin/ip link set up {name}
Type=notify

[Install]
WantedBy=multi-user.target
"""


def generate(config_path: Path) -> str:
    with config_path.open("rb") as f:
        cfg = tomllib.load(f)

    name = config_path.stem
    addresses = cfg.get("Interface", {}).get("Addresses", [])
    if isinstance(addresses, str):
        addresses = [addresses]

    post = "".join(
        f"ExecStartPost=/usr/bin/ip addr add {addr} dev {name}\n"
        for addr in addresses
    )

    return TEMPLATE.format(
        name=name,
        config=f"/etc/wiresneak/{config_path.name}",
        post=post,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("config", type=Path, help="path to <iface>.toml")
    ap.add_argument("-o", "--output", type=Path,
                    help="output file (default: stdout)")
    args = ap.parse_args()

    unit = generate(args.config)
    if args.output:
        args.output.write_text(unit)
    else:
        sys.stdout.write(unit)


if __name__ == "__main__":
    main()
