from __future__ import annotations

import argparse

from pathlib import Path

from .collectors import collect_hardware
from .render_svg import render_svg


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    report = collect_hardware(
        exclude_usb_devices=args.exclude_usb_devices,
        no_pci_bridge=args.no_pci_bridge,
        no_addr=args.no_addr,
        no_vendor=args.no_vendor,
        no_net_dev=args.no_net_dev,
        no_net_status=args.no_net_status,
        no_wifi=args.no_wifi,
        no_bluetooth=args.no_bluetooth,
        no_display=args.no_display,
        no_display_status=args.no_display_status,
        no_audio_jack=args.no_audio_jack,
        read_sensors=args.read_sensors,
        no_sensors=args.no_sensors,
        test_numa=args.test_numa,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    render_svg(report, args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toposcope",
        description="Collect Linux hardware topology from direct kernel interfaces and render it as an SVG block diagram.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("toposcope.svg"),
        help="SVG block diagram output path. Defaults to ./toposcope.svg.",
    )
    parser.add_argument(
        "--no-usb-dev",
        dest="exclude_usb_devices",
        action="store_true",
        help="Hide everything behind USB root hubs while keeping USB controllers and root hubs.",
    )
    parser.add_argument(
        "--no-pci-bridge",
        action="store_true",
        help="Hide PCI bridge nodes and connect their downstream devices as grouped endpoints.",
    )
    parser.add_argument(
        "--no-addr",
        action="store_true",
        help="Do not prefix node labels with bus-local device addresses.",
    )
    parser.add_argument(
        "--no-vendor",
        action="store_true",
        help="Do not prefix node labels with vendor or manufacturer names.",
    )
    parser.add_argument(
        "--no-net-dev",
        action="store_true",
        help="Do not attach Ethernet or InfiniBand port nodes to NIC devices.",
    )
    parser.add_argument(
        "--no-net-status",
        action="store_true",
        help="Do not include current network port status in network port node labels.",
    )
    parser.add_argument(
        "--no-wifi",
        action="store_true",
        help="Do not attach Wi-Fi capability nodes to Wi-Fi devices.",
    )
    parser.add_argument(
        "--no-bluetooth",
        action="store_true",
        help="Do not attach Bluetooth adapter nodes to Bluetooth host devices.",
    )
    parser.add_argument(
        "--no-display",
        action="store_true",
        help="Do not attach connected display device nodes to GPU display ports.",
    )
    parser.add_argument(
        "--no-display-status",
        action="store_true",
        help="Show display capability summaries instead of current display status in connected display node labels.",
    )
    parser.add_argument(
        "--no-audio-jack",
        action="store_true",
        help="Do not attach connected audio endpoint nodes to audio ports.",
    )
    parser.add_argument(
        "--no-sensor",
        dest="no_sensors",
        action="store_true",
        help="Do not attach hwmon sensor channel nodes to hardware devices.",
    )
    parser.add_argument(
        "--read-sensor",
        dest="read_sensors",
        action="store_true",
        help="Append current hwmon sensor readings to sensor node labels.",
    )
    parser.add_argument(
        "--test-numa",
        metavar="N",
        type=positive_int,
        help="Debug: render N copies of NUMA node 0 instead of the current system NUMA topology.",
    )
    return parser


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number
