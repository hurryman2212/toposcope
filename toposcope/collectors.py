from __future__ import annotations

import ctypes, fcntl, os, platform, re, socket, struct

from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from .ids import PciIds, PnpIds, UsbIds, pci_class_name, usb_class_name
from .topology import build_topology_report
from .util import (
    clean_value,
    drop_none,
    human_bytes,
    parse_cpu_list,
    parse_int,
    parse_meminfo,
    natural_key,
    read_bytes,
    read_clean,
    read_first_line,
    read_hex_id,
    read_int,
    read_text,
    readlink_name,
    readlink_target,
    redact_tree,
    root_join,
    sorted_paths,
    truthy_sysfs,
)

CPU_DIR_PATTERN = re.compile(r"cpu\d+$")
MEMORY_DIR_PATTERN = re.compile(r"memory\d+$")
PCI_SLOT_PATTERN = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
USB_ROOT_PATTERN = re.compile(r"^usb\d+$")
USB_DEVICE_PATTERN = re.compile(r"^\d+-\d+(?:\.\d+)*$")
HDA_NODE_PATTERN = re.compile(r"^Node\s+(0x[0-9a-fA-F]+)\s+\[([^\]]+)\](.*)$")
HDA_PIN_DEFAULT_PATTERN = re.compile(
    r"^Pin Default\s+(0x[0-9a-fA-F]+):\s+\[([^\]]+)\]\s+(.+?)(?:\s+at\s+(.+))?$"
)
HDA_CONN_PATTERN = re.compile(r"^Conn\s*=\s*([^,]+),\s*Color\s*=\s*(.+)$")
HDA_CONTROL_PATTERN = re.compile(r'^Control:\s+name="([^"]+)"')
HDA_DEVICE_PATTERN = re.compile(r'^Device:\s+name="([^"]+)".*device=(\d+)')
HDA_DEV_PATTERN = re.compile(r"^\*?Dev\s+(\d+):\s+(.+)$")
USB_AUDIO_SECTION_PATTERN = re.compile(r"^(Playback|Capture):$")
USB_AUDIO_INTERFACE_PATTERN = re.compile(r"^Interface\s+(\d+)$")
USB_AUDIO_ENDPOINT_PATTERN = re.compile(
    r"^(0x[0-9a-fA-F]+)\s+\(([^)]+)\)(?:\s+\(([^)]+)\))?"
)
BLUETOOTH_HCI_NAME_PATTERN = re.compile(r"^hci(\d+)$")
EVIOCGSW_BASE = 0x8000451B
INPUT_SWITCH_NAMES = {
    2: "headphone",
    4: "microphone",
    6: "lineout",
    7: "jack",
    8: "videoout",
    13: "linein",
}
HCI_DEV_NONE = 0xFFFF
HCI_CHANNEL_CONTROL = 3
MGMT_OP_READ_VERSION = 0x0001
MGMT_OP_READ_INDEX_LIST = 0x0003
MGMT_OP_READ_INFO = 0x0004
MGMT_EV_CMD_COMPLETE = 0x0001
MGMT_EV_CMD_STATUS = 0x0002

BLUETOOTH_CORE_VERSIONS = {
    0: "1.0b",
    1: "1.1",
    2: "1.2",
    3: "2.0 + EDR",
    4: "2.1 + EDR",
    5: "3.0 + HS",
    6: "4.0",
    7: "4.1",
    8: "4.2",
    9: "5.0",
    10: "5.1",
    11: "5.2",
    12: "5.3",
    13: "5.4",
}

BLUETOOTH_MGMT_SETTINGS = (
    (0, "Powered"),
    (1, "Connectable"),
    (2, "Fast Connectable"),
    (3, "Discoverable"),
    (4, "Bondable"),
    (5, "Link Security"),
    (6, "SSP"),
    (7, "BR/EDR"),
    (8, "HS"),
    (9, "LE"),
    (10, "Advertising"),
    (11, "Secure Connections"),
    (12, "Debug Keys"),
    (13, "Privacy"),
    (14, "Controller Configuration"),
    (15, "Static Address"),
    (16, "PHY Configuration"),
    (17, "Wideband Speech"),
    (18, "CIS Central"),
    (19, "CIS Peripheral"),
    (20, "ISO Broadcaster"),
    (21, "Synchronized Receiver"),
    (22, "LL Privacy"),
    (23, "PAST Sender"),
    (24, "PAST Receiver"),
)

NL80211_CMD_ASSOC_MLO_RECONF_FALLBACK = "NL80211_CMD_156"
NL80211_STATION_IFTYPE = "NL80211_IFTYPE_STATION"
NL80211_EHT_BAND_IFTYPE_ATTRS = (
    ("NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS", "hex"),
    ("NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC", "array(uint8)"),
    ("NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY", "array(uint8)"),
    ("NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET", "array(uint8)"),
    ("NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE", "array(uint8)"),
)

DMI_MEMORY_FORM_FACTORS = {
    0x01: "Other",
    0x02: "Unknown",
    0x03: "SIMM",
    0x04: "SIP",
    0x05: "Chip",
    0x06: "DIP",
    0x07: "ZIP",
    0x08: "Proprietary Card",
    0x09: "DIMM",
    0x0A: "TSOP",
    0x0B: "Row Of Chips",
    0x0C: "RIMM",
    0x0D: "SODIMM",
    0x0E: "SRIMM",
    0x0F: "FB-DIMM",
}

DMI_MEMORY_TYPES = {
    0x01: "Other",
    0x02: "Unknown",
    0x03: "DRAM",
    0x04: "EDRAM",
    0x05: "VRAM",
    0x06: "SRAM",
    0x07: "RAM",
    0x08: "ROM",
    0x09: "Flash",
    0x0A: "EEPROM",
    0x0B: "FEPROM",
    0x0C: "EPROM",
    0x0D: "CDRAM",
    0x0E: "3DRAM",
    0x0F: "SDRAM",
    0x10: "SGRAM",
    0x11: "RDRAM",
    0x12: "DDR",
    0x13: "DDR2",
    0x14: "DDR2 FB-DIMM",
    0x18: "DDR3",
    0x19: "FBD2",
    0x1A: "DDR4",
    0x1B: "LPDDR",
    0x1C: "LPDDR2",
    0x1D: "LPDDR3",
    0x1E: "LPDDR4",
    0x1F: "Logical non-volatile device",
    0x20: "HBM",
    0x21: "HBM2",
    0x22: "DDR5",
    0x23: "LPDDR5",
    0x24: "HBM3",
}

DRM_DISPLAY_MODE_LEN = 32


class DrmModeModeInfo(ctypes.Structure):
    _fields_ = [
        ("clock", ctypes.c_uint32),
        ("hdisplay", ctypes.c_uint16),
        ("hsync_start", ctypes.c_uint16),
        ("hsync_end", ctypes.c_uint16),
        ("htotal", ctypes.c_uint16),
        ("hskew", ctypes.c_uint16),
        ("vdisplay", ctypes.c_uint16),
        ("vsync_start", ctypes.c_uint16),
        ("vsync_end", ctypes.c_uint16),
        ("vtotal", ctypes.c_uint16),
        ("vscan", ctypes.c_uint16),
        ("vrefresh", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("name", ctypes.c_char * DRM_DISPLAY_MODE_LEN),
    ]


class DrmModeCrtc(ctypes.Structure):
    _fields_ = [
        ("set_connectors_ptr", ctypes.c_uint64),
        ("count_connectors", ctypes.c_uint32),
        ("crtc_id", ctypes.c_uint32),
        ("fb_id", ctypes.c_uint32),
        ("x", ctypes.c_uint32),
        ("y", ctypes.c_uint32),
        ("gamma_size", ctypes.c_uint32),
        ("mode_valid", ctypes.c_uint32),
        ("mode", DrmModeModeInfo),
    ]


class DrmModeGetEncoder(ctypes.Structure):
    _fields_ = [
        ("encoder_id", ctypes.c_uint32),
        ("encoder_type", ctypes.c_uint32),
        ("crtc_id", ctypes.c_uint32),
        ("possible_crtcs", ctypes.c_uint32),
        ("possible_clones", ctypes.c_uint32),
    ]


class DrmModeGetConnector(ctypes.Structure):
    _fields_ = [
        ("encoders_ptr", ctypes.c_uint64),
        ("modes_ptr", ctypes.c_uint64),
        ("props_ptr", ctypes.c_uint64),
        ("prop_values_ptr", ctypes.c_uint64),
        ("count_modes", ctypes.c_uint32),
        ("count_props", ctypes.c_uint32),
        ("count_encoders", ctypes.c_uint32),
        ("encoder_id", ctypes.c_uint32),
        ("connector_id", ctypes.c_uint32),
        ("connector_type", ctypes.c_uint32),
        ("connector_type_id", ctypes.c_uint32),
        ("connection", ctypes.c_uint32),
        ("mm_width", ctypes.c_uint32),
        ("mm_height", ctypes.c_uint32),
        ("subpixel", ctypes.c_uint32),
        ("pad", ctypes.c_uint32),
    ]


class DrmModePropertyEnum(ctypes.Structure):
    _fields_ = [
        ("value", ctypes.c_uint64),
        ("name", ctypes.c_char * 32),
    ]


class DrmModeGetProperty(ctypes.Structure):
    _fields_ = [
        ("values_ptr", ctypes.c_uint64),
        ("enum_blob_ptr", ctypes.c_uint64),
        ("prop_id", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("name", ctypes.c_char * 32),
        ("count_values", ctypes.c_uint32),
        ("count_enum_blobs", ctypes.c_uint32),
    ]


def drm_iowr(number: int, data_type: type[ctypes.Structure]) -> int:
    return (3 << 30) | (ord("d") << 8) | number | (ctypes.sizeof(data_type) << 16)


DRM_IOCTL_MODE_GETCRTC = drm_iowr(0xA1, DrmModeCrtc)
DRM_IOCTL_MODE_GETENCODER = drm_iowr(0xA6, DrmModeGetEncoder)
DRM_IOCTL_MODE_GETCONNECTOR = drm_iowr(0xA7, DrmModeGetConnector)
DRM_IOCTL_MODE_GETPROPERTY = drm_iowr(0xAA, DrmModeGetProperty)


class HardwareCollector:
    def __init__(
        self,
        root: Path = Path("/"),
        *,
        redact_serials: bool = False,
        exclude_usb_devices: bool = False,
        no_pci_bridge: bool = False,
        no_addr: bool = False,
        no_vendor: bool = False,
        no_net_dev: bool = False,
        no_net_status: bool = False,
        no_wifi: bool = False,
        no_bluetooth: bool = False,
        no_display: bool = False,
        no_display_status: bool = False,
        no_audio_jack: bool = False,
        read_sensors: bool = False,
        no_sensors: bool = False,
        test_numa: int | None = None,
    ) -> None:
        self.root = root
        self.redact_serials = redact_serials
        self.exclude_usb_devices = exclude_usb_devices
        self.no_pci_bridge = no_pci_bridge
        self.no_addr = no_addr
        self.no_vendor = no_vendor
        self.no_net_dev = no_net_dev
        self.no_net_status = no_net_status
        self.no_wifi = no_wifi
        self.no_bluetooth = no_bluetooth
        self.no_display = no_display
        self.no_display_status = no_display_status
        self.no_audio_jack = no_audio_jack
        self.read_sensors = read_sensors
        self.no_sensors = no_sensors
        self.test_numa = test_numa
        self.pci_ids = PciIds.load(root)
        self.pnp_ids = PnpIds.load(root)
        self.usb_ids = UsbIds.load(root)

    def path(self, absolute_path: str | Path) -> Path:
        return root_join(self.root, absolute_path)

    def is_virtual_path(self, path: str | None) -> bool:
        if not path:
            return True
        cleaned = path.rstrip("/")
        return cleaned == "/sys/devices/virtual" or "/sys/devices/virtual/" in cleaned

    def is_sriov_vf_dir(self, dev_dir: Path) -> bool:
        return (dev_dir / "physfn").exists()

    def is_sriov_vf_path(self, path: str | None) -> bool:
        if not path:
            return False
        candidate = Path(path)
        if (candidate / "physfn").exists():
            return True
        slot = candidate.name
        if PCI_SLOT_PATTERN.match(slot):
            return self.is_sriov_vf_dir(self.path("/sys/bus/pci/devices") / slot)
        return False

    def should_output_device_path(self, path: str | None) -> bool:
        return (
            bool(path)
            and not self.is_virtual_path(path)
            and not self.is_sriov_vf_path(path)
            and not (self.exclude_usb_devices and self.is_usb_downstream_path(path))
        )

    def is_usb_downstream_path(self, path: str | None) -> bool:
        if not path:
            return False
        for part in reversed(Path(path).parts):
            if ":" in part:
                base, suffix = part.split(":", 1)
                if not re.fullmatch(r"\d+\.\d+", suffix):
                    continue
                name = base
            else:
                name = part
            if USB_ROOT_PATTERN.match(name):
                return False
            if not USB_DEVICE_PATTERN.match(name):
                continue
            dev_dir = self.path("/sys/bus/usb/devices") / name
            if not dev_dir.exists():
                continue
            return True
        return False

    def collect(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "schema": "toposcope.hardware.v1",
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "collector": {
                "name": "toposcope",
                "version": "0.1.0",
                "root": str(self.root),
                "pci_id_source": self.pci_ids.source,
                "pnp_id_source": self.pnp_ids.source,
                "usb_id_source": self.usb_ids.source,
                "strategy": "direct /sys, /proc, firmware interface, and local hardware ID database reads",
            },
            "options": {
                "exclude_usb_devices": self.exclude_usb_devices,
                "no_pci_bridge": self.no_pci_bridge,
                "no_addr": self.no_addr,
                "no_vendor": self.no_vendor,
                "no_net_dev": self.no_net_dev,
                "no_net_status": self.no_net_status,
                "no_wifi": self.no_wifi,
                "no_bluetooth": self.no_bluetooth,
                "no_display": self.no_display,
                "no_display_status": self.no_display_status,
                "no_audio_jack": self.no_audio_jack,
                "read_sensors": self.read_sensors,
                "no_sensors": self.no_sensors,
            },
            "host": self.collect_host(),
            "firmware": self.collect_firmware(),
            "cpu": self.collect_cpu(),
            "memory": self.collect_memory(),
            "pci": self.collect_pci(),
            "usb": self.collect_usb(),
            "storage": self.collect_storage(),
            "network": self.collect_network(),
            "bluetooth": self.collect_bluetooth(),
            "graphics": self.collect_graphics(),
            "sound": self.collect_sound(),
            "input": self.collect_input(),
            "power": self.collect_power(),
            "thermal": self.collect_thermal(),
            "sensors": self.collect_hwmon(),
            "acpi": self.collect_acpi(),
            "resources": self.collect_system_resources(),
            "buses": self.collect_buses(),
        }
        if self.test_numa is not None:
            report.setdefault("debug", {})["test_numa"] = self.test_numa
            self.apply_test_numa(report, self.test_numa)
        report["topology"] = build_topology_report(report)
        cleaned = drop_none(report)
        if self.redact_serials:
            return redact_tree(
                cleaned,
                sensitive_terms=("serial", "uuid", "wwid", "wwn", "eui", "nguid"),
            )
        return cleaned

    def collect_host(self) -> dict[str, Any]:
        os_release = self.parse_os_release(self.path("/etc/os-release"))
        return {
            "kernel": {
                "sysname": read_clean(self.path("/proc/sys/kernel/ostype"))
                or platform.system(),
                "release": read_clean(self.path("/proc/sys/kernel/osrelease"))
                or platform.release(),
                "version": read_clean(self.path("/proc/version")),
                "architecture": platform.machine(),
                "boot_id": read_clean(self.path("/proc/sys/kernel/random/boot_id")),
            },
            "os_release": os_release,
            "machine_id": read_clean(self.path("/etc/machine-id")),
        }

    def parse_os_release(self, path: Path) -> dict[str, str]:
        text = read_text(path)
        if text is None:
            return {}
        result: dict[str, str] = {}
        for line in text.splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
            result[key] = value
        return result

    def collect_firmware(self) -> dict[str, Any]:
        dmi = self.path("/sys/class/dmi/id")
        dmi_fields = {
            "system": (
                "sys_vendor",
                "product_name",
                "product_version",
                "product_family",
                "product_sku",
                "product_serial",
                "product_uuid",
            ),
            "baseboard": (
                "board_vendor",
                "board_name",
                "board_version",
                "board_serial",
                "board_asset_tag",
            ),
            "bios": (
                "bios_vendor",
                "bios_version",
                "bios_date",
                "bios_release",
                "ec_firmware_release",
            ),
            "chassis": (
                "chassis_vendor",
                "chassis_type",
                "chassis_version",
                "chassis_serial",
                "chassis_asset_tag",
            ),
        }
        result: dict[str, Any] = {}
        for group, fields in dmi_fields.items():
            values = {field: read_clean(dmi / field) for field in fields}
            result[group] = values

        device_tree = self.path("/proc/device-tree")
        if device_tree.exists():
            result["device_tree"] = {
                "model": read_clean(device_tree / "model"),
                "compatible": read_clean(device_tree / "compatible"),
                "serial_number": read_clean(device_tree / "serial-number"),
            }
        result["modalias"] = read_clean(dmi / "modalias")
        return result

    def collect_cpu(self) -> dict[str, Any]:
        cpuinfo = self.parse_cpuinfo(self.path("/proc/cpuinfo"))
        sys_cpu = self.path("/sys/devices/system/cpu")
        cpu_dirs = []
        if sys_cpu.exists():
            cpu_dirs = [
                path
                for path in sorted_paths(sys_cpu.iterdir())
                if CPU_DIR_PATTERN.match(path.name)
            ]
        topologies = [self.collect_cpu_topology(cpu_dir) for cpu_dir in cpu_dirs]
        cpufreq = [
            freq for cpu_dir in cpu_dirs if (freq := self.collect_cpufreq(cpu_dir))
        ]
        caches = self.collect_cpu_caches(cpu_dirs)
        possible = read_clean(sys_cpu / "possible")
        present = read_clean(sys_cpu / "present")
        online = read_clean(sys_cpu / "online")
        isolated = read_clean(sys_cpu / "isolated")
        offline = read_clean(sys_cpu / "offline")
        model_counter: Counter[str] = Counter()
        vendors: set[str] = set()
        flags: set[str] = set()
        for processor in cpuinfo:
            model_name = (
                processor.get("model name")
                or processor.get("Processor")
                or processor.get("cpu")
                or processor.get("Hardware")
            )
            if model_name:
                model_counter[model_name] += 1
            vendor = processor.get("vendor_id") or processor.get("CPU implementer")
            if vendor:
                vendors.add(vendor)
            for key in ("flags", "Features"):
                if processor.get(key):
                    flags.update(processor[key].split())
        sockets = sorted(
            {
                topology.get("physical_package_id")
                for topology in topologies
                if topology.get("physical_package_id") not in (None, "-1")
            }
        )
        cores = sorted(
            {
                (
                    topology.get("physical_package_id"),
                    topology.get("core_id"),
                )
                for topology in topologies
                if topology.get("core_id") not in (None, "-1")
            }
        )
        return {
            "summary": {
                "architecture": platform.machine(),
                "logical_processors": len(cpuinfo) or len(cpu_dirs) or None,
                "online_processors": len(parse_cpu_list(online)) if online else None,
                "possible_processors": (
                    len(parse_cpu_list(possible)) if possible else None
                ),
                "sockets": len(sockets) or None,
                "cores": len(cores) or None,
                "models": dict(model_counter),
                "vendors": sorted(vendors),
                "feature_count": len(flags) or None,
            },
            "cpu_sets": {
                "possible": possible,
                "present": present,
                "online": online,
                "offline": offline,
                "isolated": isolated,
            },
            "processors": cpuinfo,
            "topology": topologies,
            "frequency": cpufreq,
            "caches": caches,
            "numa": self.collect_numa(),
        }

    def parse_cpuinfo(self, path: Path) -> list[dict[str, str]]:
        text = read_text(path, max_bytes=4_000_000)
        if text is None:
            return []
        processors: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in text.splitlines():
            if not line.strip():
                if current:
                    processors.append(current)
                    current = {}
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                current[key.strip()] = value.strip()
        if current:
            processors.append(current)
        return processors

    def collect_cpu_topology(self, cpu_dir: Path) -> dict[str, Any]:
        topology_dir = cpu_dir / "topology"
        cache_root = cpu_dir / "cache"
        cpu_number = parse_int(cpu_dir.name.removeprefix("cpu"))
        topology_attrs = (
            "physical_package_id",
            "die_id",
            "cluster_id",
            "core_id",
            "book_id",
            "drawer_id",
            "thread_siblings_list",
            "core_siblings_list",
            "package_cpus_list",
            "die_cpus_list",
            "cluster_cpus_list",
        )
        values = {attr: read_clean(topology_dir / attr) for attr in topology_attrs}
        values.update(
            {
                "cpu": cpu_number,
                "online": truthy_sysfs(read_first_line(cpu_dir / "online")),
                "cache_indexes": (
                    len(list(cache_root.glob("index*")))
                    if cache_root.exists()
                    else None
                ),
            }
        )
        return values

    def collect_cpufreq(self, cpu_dir: Path) -> dict[str, Any] | None:
        freq_dir = cpu_dir / "cpufreq"
        if not freq_dir.exists():
            return None
        attrs = (
            "scaling_driver",
            "scaling_governor",
            "scaling_cur_freq",
            "scaling_min_freq",
            "scaling_max_freq",
            "cpuinfo_cur_freq",
            "cpuinfo_min_freq",
            "cpuinfo_max_freq",
            "base_frequency",
            "bios_limit",
            "energy_performance_preference",
        )
        values: dict[str, Any] = {"cpu": parse_int(cpu_dir.name.removeprefix("cpu"))}
        for attr in attrs:
            raw = read_clean(freq_dir / attr)
            if raw is None:
                continue
            values[attr] = parse_int(raw) if raw.isdigit() else raw
        return values

    def collect_cpu_caches(self, cpu_dirs: list[Path]) -> list[dict[str, Any]]:
        seen: set[tuple[Any, ...]] = set()
        caches: list[dict[str, Any]] = []
        for cpu_dir in cpu_dirs:
            cpu_number = parse_int(cpu_dir.name.removeprefix("cpu"))
            cache_root = cpu_dir / "cache"
            if not cache_root.exists():
                continue
            for index_dir in sorted_paths(cache_root.glob("index*")):
                shared_cpu_list = read_clean(index_dir / "shared_cpu_list")
                entry = {
                    "first_seen_cpu": cpu_number,
                    "index": index_dir.name,
                    "level": read_clean(index_dir / "level"),
                    "type": read_clean(index_dir / "type"),
                    "size": read_clean(index_dir / "size"),
                    "shared_cpu_list": shared_cpu_list,
                    "shared_cpu_count": len(parse_cpu_list(shared_cpu_list)),
                    "coherency_line_size": read_int(index_dir / "coherency_line_size"),
                    "ways_of_associativity": read_int(
                        index_dir / "ways_of_associativity"
                    ),
                    "number_of_sets": read_int(index_dir / "number_of_sets"),
                    "physical_line_partition": read_int(
                        index_dir / "physical_line_partition"
                    ),
                }
                key = (
                    entry.get("level"),
                    entry.get("type"),
                    entry.get("size"),
                    entry.get("shared_cpu_list"),
                    entry.get("coherency_line_size"),
                    entry.get("ways_of_associativity"),
                    entry.get("number_of_sets"),
                )
                if key in seen:
                    continue
                seen.add(key)
                caches.append(entry)
        return caches

    def collect_numa(self) -> dict[str, Any]:
        node_root = self.path("/sys/devices/system/node")
        nodes: list[dict[str, Any]] = []
        if node_root.exists():
            for node_dir in sorted_paths(node_root.glob("node*")):
                node_id = parse_int(node_dir.name.removeprefix("node"))
                meminfo = self.parse_node_meminfo(node_dir / "meminfo")
                nodes.append(
                    {
                        "node": node_id,
                        "cpulist": read_clean(node_dir / "cpulist"),
                        "distance": read_clean(node_dir / "distance"),
                        "meminfo": meminfo,
                        "hugepages": self.collect_hugepages(node_dir / "hugepages"),
                    }
                )
        return {"nodes": nodes}

    def apply_test_numa(self, report: dict[str, Any], count: int) -> None:
        cpu = report.setdefault("cpu", {})
        numa = cpu.setdefault("numa", {})
        existing_nodes = numa.get("nodes") or []
        if existing_nodes:
            base = deepcopy(existing_nodes[0])
        else:
            cpu_sets = cpu.get("cpu_sets", {})
            memory = report.get("memory", {}).get("summary", {})
            base = {
                "node": 0,
                "cpulist": cpu_sets.get("online")
                or cpu_sets.get("present")
                or cpu_sets.get("possible"),
                "distance": "10",
                "meminfo": {"MemTotal": memory.get("total")},
                "hugepages": [],
            }
        synthetic_nodes: list[dict[str, Any]] = []
        for index in range(count):
            node = deepcopy(base)
            node["node"] = index
            node["synthetic_from_node"] = base.get("node", 0)
            node["distance"] = " ".join(
                "10" if peer == index else "20" for peer in range(count)
            )
            synthetic_nodes.append(node)
        numa["nodes"] = synthetic_nodes
        cpu.setdefault("summary", {})["numa_nodes"] = count

    def parse_node_meminfo(self, path: Path) -> dict[str, int]:
        text = read_text(path)
        if text is None:
            return {}
        result: dict[str, int] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            left, right = line.split(":", 1)
            key = left.split(maxsplit=2)[-1]
            parts = right.strip().split()
            if not parts:
                continue
            number = parse_int(parts[0])
            if number is None:
                continue
            unit = parts[1].lower() if len(parts) > 1 else ""
            result[key] = number * 1024 if unit == "kb" else number
        return result

    def collect_hugepages(self, huge_root: Path) -> list[dict[str, Any]]:
        if not huge_root.exists():
            return []
        pages: list[dict[str, Any]] = []
        for page_dir in sorted_paths(huge_root.iterdir()):
            if not page_dir.is_dir():
                continue
            pages.append(
                {
                    "size": page_dir.name.removeprefix("hugepages-"),
                    "free": read_int(page_dir / "free_hugepages"),
                    "total": read_int(page_dir / "nr_hugepages"),
                    "surplus": read_int(page_dir / "surplus_hugepages"),
                }
            )
        return pages

    def collect_memory(self) -> dict[str, Any]:
        meminfo = parse_meminfo(self.path("/proc/meminfo"))
        memory_root = self.path("/sys/devices/system/memory")
        block_size = read_first_line(memory_root / "block_size_bytes")
        block_size_bytes = parse_int(block_size, base=16) if block_size else None
        blocks: list[dict[str, Any]] = []
        if memory_root.exists():
            for block_dir in sorted_paths(memory_root.iterdir()):
                if not MEMORY_DIR_PATTERN.match(block_dir.name):
                    continue
                node = None
                for child in block_dir.iterdir():
                    if child.name.startswith("node"):
                        node = parse_int(child.name.removeprefix("node"))
                        break
                blocks.append(
                    {
                        "name": block_dir.name,
                        "block": parse_int(block_dir.name.removeprefix("memory")),
                        "state": read_clean(block_dir / "state"),
                        "online": truthy_sysfs(read_first_line(block_dir / "online")),
                        "removable": truthy_sysfs(
                            read_first_line(block_dir / "removable")
                        ),
                        "valid_zones": read_clean(block_dir / "valid_zones"),
                        "phys_index": read_clean(block_dir / "phys_index"),
                        "node": node,
                    }
                )
        states = Counter(block.get("state", "unknown") for block in blocks)
        return {
            "summary": {
                "total": meminfo.get("MemTotal"),
                "total_human": human_bytes(
                    meminfo.get("MemTotal")
                    if isinstance(meminfo.get("MemTotal"), int)
                    else None
                ),
                "available": meminfo.get("MemAvailable"),
                "swap_total": meminfo.get("SwapTotal"),
                "memory_block_size": block_size_bytes,
                "memory_blocks": len(blocks) or None,
                "memory_block_states": dict(states),
            },
            "meminfo": meminfo,
            "memory_blocks": blocks,
            "dmi_memory_devices": self.collect_dmi_memory_devices(),
            "edac": self.collect_edac(),
            "nvdimm": self.collect_nvdimm(),
        }

    def collect_dmi_memory_devices(self) -> list[dict[str, Any]]:
        root = self.path("/sys/firmware/dmi/entries")
        if not root.exists():
            return []
        devices: list[dict[str, Any]] = []
        for entry_dir in sorted_paths(root.glob("17-*")):
            raw = read_bytes(entry_dir / "raw", max_bytes=4096)
            if raw is None:
                continue
            device = self.parse_dmi_memory_device(raw, entry_dir)
            if device:
                devices.append(device)
        return devices

    def parse_dmi_memory_device(
        self, raw: bytes, entry_dir: Path
    ) -> dict[str, Any] | None:
        if len(raw) < 18 or raw[0] != 17:
            return None
        formatted_length = raw[1]
        if formatted_length < 18 or formatted_length > len(raw):
            return None
        strings = self.parse_dmi_strings(raw, formatted_length)

        def string_at(offset: int) -> str | None:
            if len(raw) <= offset:
                return None
            index = raw[offset]
            if index == 0 or index > len(strings):
                return None
            return strings[index - 1]

        size_field = read_le(raw, 0x0C, 2)
        extended_size = read_le(raw, 0x1C, 4)
        size_bytes = parse_dmi_memory_size(size_field, extended_size)
        total_width_bits = parse_dmi_memory_width(read_le(raw, 0x08, 2))
        data_width_bits = parse_dmi_memory_width(read_le(raw, 0x0A, 2))
        speed = dmi_nonzero(read_le(raw, 0x15, 2))
        configured_speed = dmi_nonzero(read_le(raw, 0x20, 2))
        form_factor_id = read_le(raw, 0x0E, 1)
        memory_type_id = read_le(raw, 0x12, 1)
        locator = clean_value(string_at(0x10))
        bank_locator = clean_value(string_at(0x11))
        return {
            "entry": entry_dir.name,
            "handle": f"0x{read_le(raw, 0x02, 2) or 0:04x}",
            "locator": locator,
            "bank_locator": bank_locator,
            "slot": join_nonempty(bank_locator, locator),
            "populated": size_field not in (None, 0),
            "size_bytes": size_bytes,
            "size_human": human_bytes(size_bytes),
            "total_width_bits": total_width_bits,
            "data_width_bits": data_width_bits,
            "ecc": is_dmi_memory_ecc(total_width_bits, data_width_bits),
            "form_factor": DMI_MEMORY_FORM_FACTORS.get(form_factor_id or 0),
            "memory_type": DMI_MEMORY_TYPES.get(memory_type_id or 0),
            "type_detail": read_le(raw, 0x13, 2),
            "speed_mt_s": speed,
            "configured_speed_mt_s": configured_speed,
            "manufacturer": clean_value(string_at(0x17)),
            "serial": clean_value(string_at(0x18)),
            "asset_tag": clean_value(string_at(0x19)),
            "part_number": clean_value(string_at(0x1A)),
            "rank": dmi_rank(read_le(raw, 0x1B, 1)),
            "sysfs_path": str(entry_dir),
        }

    def parse_dmi_strings(self, raw: bytes, formatted_length: int) -> list[str]:
        strings: list[str] = []
        position = formatted_length
        while position < len(raw) - 1:
            if raw[position] == 0 and raw[position + 1] == 0:
                break
            end = raw.find(b"\x00", position)
            if end < 0:
                break
            text = raw[position:end].decode("utf-8", errors="replace").strip()
            strings.append(text)
            position = end + 1
        return strings

    def collect_edac(self) -> list[dict[str, Any]]:
        root = self.path("/sys/devices/system/edac/mc")
        if not root.exists():
            return []
        controllers: list[dict[str, Any]] = []
        for mc_dir in sorted_paths(root.glob("mc*")):
            dimms: list[dict[str, Any]] = []
            dimm_dirs = [
                path
                for path in sorted_paths(mc_dir.iterdir())
                if path.is_dir()
                and (path.name.startswith("dimm") or path.name.startswith("rank"))
            ]
            for dimm_dir in dimm_dirs:
                dimms.append(
                    {
                        "name": dimm_dir.name,
                        "label": read_clean(dimm_dir / "dimm_label"),
                        "location": read_clean(dimm_dir / "dimm_location"),
                        "size_mb": read_int(dimm_dir / "size"),
                        "mem_type": read_clean(dimm_dir / "dimm_mem_type"),
                        "dev_type": read_clean(dimm_dir / "dimm_dev_type"),
                        "edac_mode": read_clean(dimm_dir / "dimm_edac_mode"),
                        "ce_count": read_int(dimm_dir / "dimm_ce_count"),
                        "ue_count": read_int(dimm_dir / "dimm_ue_count"),
                        "sysfs_path": str(dimm_dir),
                        "physical_path": readlink_target(dimm_dir),
                    }
                )
            controllers.append(
                {
                    "name": mc_dir.name,
                    "mc_name": read_clean(mc_dir / "mc_name"),
                    "size_mb": read_int(mc_dir / "size_mb"),
                    "ce_count": read_int(mc_dir / "ce_count"),
                    "ue_count": read_int(mc_dir / "ue_count"),
                    "seconds_since_reset": read_int(mc_dir / "seconds_since_reset"),
                    "dimms": dimms,
                    "sysfs_path": str(mc_dir),
                    "physical_path": readlink_target(mc_dir),
                }
            )
        return controllers

    def collect_nvdimm(self) -> list[dict[str, Any]]:
        root = self.path("/sys/bus/nd/devices")
        if not root.exists():
            return []
        devices: list[dict[str, Any]] = []
        for dev_dir in sorted_paths(root.iterdir()):
            devices.append(
                {
                    "name": dev_dir.name,
                    "type": readlink_name(dev_dir / "subsystem"),
                    "driver": readlink_name(dev_dir / "driver"),
                    "size": read_int(dev_dir / "size"),
                    "state": read_clean(dev_dir / "state"),
                    "modalias": read_clean(dev_dir / "modalias"),
                }
            )
        return devices

    def collect_pci(self) -> dict[str, Any]:
        root = self.path("/sys/bus/pci/devices")
        devices: list[dict[str, Any]] = []
        if root.exists():
            for dev_dir in sorted_paths(root.iterdir()):
                if not PCI_SLOT_PATTERN.match(dev_dir.name):
                    continue
                if self.is_sriov_vf_dir(dev_dir):
                    continue
                vendor_id = read_hex_id(dev_dir / "vendor")
                device_id = read_hex_id(dev_dir / "device")
                subsystem_vendor_id = read_hex_id(dev_dir / "subsystem_vendor")
                subsystem_device_id = read_hex_id(dev_dir / "subsystem_device")
                class_id_raw = read_clean(dev_dir / "class")
                class_id = (
                    class_id_raw[2:].lower()
                    if class_id_raw and class_id_raw.startswith("0x")
                    else class_id_raw
                )
                devices.append(
                    {
                        "slot": dev_dir.name,
                        "vendor_id": vendor_id,
                        "vendor_name": self.pci_ids.vendor_name(vendor_id),
                        "device_id": device_id,
                        "device_name": self.pci_ids.device_name(vendor_id, device_id),
                        "subsystem_vendor_id": subsystem_vendor_id,
                        "subsystem_vendor_name": self.pci_ids.vendor_name(
                            subsystem_vendor_id
                        ),
                        "subsystem_device_id": subsystem_device_id,
                        "class_id": class_id,
                        "class_name": pci_class_name(class_id),
                        "revision": read_hex_id(dev_dir / "revision", width=2),
                        "driver": readlink_name(dev_dir / "driver"),
                        "subsystem": readlink_name(dev_dir / "subsystem"),
                        "numa_node": read_int(dev_dir / "numa_node"),
                        "irq": read_int(dev_dir / "irq"),
                        "local_cpus": read_clean(dev_dir / "local_cpulist"),
                        "enable": read_int(dev_dir / "enable"),
                        "boot_vga": truthy_sysfs(read_first_line(dev_dir / "boot_vga")),
                        "d3cold_allowed": truthy_sysfs(
                            read_first_line(dev_dir / "d3cold_allowed")
                        ),
                        "msi_bus": truthy_sysfs(read_first_line(dev_dir / "msi_bus")),
                        "current_link_speed": read_clean(
                            dev_dir / "current_link_speed"
                        ),
                        "current_link_width": read_int(dev_dir / "current_link_width"),
                        "max_link_speed": read_clean(dev_dir / "max_link_speed"),
                        "max_link_width": read_int(dev_dir / "max_link_width"),
                        "modalias": read_clean(dev_dir / "modalias"),
                        "iommu_group": readlink_name(dev_dir / "iommu_group"),
                        "sysfs_path": str(dev_dir),
                        "physical_path": readlink_target(dev_dir),
                        "resources": self.collect_pci_resources(dev_dir / "resource"),
                    }
                )
        by_class = Counter(device.get("class_name", "Unknown") for device in devices)
        return {
            "summary": {
                "device_count": len(devices),
                "classes": dict(sorted(by_class.items())),
            },
            "devices": devices,
        }

    def collect_pci_resources(self, path: Path) -> list[dict[str, Any]]:
        text = read_text(path)
        if text is None:
            return []
        resources: list[dict[str, Any]] = []
        for index, line in enumerate(text.splitlines()):
            parts = line.split()
            if len(parts) < 3:
                continue
            start = parse_int(parts[0], base=16)
            end = parse_int(parts[1], base=16)
            flags = parse_int(parts[2], base=16)
            if start is None or end is None or flags is None:
                continue
            if start == 0 and end == 0:
                continue
            resources.append(
                {
                    "index": index,
                    "start": start,
                    "end": end,
                    "size": end - start + 1 if end >= start else 0,
                    "flags": flags,
                }
            )
        return resources

    def collect_usb(self) -> dict[str, Any]:
        root = self.path("/sys/bus/usb/devices")
        devices: list[dict[str, Any]] = []
        if root.exists():
            for dev_dir in sorted_paths(root.iterdir()):
                vendor_id = read_hex_id(dev_dir / "idVendor")
                product_id = read_hex_id(dev_dir / "idProduct")
                if vendor_id is None and product_id is None:
                    continue
                if self.exclude_usb_devices and not USB_ROOT_PATTERN.match(
                    dev_dir.name
                ):
                    continue
                class_id = read_hex_id(dev_dir / "bDeviceClass", width=2)
                class_name = usb_class_name(class_id)
                max_children = read_int(dev_dir / "maxchild")
                devices.append(
                    {
                        "name": dev_dir.name,
                        "busnum": read_int(dev_dir / "busnum"),
                        "devnum": read_int(dev_dir / "devnum"),
                        "devpath": read_clean(dev_dir / "devpath"),
                        "vendor_id": vendor_id,
                        "vendor_name": self.usb_ids.vendor_name(vendor_id),
                        "product_id": product_id,
                        "product_name_from_ids": self.usb_ids.device_name(
                            vendor_id, product_id
                        ),
                        "manufacturer": read_clean(dev_dir / "manufacturer"),
                        "product": read_clean(dev_dir / "product"),
                        "serial": read_clean(dev_dir / "serial"),
                        "device_class": class_id,
                        "device_class_name": class_name,
                        "device_subclass": read_hex_id(
                            dev_dir / "bDeviceSubClass", width=2
                        ),
                        "device_protocol": read_hex_id(
                            dev_dir / "bDeviceProtocol", width=2
                        ),
                        "usb_version": read_clean(dev_dir / "version"),
                        "speed_mbps": read_clean(dev_dir / "speed"),
                        "max_power": read_clean(dev_dir / "bMaxPower"),
                        "max_children": max_children,
                        "authorized": truthy_sysfs(
                            read_first_line(dev_dir / "authorized")
                        ),
                        "removable": read_clean(dev_dir / "removable"),
                        "configuration": read_clean(dev_dir / "configuration"),
                        "driver": readlink_name(dev_dir / "driver"),
                        "interfaces": self.collect_usb_interfaces(dev_dir),
                        "sysfs_path": str(dev_dir),
                        "physical_path": readlink_target(dev_dir),
                    }
                )
        by_class = Counter(
            device.get("device_class_name", "Unknown") for device in devices
        )
        return {
            "summary": {
                "device_count": len(devices),
                "classes": dict(sorted(by_class.items())),
            },
            "devices": devices,
        }

    def collect_usb_interfaces(self, dev_dir: Path) -> list[dict[str, Any]]:
        interfaces: list[dict[str, Any]] = []
        prefix = f"{dev_dir.name}:"
        for interface_dir in sorted_paths(dev_dir.iterdir()):
            if not interface_dir.name.startswith(prefix):
                continue
            class_id = read_hex_id(interface_dir / "bInterfaceClass", width=2)
            interfaces.append(
                {
                    "name": interface_dir.name,
                    "interface": read_clean(interface_dir / "interface"),
                    "class": class_id,
                    "class_name": usb_class_name(class_id),
                    "subclass": read_hex_id(
                        interface_dir / "bInterfaceSubClass", width=2
                    ),
                    "protocol": read_hex_id(
                        interface_dir / "bInterfaceProtocol", width=2
                    ),
                    "driver": readlink_name(interface_dir / "driver"),
                }
            )
        return interfaces

    def collect_storage(self) -> dict[str, Any]:
        root = self.path("/sys/block")
        devices: list[dict[str, Any]] = []
        if root.exists():
            for block_dir in sorted_paths(root.iterdir()):
                device = self.collect_block_device(block_dir)
                if device.pop("_is_virtual", False):
                    continue
                devices.append(device)
        return {
            "summary": {
                "block_device_count": len(devices),
                "total_physical_capacity": sum(
                    device.get("size_bytes") or 0 for device in devices
                ),
                "total_physical_capacity_human": human_bytes(
                    sum(device.get("size_bytes") or 0 for device in devices)
                ),
            },
            "block_devices": devices,
            "nvme_controllers": self.collect_nvme(),
        }

    def collect_block_device(self, block_dir: Path) -> dict[str, Any]:
        queue_dir = block_dir / "queue"
        device_dir = block_dir / "device"
        sectors = read_int(block_dir / "size")
        size_bytes = sectors * 512 if sectors is not None else None
        subsystem = readlink_name(block_dir / "subsystem")
        name = block_dir.name
        is_virtual = (
            name.startswith(("loop", "ram", "zram"))
            or name.startswith("dm-")
            or not device_dir.exists()
        )
        partitions: list[dict[str, Any]] = []
        for child in sorted_paths(block_dir.iterdir()):
            if not (child / "partition").exists():
                continue
            partition_sectors = read_int(child / "size")
            partitions.append(
                {
                    "name": child.name,
                    "partition": read_int(child / "partition"),
                    "start": read_int(child / "start"),
                    "size_bytes": (
                        partition_sectors * 512
                        if partition_sectors is not None
                        else None
                    ),
                    "alignment_offset": read_int(child / "alignment_offset"),
                    "discard_alignment": read_int(child / "discard_alignment"),
                }
            )
        queue_attrs = (
            "logical_block_size",
            "physical_block_size",
            "minimum_io_size",
            "optimal_io_size",
            "rotational",
            "removable",
            "read_ahead_kb",
            "scheduler",
            "write_cache",
            "zoned",
            "nr_requests",
            "max_sectors_kb",
            "discard_max_bytes",
            "discard_granularity",
        )
        queue = {
            attr: self.parse_queue_attr(read_first_line(queue_dir / attr))
            for attr in queue_attrs
            if (queue_dir / attr).exists()
        }
        return {
            "name": name,
            "major_minor": read_clean(block_dir / "dev"),
            "size_bytes": size_bytes,
            "size_human": human_bytes(size_bytes),
            "hidden": truthy_sysfs(read_first_line(block_dir / "hidden")),
            "removable": truthy_sysfs(read_first_line(block_dir / "removable")),
            "ro": truthy_sysfs(read_first_line(block_dir / "ro")),
            "_is_virtual": is_virtual,
            "subsystem": subsystem,
            "driver": readlink_name(device_dir / "driver"),
            "device": {
                "vendor": read_clean(device_dir / "vendor"),
                "model": read_clean(device_dir / "model"),
                "rev": read_clean(device_dir / "rev"),
                "serial": read_clean(device_dir / "serial"),
                "wwid": read_clean(device_dir / "wwid"),
                "state": read_clean(device_dir / "state"),
                "timeout": read_int(device_dir / "timeout"),
            },
            "dm": {
                "name": read_clean(block_dir / "dm/name"),
                "uuid": read_clean(block_dir / "dm/uuid"),
                "suspended": read_int(block_dir / "dm/suspended"),
            },
            "queue": queue,
            "holders": (
                [path.name for path in sorted_paths((block_dir / "holders").iterdir())]
                if (block_dir / "holders").exists()
                else []
            ),
            "slaves": (
                [path.name for path in sorted_paths((block_dir / "slaves").iterdir())]
                if (block_dir / "slaves").exists()
                else []
            ),
            "partitions": partitions,
            "sysfs_path": str(block_dir),
            "physical_path": readlink_target(block_dir),
        }

    def parse_queue_attr(self, value: str | None) -> int | str | None:
        if value is None:
            return None
        stripped = value.strip()
        number = parse_int(stripped)
        return number if number is not None else stripped

    def collect_nvme(self) -> list[dict[str, Any]]:
        root = self.path("/sys/class/nvme")
        if not root.exists():
            return []
        controllers: list[dict[str, Any]] = []
        for ctrl_dir in sorted_paths(root.glob("nvme*")):
            path = readlink_target(ctrl_dir)
            if not self.should_output_device_path(path):
                continue
            controllers.append(
                {
                    "name": ctrl_dir.name,
                    "model": read_clean(ctrl_dir / "model"),
                    "serial": read_clean(ctrl_dir / "serial"),
                    "firmware_rev": read_clean(ctrl_dir / "firmware_rev"),
                    "state": read_clean(ctrl_dir / "state"),
                    "transport": read_clean(ctrl_dir / "transport"),
                    "address": read_clean(ctrl_dir / "address"),
                    "cntlid": read_clean(ctrl_dir / "cntlid"),
                    "subsysnqn": read_clean(ctrl_dir / "subsysnqn"),
                    "driver": readlink_name(ctrl_dir / "device/driver"),
                    "physical_path": path,
                }
            )
        return controllers

    def collect_network(self) -> dict[str, Any]:
        root = self.path("/sys/class/net")
        interfaces: list[dict[str, Any]] = []
        infiniband_ports = self.collect_infiniband_ports()
        wireless_capabilities = self.collect_wireless_capabilities()
        ethtool = self.open_ethtool()
        if root.exists():
            try:
                for if_dir in sorted_paths(root.iterdir()):
                    device_path = readlink_target(if_dir / "device")
                    if not self.should_output_device_path(device_path):
                        continue
                    arphrd = read_int(if_dir / "type")
                    ethtool_data = self.collect_network_ethtool_info(
                        ethtool, if_dir.name
                    )
                    speed_mbps = read_int(if_dir / "speed")
                    if speed_mbps is None:
                        speed_mbps = ethtool_data.get("negotiated_speed_mbps")
                    duplex = read_clean(if_dir / "duplex") or ethtool_data.get("duplex")
                    is_wireless = (if_dir / "wireless").exists()
                    interfaces.append(
                        {
                            "name": if_dir.name,
                            "ifindex": read_int(if_dir / "ifindex"),
                            "type": arphrd,
                            "kind": self.network_kind(arphrd),
                            "mac_address": read_clean(if_dir / "address"),
                            "operstate": read_clean(if_dir / "operstate"),
                            "carrier": truthy_sysfs(
                                read_first_line(if_dir / "carrier")
                            ),
                            "mtu": read_int(if_dir / "mtu"),
                            "speed_mbps": speed_mbps,
                            "duplex": duplex,
                            "broadcast": read_clean(if_dir / "broadcast"),
                            "addr_assign_type": read_int(if_dir / "addr_assign_type"),
                            "phys_port_name": read_clean(if_dir / "phys_port_name"),
                            "phys_switch_id": read_clean(if_dir / "phys_switch_id"),
                            "dev_port": read_int(if_dir / "dev_port"),
                            "is_wireless": is_wireless,
                            "wireless": (
                                wireless_capabilities.get(if_dir.name)
                                if is_wireless
                                else None
                            ),
                            "driver": readlink_name(if_dir / "device/driver"),
                            "device_path": device_path,
                            "subsystem": readlink_name(if_dir / "device/subsystem"),
                            **ethtool_data,
                        }
                    )
            finally:
                if ethtool is not None:
                    close = getattr(ethtool, "close", None)
                    if callable(close):
                        close()
        return {
            "summary": {
                "interface_count": len(interfaces),
                "wireless_interface_count": sum(
                    1 for item in interfaces if item.get("is_wireless")
                ),
                "infiniband_port_count": sum(
                    1
                    for port in infiniband_ports
                    if str(port.get("link_layer") or "").casefold() == "infiniband"
                ),
            },
            "interfaces": interfaces,
            "infiniband_ports": infiniband_ports,
        }

    def collect_wireless_capabilities(self) -> dict[str, dict[str, Any]]:
        if self.root != Path("/"):
            return {}
        interface_wiphys = collect_wireless_interface_wiphys()
        if not interface_wiphys:
            return {}
        wiphys = collect_nl80211_wiphy_capabilities()
        result: dict[str, dict[str, Any]] = {}
        for ifname, interface in interface_wiphys.items():
            wiphy_name = interface.get("wiphy")
            if not wiphy_name:
                continue
            capability = deepcopy(wiphys.get(str(wiphy_name)) or {})
            if not capability:
                continue
            capability.update(
                {
                    "wiphy": wiphy_name,
                    "ifindex": interface.get("ifindex"),
                    "wireless_mac": interface.get("mac_address"),
                }
            )
            result[ifname] = capability
        return result

    def collect_infiniband_ports(self) -> list[dict[str, Any]]:
        root = self.path("/sys/class/infiniband")
        if not root.exists():
            return []
        ports: list[dict[str, Any]] = []
        for hca_dir in sorted_paths(root.iterdir()):
            device_path = readlink_target(hca_dir / "device")
            if not self.should_output_device_path(device_path):
                continue
            ports_dir = hca_dir / "ports"
            if not ports_dir.exists():
                continue
            hca_info = {
                "hca": hca_dir.name,
                "node_guid": read_clean(hca_dir / "node_guid"),
                "sys_image_guid": read_clean(hca_dir / "sys_image_guid"),
                "node_type": read_clean(hca_dir / "node_type"),
                "node_desc": read_clean(hca_dir / "node_desc"),
                "hca_type": read_clean(hca_dir / "hca_type"),
                "board_id": read_clean(hca_dir / "board_id"),
                "fw_ver": read_clean(hca_dir / "fw_ver"),
                "hw_rev": read_clean(hca_dir / "hw_rev"),
                "device_path": device_path,
            }
            for port_dir in sorted_paths(ports_dir.iterdir()):
                if not port_dir.is_dir():
                    continue
                ports.append(
                    {
                        **hca_info,
                        "port": port_dir.name,
                        "link_layer": read_clean(port_dir / "link_layer"),
                        "state": read_clean(port_dir / "state"),
                        "physical_state": read_clean(port_dir / "phys_state"),
                        "rate": read_clean(port_dir / "rate"),
                        "lid": read_clean(port_dir / "lid"),
                        "lid_mask_count": read_clean(port_dir / "lid_mask_count"),
                        "sm_lid": read_clean(port_dir / "sm_lid"),
                        "sm_sl": read_clean(port_dir / "sm_sl"),
                        "cap_mask": read_clean(port_dir / "cap_mask"),
                        "physical_path": readlink_target(port_dir),
                    }
                )
        return ports

    def collect_bluetooth(self) -> dict[str, Any]:
        root = self.path("/sys/class/bluetooth")
        adapters: list[dict[str, Any]] = []
        mgmt_info = self.collect_bluetooth_mgmt_info()
        if root.exists():
            for hci_dir in sorted_paths(root.glob("hci*")):
                match = BLUETOOTH_HCI_NAME_PATTERN.match(hci_dir.name)
                if not match:
                    continue
                index = int(match.group(1))
                physical_path = readlink_target(hci_dir)
                device_path = readlink_target(hci_dir / "device")
                if not self.should_output_device_path(device_path or physical_path):
                    continue
                controller_info = mgmt_info.get(index, {})
                adapters.append(
                    {
                        "name": hci_dir.name,
                        "index": index,
                        "address": controller_info.get("address"),
                        "bluetooth_version": controller_info.get("bluetooth_version"),
                        "bluetooth_version_code": controller_info.get(
                            "bluetooth_version_code"
                        ),
                        "manufacturer_id": controller_info.get("manufacturer_id"),
                        "supported_settings": controller_info.get("supported_settings"),
                        "current_settings": controller_info.get("current_settings"),
                        "device_class": controller_info.get("device_class"),
                        "controller_name": controller_info.get("name"),
                        "short_name": controller_info.get("short_name"),
                        "driver": readlink_name(hci_dir / "device/driver"),
                        "device_path": device_path,
                        "physical_path": physical_path,
                    }
                )
        return {
            "summary": {"adapter_count": len(adapters)},
            "adapters": adapters,
        }

    def collect_bluetooth_mgmt_info(self) -> dict[int, dict[str, Any]]:
        if self.root != Path("/"):
            return {}
        try:
            sock = open_bluetooth_mgmt_socket()
        except OSError:
            return {}
        try:
            mgmt_version: dict[str, Any] = {}
            status, _, payload = bluetooth_mgmt_command(sock, MGMT_OP_READ_VERSION)
            if status == 0 and len(payload) >= 3:
                mgmt_version = {
                    "mgmt_version": payload[0],
                    "mgmt_revision": struct.unpack_from("<H", payload, 1)[0],
                }

            status, _, payload = bluetooth_mgmt_command(sock, MGMT_OP_READ_INDEX_LIST)
            if status != 0 or len(payload) < 2:
                return {}
            count = struct.unpack_from("<H", payload)[0]
            indexes = [
                struct.unpack_from("<H", payload, 2 + index * 2)[0]
                for index in range(count)
                if len(payload) >= 4 + index * 2
            ]

            controllers: dict[int, dict[str, Any]] = {}
            for index in indexes:
                status, _, payload = bluetooth_mgmt_command(
                    sock, MGMT_OP_READ_INFO, index
                )
                if status != 0:
                    continue
                controller = parse_bluetooth_mgmt_controller_info(payload)
                controller.update(mgmt_version)
                controllers[index] = controller
            return controllers
        except (OSError, TimeoutError, struct.error):
            return {}
        finally:
            sock.close()

    def open_ethtool(self) -> Any | None:
        try:
            from pyroute2 import Ethtool
        except Exception:
            return None
        try:
            return Ethtool()
        except Exception:
            return None

    def collect_network_ethtool_info(
        self, ethtool: Any | None, ifname: str
    ) -> dict[str, Any]:
        if ethtool is None:
            return {}
        result: dict[str, Any] = {}
        try:
            mode = ethtool.get_link_mode(ifname)
        except Exception:
            mode = None
        if mode is not None:
            result["negotiated_speed_mbps"] = getattr(mode, "speed", None)
            result["duplex"] = getattr(mode, "duplex", None)
            result["autoneg"] = getattr(mode, "autoneg", None)
            result["supported_ports"] = list(
                getattr(mode, "supported_ports", None) or []
            )
            result["supported_modes"] = list(
                getattr(mode, "supported_modes", None) or []
            )
        try:
            link_info = ethtool.get_link_info(ifname)
        except Exception:
            link_info = None
        if link_info is not None:
            result["port_type"] = getattr(link_info, "port", None)
            result["phy_address"] = getattr(link_info, "phyaddr", None)
            result["transceiver"] = getattr(link_info, "transceiver", None)
        return result

    def network_kind(self, arphrd: int | None) -> str | None:
        names = {
            1: "ethernet",
            24: "ieee1394",
            32: "infiniband",
            512: "ppp",
            772: "loopback",
            776: "sit",
            778: "ipip",
            783: "irda",
            801: "ieee802.11",
        }
        if arphrd is None:
            return None
        return names.get(arphrd, f"arphrd-{arphrd}")

    def collect_graphics(self) -> dict[str, Any]:
        drm_root = self.path("/sys/class/drm")
        devices: list[dict[str, Any]] = []
        connectors: list[dict[str, Any]] = []
        if drm_root.exists():
            for entry in sorted_paths(drm_root.iterdir()):
                if entry.name == "version":
                    continue
                if "-" in entry.name:
                    path = readlink_target(entry)
                    device_path = readlink_target(entry / "device")
                    if not self.should_output_device_path(device_path):
                        continue
                    modes_text = read_text(entry / "modes")
                    connector_id = read_int(entry / "connector_id")
                    edid = self.parse_edid(read_bytes(entry / "edid", max_bytes=32768))
                    runtime = self.collect_drm_connector_runtime(
                        entry.name, connector_id
                    )
                    connectors.append(
                        {
                            "name": entry.name,
                            "connector_id": connector_id,
                            "status": read_clean(entry / "status"),
                            "enabled": read_clean(entry / "enabled"),
                            "dpms": read_clean(entry / "dpms"),
                            "modes": modes_text.splitlines() if modes_text else [],
                            "edid": edid,
                            "runtime": runtime,
                            "device_path": device_path,
                            "sysfs_path": str(entry),
                            "physical_path": path,
                        }
                    )
                elif re.match(r"card\d+$", entry.name):
                    path = readlink_target(entry)
                    device_path = readlink_target(entry / "device")
                    if not self.should_output_device_path(device_path):
                        continue
                    devices.append(
                        {
                            "name": entry.name,
                            "driver": readlink_name(entry / "device/driver"),
                            "device_path": device_path,
                            "dev": read_clean(entry / "dev"),
                            "sysfs_path": str(entry),
                            "physical_path": path,
                        }
                    )
        return {
            "summary": {
                "drm_device_count": len(devices),
                "connector_count": len(connectors),
                "connected_connector_count": sum(
                    1 for item in connectors if item.get("status") == "connected"
                ),
            },
            "drm_devices": devices,
            "connectors": connectors,
        }

    def collect_drm_connector_runtime(
        self, connector_name: str, connector_id: int | None
    ) -> dict[str, Any]:
        if connector_id is None:
            return {}
        match = re.match(r"^(card\d+)-", connector_name)
        if not match:
            return {}
        card_path = self.path("/dev/dri") / match.group(1)
        try:
            fd = os.open(card_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            return {}
        try:
            connector, modes, props = drm_get_connector(fd, connector_id)
            result: dict[str, Any] = {
                "connector_id": connector_id,
                "modes": [format_drm_mode(mode) for mode in modes],
            }
            if connector.mm_width and connector.mm_height:
                result["physical_size"] = (
                    f"{connector.mm_width} x {connector.mm_height} mm"
                )
            current_mode = drm_current_mode(fd, connector.encoder_id)
            if current_mode:
                result["current_mode"] = current_mode
            simple_props = {name: value for name, value in props.items()}
            result["properties"] = simple_props
            if "max bpc" in simple_props:
                result["max_bpc"] = int(simple_props["max bpc"])
            if "vrr_capable" in simple_props:
                result["vrr_capable"] = bool(simple_props["vrr_capable"])
            colorspace = simple_props.get("Colorspace")
            if isinstance(colorspace, str):
                result["colorspace"] = colorspace
            return result
        except OSError:
            return {}
        finally:
            os.close(fd)

    def parse_edid(self, edid: bytes | None) -> dict[str, Any]:
        if not edid or len(edid) < 128:
            return {}
        base = edid[:128]
        if base[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
            return {}
        manufacturer_id = edid_manufacturer_id(base[8], base[9])
        product_code = int.from_bytes(base[10:12], "little")
        serial_number = int.from_bytes(base[12:16], "little")
        descriptors = parse_edid_descriptors(base)
        display_name = descriptors.get("display_name")
        text = descriptors.get("text")
        serial_text = descriptors.get("serial")
        preferred_mode = parse_edid_preferred_mode(base)
        width_cm = base[21] or None
        height_cm = base[22] or None
        year = 1990 + base[17] if base[17] else None
        week = base[16] if 1 <= base[16] <= 54 else None
        return {
            "manufacturer_id": manufacturer_id,
            "manufacturer_name": self.pnp_ids.vendor_name(manufacturer_id),
            "product_code": f"0x{product_code:04x}",
            "serial_number": serial_text
            or (str(serial_number) if serial_number not in (0, 0xFFFFFFFF) else None),
            "display_name": display_name,
            "text": text,
            "preferred_mode": preferred_mode,
            "detailed_modes": parse_edid_detailed_modes(edid),
            "refresh_range": parse_edid_refresh_range(base),
            **parse_edid_hdr_static_metadata(edid),
            "physical_size": (
                f"{width_cm} x {height_cm} cm" if width_cm and height_cm else None
            ),
            "manufacture_week": week,
            "manufacture_year": year,
            "edid_version": f"{base[18]}.{base[19]}",
            "extension_blocks": base[126],
            "checksum_valid": sum(base) % 256 == 0,
        }

    def collect_sound(self) -> dict[str, Any]:
        root = self.path("/sys/class/sound")
        cards: list[dict[str, Any]] = []
        ports: list[dict[str, Any]] = []
        if root.exists():
            for card_dir in sorted_paths(root.glob("card*")):
                if not re.match(r"card\d+$", card_dir.name):
                    continue
                path = readlink_target(card_dir)
                device_path = readlink_target(card_dir / "device")
                if not self.should_output_device_path(device_path):
                    continue
                number = read_int(card_dir / "number")
                card_ports = self.collect_sound_card_ports(number, path, device_path)
                ports.extend(card_ports)
                cards.append(
                    {
                        "name": card_dir.name,
                        "id": read_clean(card_dir / "id"),
                        "number": number,
                        "driver": readlink_name(card_dir / "device/driver"),
                        "device_path": device_path,
                        "sysfs_path": str(card_dir),
                        "physical_path": path,
                        "ports": card_ports,
                    }
                )
        return {
            "summary": {
                "card_count": len(cards),
                "audio_port_count": len(ports),
                "connected_audio_device_count": sum(
                    len(port.get("connected_devices") or []) for port in ports
                ),
            },
            "cards": cards,
            "ports": ports,
        }

    def collect_sound_card_ports(
        self,
        card_number: int | None,
        card_path: str | None,
        device_path: str | None,
    ) -> list[dict[str, Any]]:
        if card_number is None:
            return []
        proc_card = self.path(f"/proc/asound/card{card_number}")
        if not proc_card.exists():
            return []
        ports: list[dict[str, Any]] = []
        ports.extend(
            self.collect_hda_audio_ports(proc_card, card_number, card_path, device_path)
        )
        ports.extend(
            self.collect_usb_audio_stream_ports(
                proc_card, card_number, card_path, device_path
            )
        )
        return ports

    def collect_hda_audio_ports(
        self,
        proc_card: Path,
        card_number: int,
        card_path: str | None,
        device_path: str | None,
    ) -> list[dict[str, Any]]:
        ports: list[dict[str, Any]] = []
        elds_by_pin = collect_hda_elds_by_pin(proc_card)
        jack_states = self.collect_hda_jack_states(card_number)
        for codec_path in sorted_paths(proc_card.glob("codec#*")):
            text = read_text(codec_path, max_bytes=1_048_576)
            if not text:
                continue
            codec_index = codec_path.name.split("#", 1)[-1]
            for pin in parse_hda_codec_pins(text):
                if not should_show_hda_audio_pin(pin):
                    continue
                pin_id = normalize_hda_nid(pin.get("node_id"))
                eld = select_hda_pin_eld(elds_by_pin.get(pin_id) or [])
                port = hda_audio_port_from_pin(pin, eld)
                if not port:
                    continue
                jack = select_hda_jack_for_pin(pin, jack_states)
                if jack:
                    port["jack"] = jack
                    connected = hda_analog_connected_audio_device(pin, jack)
                    if connected:
                        port.setdefault("connected_devices", []).append(connected)
                ports.append(
                    {
                        **port,
                        "id": f"hda:{card_number}:{codec_index}:{pin_id}",
                        "card": card_number,
                        "codec": codec_index,
                        "codec_name": pin.get("codec_name"),
                        "codec_address": pin.get("codec_address"),
                        "address": pin_id,
                        "physical_path": card_path,
                        "device_path": device_path,
                        "source": str(codec_path),
                        "node_kind": "audio-port",
                    }
                )
        return ports

    def collect_hda_jack_states(self, card_number: int) -> list[dict[str, Any]]:
        root = self.path("/sys/class/input")
        if not root.exists():
            return []
        jacks: list[dict[str, Any]] = []
        card_marker = f"/sound/card{card_number}/"
        card_suffix = f"/sound/card{card_number}"
        for input_dir in sorted_paths(root.glob("input*")):
            input_path = readlink_target(input_dir)
            device_path = readlink_target(input_dir / "device")
            if not input_path or (
                card_marker not in input_path and not input_path.endswith(card_suffix)
            ):
                continue
            name = read_clean(input_dir / "name")
            supported_mask = parse_input_switch_mask(
                read_clean(input_dir / "capabilities/sw")
            )
            if not supported_mask:
                continue
            event_name = first_input_event_name(input_dir)
            state_mask = (
                self.read_input_switch_state(event_name) if event_name else None
            )
            supported_switches = input_switch_names(supported_mask)
            active_switches = input_switch_names(state_mask or 0)
            jacks.append(
                {
                    "name": name,
                    "sysfs_name": input_dir.name,
                    "event": event_name,
                    "phys": read_clean(input_dir / "phys"),
                    "supported_switch_mask": supported_mask,
                    "state_switch_mask": state_mask,
                    "supported_switches": supported_switches,
                    "active_switches": active_switches,
                    "inserted": bool(state_mask and state_mask & supported_mask),
                    "device_path": device_path,
                    "physical_path": input_path,
                }
            )
        return jacks

    def read_input_switch_state(self, event_name: str) -> int | None:
        event_path = self.path("/dev/input") / event_name
        try:
            fd = os.open(event_path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            data = bytearray(32)
            request = EVIOCGSW_BASE | (len(data) << 16)
            fcntl.ioctl(fd, request, data, True)
            return int.from_bytes(data, "little")
        except OSError:
            return None
        finally:
            os.close(fd)

    def collect_usb_audio_stream_ports(
        self,
        proc_card: Path,
        card_number: int,
        card_path: str | None,
        device_path: str | None,
    ) -> list[dict[str, Any]]:
        ports: list[dict[str, Any]] = []
        for stream_path in sorted_paths(proc_card.glob("stream*")):
            text = read_text(stream_path, max_bytes=1_048_576)
            if not text:
                continue
            stream_index = stream_path.name.removeprefix("stream") or "0"
            for stream_port in parse_usb_audio_stream_ports(text):
                endpoint = stream_port.get("endpoint_address") or "endpoint"
                direction = stream_port.get("direction") or "stream"
                interface = stream_port.get("interface")
                ports.append(
                    {
                        **stream_port,
                        "id": f"usb-audio:{card_number}:{stream_index}:{direction}:{interface}:{endpoint}",
                        "card": card_number,
                        "stream": stream_index,
                        "address": endpoint,
                        "label": usb_audio_stream_port_label(stream_port),
                        "edge_label": "USB Audio",
                        "physical_path": card_path,
                        "device_path": device_path,
                        "source": str(stream_path),
                        "node_kind": "audio-stream-port",
                    }
                )
        return ports

    def collect_input(self) -> dict[str, Any]:
        root = self.path("/sys/class/input")
        devices: list[dict[str, Any]] = []
        if root.exists():
            for input_dir in sorted_paths(root.glob("input*")):
                device_path = readlink_target(input_dir / "device")
                if not self.should_output_device_path(device_path):
                    continue
                devices.append(
                    {
                        "name": read_clean(input_dir / "name"),
                        "sysfs_name": input_dir.name,
                        "phys": read_clean(input_dir / "phys"),
                        "uniq": read_clean(input_dir / "uniq"),
                        "properties": read_clean(input_dir / "properties"),
                        "id": {
                            "bustype": read_hex_id(input_dir / "id/bustype", width=4),
                            "vendor": read_hex_id(input_dir / "id/vendor", width=4),
                            "product": read_hex_id(input_dir / "id/product", width=4),
                            "version": read_hex_id(input_dir / "id/version", width=4),
                        },
                        "capabilities": {
                            "ev": read_clean(input_dir / "capabilities/ev"),
                            "key": read_clean(input_dir / "capabilities/key"),
                            "rel": read_clean(input_dir / "capabilities/rel"),
                            "abs": read_clean(input_dir / "capabilities/abs"),
                            "msc": read_clean(input_dir / "capabilities/msc"),
                            "sw": read_clean(input_dir / "capabilities/sw"),
                        },
                        "driver": readlink_name(input_dir / "device/driver"),
                        "device_path": device_path,
                    }
                )
        return {
            "summary": {"device_count": len(devices)},
            "devices": devices,
        }

    def collect_power(self) -> dict[str, Any]:
        root = self.path("/sys/class/power_supply")
        supplies: list[dict[str, Any]] = []
        attrs = (
            "type",
            "scope",
            "status",
            "present",
            "online",
            "manufacturer",
            "model_name",
            "serial_number",
            "technology",
            "capacity",
            "capacity_level",
            "energy_full",
            "energy_full_design",
            "energy_now",
            "charge_full",
            "charge_full_design",
            "charge_now",
            "power_now",
            "current_now",
            "voltage_now",
            "cycle_count",
            "health",
        )
        if root.exists():
            for supply_dir in sorted_paths(root.iterdir()):
                values: dict[str, Any] = {"name": supply_dir.name}
                for attr in attrs:
                    raw = read_clean(supply_dir / attr)
                    if raw is None:
                        continue
                    values[attr] = parse_int(raw) if raw.isdigit() else raw
                supplies.append(values)
        return {
            "summary": {
                "supply_count": len(supplies),
                "battery_count": sum(
                    1
                    for item in supplies
                    if str(item.get("type", "")).lower() == "battery"
                ),
            },
            "supplies": supplies,
        }

    def collect_thermal(self) -> dict[str, Any]:
        root = self.path("/sys/class/thermal")
        zones: list[dict[str, Any]] = []
        cooling_devices: list[dict[str, Any]] = []
        if root.exists():
            for zone_dir in sorted_paths(root.glob("thermal_zone*")):
                zones.append(
                    {
                        "name": zone_dir.name,
                        "type": read_clean(zone_dir / "type"),
                        "temp_millicelsius": read_int(zone_dir / "temp"),
                        "mode": read_clean(zone_dir / "mode"),
                        "policy": read_clean(zone_dir / "policy"),
                        "trips": self.collect_thermal_trips(zone_dir),
                    }
                )
            for cooling_dir in sorted_paths(root.glob("cooling_device*")):
                cooling_devices.append(
                    {
                        "name": cooling_dir.name,
                        "type": read_clean(cooling_dir / "type"),
                        "cur_state": read_int(cooling_dir / "cur_state"),
                        "max_state": read_int(cooling_dir / "max_state"),
                        "stats": {
                            "total_trans": read_int(cooling_dir / "stats/total_trans"),
                        },
                    }
                )
        return {
            "summary": {
                "thermal_zone_count": len(zones),
                "cooling_device_count": len(cooling_devices),
            },
            "zones": zones,
            "cooling_devices": cooling_devices,
        }

    def collect_thermal_trips(self, zone_dir: Path) -> list[dict[str, Any]]:
        trips: list[dict[str, Any]] = []
        trip_indexes: set[int] = set()
        for path in zone_dir.glob("trip_point_*_temp"):
            match = re.match(r"trip_point_(\d+)_temp", path.name)
            if match:
                trip_indexes.add(int(match.group(1)))
        for index in sorted(trip_indexes):
            trips.append(
                {
                    "index": index,
                    "type": read_clean(zone_dir / f"trip_point_{index}_type"),
                    "temp_millicelsius": read_int(
                        zone_dir / f"trip_point_{index}_temp"
                    ),
                    "hyst_millicelsius": read_int(
                        zone_dir / f"trip_point_{index}_hyst"
                    ),
                }
            )
        return trips

    def collect_hwmon(self) -> dict[str, Any]:
        root = self.path("/sys/class/hwmon")
        devices: list[dict[str, Any]] = []
        if root.exists():
            for hwmon_dir in sorted_paths(root.glob("hwmon*")):
                device_path = readlink_target(hwmon_dir / "device")
                if not self.should_output_device_path(device_path):
                    continue
                devices.append(
                    {
                        "name": read_clean(hwmon_dir / "name"),
                        "sysfs_name": hwmon_dir.name,
                        "driver": readlink_name(hwmon_dir / "device/driver"),
                        "device_path": device_path,
                        "channels": self.collect_hwmon_channels(hwmon_dir),
                    }
                )
        return {
            "summary": {"device_count": len(devices)},
            "devices": devices,
        }

    def collect_hwmon_channels(self, hwmon_dir: Path) -> dict[str, dict[str, str]]:
        channels: dict[str, dict[str, str]] = defaultdict(dict)
        pattern = re.compile(
            r"^(temp|fan|in|curr|power|energy|humidity|pwm)(\d+)(?:_(.+))?$"
        )
        for attr_path in sorted_paths(hwmon_dir.iterdir()):
            if not attr_path.is_file():
                continue
            match = pattern.match(attr_path.name)
            if not match:
                continue
            kind, index, attr = match.groups()
            key = f"{kind}{index}"
            channels[key][attr or "value"] = read_first_line(attr_path) or ""
        return dict(channels)

    def collect_buses(self) -> dict[str, Any]:
        return {
            "i2c": self.collect_simple_bus("i2c"),
            "spi": self.collect_simple_bus("spi"),
            "platform": self.collect_simple_bus("platform"),
            "serio": self.collect_simple_bus("serio"),
        }

    def collect_acpi(self) -> dict[str, Any]:
        devices_by_path: dict[str, dict[str, Any]] = {}
        bus_root = self.path("/sys/bus/acpi/devices")
        bus_name_by_path: dict[str, str] = {}
        if bus_root.exists():
            for dev_dir in sorted_paths(bus_root.iterdir()):
                target = readlink_target(dev_dir)
                if target:
                    bus_name_by_path[target] = dev_dir.name

        sys_devices = self.path("/sys/devices")
        acpi_roots = (
            sorted_paths(sys_devices.glob("LNXSYSTM:*")) if sys_devices.exists() else []
        )
        for acpi_root in acpi_roots:
            for path_file in sorted_paths(acpi_root.rglob("path")):
                dev_dir = path_file.parent
                physical_path = readlink_target(dev_dir)
                acpi_path = read_clean(path_file)
                if not physical_path or not acpi_path:
                    continue
                firmware_node = dev_dir / "firmware_node"
                device = {
                    "name": bus_name_by_path.get(physical_path) or dev_dir.name,
                    "acpi_path": acpi_path,
                    "hid": read_clean(dev_dir / "hid"),
                    "modalias": read_clean(dev_dir / "modalias"),
                    "status": read_clean(dev_dir / "status"),
                    "firmware_node_path": (
                        readlink_target(firmware_node)
                        if firmware_node.exists()
                        else None
                    ),
                    "physical_node_paths": [
                        target
                        for target in (
                            readlink_target(link)
                            for link in sorted_paths(dev_dir.glob("physical_node*"))
                        )
                        if target
                    ],
                    "physical_path": physical_path,
                }
                devices_by_path[physical_path] = device

        devices = sorted(
            devices_by_path.values(),
            key=lambda item: natural_acpi_key(item.get("acpi_path"), item.get("name")),
        )
        return {
            "summary": {"device_count": len(devices)},
            "devices": devices,
        }

    def collect_system_resources(self) -> dict[str, Any]:
        return {
            "ioports": self.collect_resource_tree("ioport", self.path("/proc/ioports")),
            "iomem": self.collect_resource_tree("iomem", self.path("/proc/iomem")),
        }

    def collect_resource_tree(self, kind: str, path: Path) -> list[dict[str, Any]]:
        text = read_text(path, max_bytes=2 * 1024 * 1024)
        if text is None:
            return []
        resources: list[dict[str, Any]] = []
        stack: list[tuple[int, dict[str, Any]]] = []
        pattern = re.compile(r"^(\s*)([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.+?)\s*$")
        for line in text.splitlines():
            match = pattern.match(line)
            if not match:
                continue
            indent_text, start_text, end_text, owner = match.groups()
            indent = len(indent_text)
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1] if stack else None
            owner = owner.strip()
            resource = {
                "index": len(resources),
                "kind": kind,
                "owner": owner,
                "start": parse_int(start_text, base=16),
                "end": parse_int(end_text, base=16),
                "raw_start": start_text,
                "raw_end": end_text,
                "address_known": not (
                    all(char == "0" for char in start_text)
                    and all(char == "0" for char in end_text)
                ),
                "parent_owner": parent.get("owner") if parent else None,
                "ancestor_owners": (
                    list(parent.get("ancestor_owners", [])) + [parent.get("owner")]
                    if parent
                    else []
                ),
            }
            resources.append(resource)
            stack.append((indent, resource))
        return resources

    def collect_simple_bus(self, bus_name: str) -> dict[str, Any]:
        root = self.path(f"/sys/bus/{bus_name}/devices")
        devices: list[dict[str, Any]] = []
        if root.exists():
            for dev_dir in sorted_paths(root.iterdir()):
                path = readlink_target(dev_dir)
                if not self.should_output_device_path(path):
                    continue
                modalias = read_clean(dev_dir / "modalias")
                firmware_node = dev_dir / "firmware_node"
                devices.append(
                    {
                        "name": dev_dir.name,
                        "device_name": read_clean(dev_dir / "name"),
                        "modalias": modalias,
                        "driver": readlink_name(dev_dir / "driver"),
                        "subsystem": readlink_name(dev_dir / "subsystem"),
                        "firmware_node_path": (
                            readlink_target(firmware_node)
                            if firmware_node.exists()
                            else None
                        ),
                        "physical_node_paths": [
                            target
                            for target in (
                                readlink_target(link)
                                for link in sorted_paths(dev_dir.glob("physical_node*"))
                            )
                            if target
                        ],
                        "physical_path": path,
                    }
                )
        return {
            "summary": {"device_count": len(devices)},
            "devices": devices,
        }


def read_le(data: bytes, offset: int, size: int) -> int | None:
    if offset < 0 or size <= 0 or len(data) < offset + size:
        return None
    return int.from_bytes(data[offset : offset + size], "little")


def natural_acpi_key(*values: Any) -> list[tuple[int, int | str]]:
    return natural_key(" ".join(str(value or "") for value in values))


def dmi_nonzero(value: int | None) -> int | None:
    return value if value not in (None, 0) else None


def dmi_rank(attributes: int | None) -> int | None:
    if attributes is None:
        return None
    rank = attributes & 0x0F
    return rank or None


def parse_dmi_memory_width(width: int | None) -> int | None:
    if width in (None, 0xFFFF):
        return None
    return width


def is_dmi_memory_ecc(
    total_width_bits: int | None, data_width_bits: int | None
) -> bool | None:
    if total_width_bits is None or data_width_bits is None:
        return None
    return total_width_bits > data_width_bits


def parse_dmi_memory_size(
    size_field: int | None, extended_size: int | None
) -> int | None:
    if size_field in (None, 0, 0xFFFF):
        return None
    if size_field == 0x7FFF:
        if extended_size in (None, 0):
            return None
        value = extended_size & 0x7FFFFFFF
        unit = 1024 if extended_size & 0x80000000 else 1024 * 1024
        return value * unit
    value = size_field & 0x7FFF
    unit = 1024 if size_field & 0x8000 else 1024 * 1024
    return value * unit


def join_nonempty(*parts: Any) -> str | None:
    values = [
        str(part).strip() for part in parts if part is not None and str(part).strip()
    ]
    if not values:
        return None
    return " ".join(values)


def collect_hardware(
    root: Path = Path("/"),
    *,
    redact_serials: bool = False,
    exclude_usb_devices: bool = False,
    no_pci_bridge: bool = False,
    no_addr: bool = False,
    no_vendor: bool = False,
    no_net_dev: bool = False,
    no_net_status: bool = False,
    no_wifi: bool = False,
    no_bluetooth: bool = False,
    no_display: bool = False,
    no_display_status: bool = False,
    no_audio_jack: bool = False,
    read_sensors: bool = False,
    no_sensors: bool = False,
    test_numa: int | None = None,
) -> dict[str, Any]:
    return HardwareCollector(
        root,
        redact_serials=redact_serials,
        exclude_usb_devices=exclude_usb_devices,
        no_pci_bridge=no_pci_bridge,
        no_addr=no_addr,
        no_vendor=no_vendor,
        no_net_dev=no_net_dev,
        no_net_status=no_net_status,
        no_wifi=no_wifi,
        no_bluetooth=no_bluetooth,
        no_display=no_display,
        no_display_status=no_display_status,
        no_audio_jack=no_audio_jack,
        read_sensors=read_sensors,
        no_sensors=no_sensors,
        test_numa=test_numa,
    ).collect()


def collect_wireless_interface_wiphys() -> dict[str, dict[str, Any]]:
    try:
        from pyroute2.iwutil import IW
    except Exception:
        return {}
    try:
        with IW() as iw:
            interfaces = iw.get_interfaces_dict()
    except Exception:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for name, values in interfaces.items():
        if not values or len(values) < 2:
            continue
        result[str(name)] = {
            "ifindex": values[0],
            "wiphy": values[1],
            "mac_address": values[2] if len(values) > 2 else None,
        }
    return result


def collect_nl80211_wiphy_capabilities() -> dict[str, dict[str, Any]]:
    try:
        from pyroute2.netlink import NLM_F_DUMP, NLM_F_REQUEST
        from pyroute2.netlink.nl80211 import NL80211, NL80211_NAMES, nl80211cmd
    except Exception:
        return {}
    extend_nl80211_eht_parser(nl80211cmd)
    try:
        nl = NL80211()
        nl.bind()
    except Exception:
        return {}
    try:
        message = nl80211cmd()
        message["cmd"] = NL80211_NAMES["NL80211_CMD_GET_WIPHY"]
        message["attrs"].append(["NL80211_ATTR_SPLIT_WIPHY_DUMP", b""])
        messages = nl.nlm_request(
            message,
            msg_type=nl.prid,
            msg_flags=NLM_F_REQUEST | NLM_F_DUMP,
        )
        return parse_nl80211_wiphy_messages(messages)
    except Exception:
        return {}
    finally:
        nl.close()


def extend_nl80211_eht_parser(nl80211cmd: Any) -> None:
    iftype_data = getattr(getattr(nl80211cmd, "band", None), "iftype_data", None)
    if iftype_data is None or not hasattr(iftype_data, "nla_map"):
        return
    names = [name for name, _ in iftype_data.nla_map]
    if "NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET" in names:
        return
    mapping = list(iftype_data.nla_map)
    existing = {name for name, _ in mapping}
    for name, parser in NL80211_EHT_BAND_IFTYPE_ATTRS:
        if name not in existing:
            mapping.append((name, parser))
    iftype_data.nla_map = tuple(mapping)


def parse_nl80211_wiphy_messages(messages: Any) -> dict[str, dict[str, Any]]:
    wiphys: dict[str, dict[str, Any]] = {}
    current_band_by_wiphy: dict[str, dict[str, Any]] = {}
    for message in messages:
        attrs = nla_dict(message)
        wiphy_name = str(
            attrs.get("NL80211_ATTR_WIPHY_NAME")
            or attrs.get("NL80211_ATTR_WIPHY")
            or ""
        ).strip()
        if not wiphy_name:
            continue
        wiphy = wiphys.setdefault(
            wiphy_name,
            {
                "wiphy": wiphy_name,
                "wiphy_index": attrs.get("NL80211_ATTR_WIPHY"),
                "bands": [],
                "supported_commands": [],
            },
        )
        update_wiphy_common_attrs(wiphy, attrs)
        for band in attrs.get("NL80211_ATTR_WIPHY_BANDS") or []:
            band_attrs = nla_dict(band)
            if not band_attrs:
                current_band_by_wiphy.pop(wiphy_name, None)
                continue
            if has_wireless_band_capabilities(band_attrs):
                band_info = parse_wireless_band_capabilities(band_attrs, wiphy)
                wiphy["bands"].append(band_info)
                current_band_by_wiphy[wiphy_name] = band_info
            elif "NL80211_BAND_ATTR_FREQS" in band_attrs:
                current_band = current_band_by_wiphy.get(wiphy_name)
                if current_band is not None:
                    current_band.setdefault("frequencies", []).extend(
                        parse_wireless_frequencies(band_attrs)
                    )
    for wiphy in wiphys.values():
        bands = [
            finalized
            for band in wiphy.get("bands", [])
            if (finalized := finalize_wireless_band(band))
        ]
        wiphy["bands"] = sorted(bands, key=wireless_band_sort_key)
        wiphy["generation"] = wireless_generation(wiphy)
        wiphy["mlo_supported"] = wireless_mlo_supported(wiphy)
    return wiphys


def update_wiphy_common_attrs(wiphy: dict[str, Any], attrs: dict[str, Any]) -> None:
    if attrs.get("NL80211_ATTR_WIPHY") is not None:
        wiphy["wiphy_index"] = attrs.get("NL80211_ATTR_WIPHY")
    for nl_name, key in (
        ("NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX", "antenna_avail_tx"),
        ("NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX", "antenna_avail_rx"),
        ("NL80211_ATTR_WIPHY_ANTENNA_TX", "antenna_tx"),
        ("NL80211_ATTR_WIPHY_ANTENNA_RX", "antenna_rx"),
    ):
        if attrs.get(nl_name) is not None:
            wiphy[key] = attrs.get(nl_name)
    commands = attrs.get("NL80211_ATTR_SUPPORTED_COMMANDS") or []
    if commands:
        existing = set(wiphy.get("supported_commands") or [])
        wiphy["supported_commands"] = [
            *wiphy.get("supported_commands", []),
            *[command for command in commands if command not in existing],
        ]


def has_wireless_band_capabilities(attrs: dict[str, Any]) -> bool:
    return any(
        key in attrs
        for key in (
            "NL80211_BAND_ATTR_HT_CAPA",
            "NL80211_BAND_ATTR_VHT_CAPA",
            "NL80211_BAND_ATTR_IFTYPE_DATA",
        )
    )


def parse_wireless_band_capabilities(
    attrs: dict[str, Any], wiphy: dict[str, Any]
) -> dict[str, Any]:
    station = wireless_station_iftype_attrs(
        attrs.get("NL80211_BAND_ATTR_IFTYPE_DATA") or []
    )
    ht_mcs = attrs.get("NL80211_BAND_ATTR_HT_MCS_SET") or {}
    vht_mcs = attrs.get("NL80211_BAND_ATTR_VHT_MCS_SET") or {}
    he_mcs = station.get("NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET") or {}
    eht_mcs = tuple(station.get("NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET") or ())
    eht_phy = tuple(station.get("NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY") or ())
    return {
        "frequencies": parse_wireless_frequencies(attrs),
        "ht": bool(ht_mcs) or attrs.get("NL80211_BAND_ATTR_HT_CAPA") is not None,
        "vht": bool(vht_mcs) or attrs.get("NL80211_BAND_ATTR_VHT_CAPA") is not None,
        "he": bool(he_mcs),
        "eht": bool(eht_mcs),
        "ht_mcs": ht_mcs,
        "vht_mcs": vht_mcs,
        "he_mcs": he_mcs,
        "eht_mcs": eht_mcs,
        "eht_phy": eht_phy,
        "antenna_avail_tx": wiphy.get("antenna_avail_tx"),
        "antenna_avail_rx": wiphy.get("antenna_avail_rx"),
    }


def parse_wireless_frequencies(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    frequencies: list[dict[str, Any]] = []
    for frequency in attrs.get("NL80211_BAND_ATTR_FREQS") or []:
        freq_attrs = nla_dict(frequency)
        mhz = freq_attrs.get("NL80211_FREQUENCY_ATTR_FREQ")
        if mhz is None:
            continue
        frequencies.append(
            {
                "mhz": mhz,
                "disabled": bool(freq_attrs.get("NL80211_FREQUENCY_ATTR_DISABLED")),
                "no_ht40_minus": bool(
                    freq_attrs.get("NL80211_FREQUENCY_ATTR_NO_HT40_MINUS")
                ),
                "no_ht40_plus": bool(
                    freq_attrs.get("NL80211_FREQUENCY_ATTR_NO_HT40_PLUS")
                ),
                "no_80mhz": bool(freq_attrs.get("NL80211_FREQUENCY_ATTR_NO_80MHZ")),
                "no_160mhz": bool(freq_attrs.get("NL80211_FREQUENCY_ATTR_NO_160MHZ")),
            }
        )
    return frequencies


def wireless_station_iftype_attrs(iftype_data: list[Any]) -> dict[str, Any]:
    fallback: dict[str, Any] = {}
    for item in iftype_data:
        attrs = nla_dict(item)
        if not fallback:
            fallback = attrs
        iftypes = nla_dict(attrs.get("NL80211_BAND_IFTYPE_ATTR_IFTYPES") or {})
        if NL80211_STATION_IFTYPE in iftypes:
            return attrs
    return fallback


def finalize_wireless_band(band: dict[str, Any]) -> dict[str, Any] | None:
    active_frequencies = [
        frequency
        for frequency in band.get("frequencies", [])
        if not frequency.get("disabled")
    ]
    band_name = wireless_band_name(active_frequencies)
    if not band_name:
        return None
    best_mode = wireless_band_best_mode(band)
    spatial_streams = wireless_band_spatial_streams(band, best_mode)
    return {
        "name": band_name,
        "max_width_mhz": wireless_band_max_width_mhz(band, band_name),
        "spatial_streams": spatial_streams,
        "mimo": f"{spatial_streams}x{spatial_streams}" if spatial_streams else None,
        "he": band.get("he"),
        "eht": band.get("eht"),
        "best_mode": best_mode,
    }


def wireless_band_name(frequencies: list[dict[str, Any]]) -> str:
    values = [frequency.get("mhz") for frequency in frequencies]
    if any(isinstance(value, int) and 2400 <= value < 2500 for value in values):
        return "2.4GHz"
    if any(isinstance(value, int) and 4900 <= value < 5925 for value in values):
        return "5GHz"
    if any(isinstance(value, int) and 5925 <= value <= 7125 for value in values):
        return "6GHz"
    return ""


def wireless_band_sort_key(band: dict[str, Any]) -> int:
    return {"2.4GHz": 0, "5GHz": 1, "6GHz": 2}.get(str(band.get("name")), 99)


def wireless_band_max_width_mhz(band: dict[str, Any], band_name: str) -> int | None:
    frequencies = band.get("frequencies") or []
    if band_name == "6GHz" and wireless_band_supports_320_mhz(band):
        return 320
    if band_name in {"5GHz", "6GHz"}:
        if wireless_band_supports_160_mhz(band) or any(
            not frequency.get("disabled") and not frequency.get("no_160mhz")
            for frequency in frequencies
        ):
            return 160
        if any(
            not frequency.get("disabled") and not frequency.get("no_80mhz")
            for frequency in frequencies
        ):
            return 80
    if band_name == "2.4GHz":
        if any(
            not frequency.get("disabled")
            and not (frequency.get("no_ht40_minus") and frequency.get("no_ht40_plus"))
            for frequency in frequencies
        ):
            return 40
        return 20
    return None


def wireless_band_supports_160_mhz(band: dict[str, Any]) -> bool:
    he_mcs = band.get("he_mcs") or {}
    if he_mcs_nss(he_mcs.get("rx_mcs_160")) or he_mcs_nss(he_mcs.get("tx_mcs_160")):
        return True
    return len(tuple(band.get("eht_mcs") or ())) >= 6


def wireless_band_supports_320_mhz(band: dict[str, Any]) -> bool:
    eht_mcs = tuple(band.get("eht_mcs") or ())
    eht_phy = tuple(band.get("eht_phy") or ())
    return len(eht_mcs) >= 9 or bool(eht_phy and eht_phy[0] & 0x02)


def wireless_band_spatial_streams(
    band: dict[str, Any], best_mode: dict[str, Any] | None = None
) -> int | None:
    values = [
        (best_mode or {}).get("spatial_streams"),
        eht_mcs_nss(band.get("eht_mcs")),
        he_mcs_nss((band.get("he_mcs") or {}).get("rx_mcs_80")),
        he_mcs_nss((band.get("he_mcs") or {}).get("tx_mcs_80")),
        bit_count(band.get("antenna_avail_tx")),
        bit_count(band.get("antenna_avail_rx")),
    ]
    return max((value for value in values if value), default=None)


def wireless_band_best_mode(band: dict[str, Any]) -> dict[str, Any] | None:
    candidates = [
        *ht_mcs_modes(band.get("ht_mcs")),
        *vht_mcs_modes(band.get("vht_mcs")),
        *he_mcs_modes(band.get("he_mcs")),
        *eht_mcs_modes(band.get("eht_mcs")),
    ]
    return max(candidates, key=wireless_mode_sort_key, default=None)


def wireless_mode_sort_key(mode: dict[str, Any]) -> tuple[int, int, int]:
    standard_order = {"HT": 0, "VHT": 1, "HE": 2, "EHT": 3}
    return (
        standard_order.get(str(mode.get("standard")), -1),
        int(mode.get("spatial_streams") or 0),
        int(mode.get("mcs") or -1),
    )


def ht_mcs_modes(value: Any) -> list[dict[str, Any]]:
    rx_mask = dict_value(value, "rx_mask") or ()
    modes: list[dict[str, Any]] = []
    for byte_index, raw_byte in enumerate(rx_mask):
        try:
            byte = int(raw_byte)
        except (TypeError, ValueError):
            continue
        for bit_index in range(8):
            if not (byte & (1 << bit_index)):
                continue
            mcs = byte_index * 8 + bit_index
            if mcs > 31:
                continue
            modes.append(
                {
                    "standard": "HT",
                    "spatial_streams": (mcs // 8) + 1,
                    "mcs": mcs,
                }
            )
    return modes


def vht_mcs_modes(value: Any) -> list[dict[str, Any]]:
    modes: list[dict[str, Any]] = []
    for key in ("rx_mcs_map", "tx_mcs_map"):
        modes.extend(
            nss_mcs_map_modes(
                "VHT",
                dict_value(value, key),
                {
                    0: 7,
                    1: 8,
                    2: 9,
                },
            )
        )
    return modes


def he_mcs_modes(value: Any) -> list[dict[str, Any]]:
    modes: list[dict[str, Any]] = []
    for key in ("rx_mcs_80", "tx_mcs_80", "rx_mcs_160", "tx_mcs_160"):
        modes.extend(
            nss_mcs_map_modes(
                "HE",
                dict_value(value, key),
                {
                    0: 7,
                    1: 9,
                    2: 11,
                },
            )
        )
    return modes


def nss_mcs_map_modes(
    standard: str, value: Any, code_to_mcs: dict[int, int]
) -> list[dict[str, Any]]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return []
    modes: list[dict[str, Any]] = []
    for index in range(8):
        code = (number >> (index * 2)) & 0x3
        if code not in code_to_mcs:
            continue
        modes.append(
            {
                "standard": standard,
                "spatial_streams": index + 1,
                "mcs": code_to_mcs[code],
            }
        )
    return modes


def eht_mcs_modes(value: Any) -> list[dict[str, Any]]:
    try:
        values = tuple(int(item) for item in value or ())
    except (TypeError, ValueError):
        return []
    if not values:
        return []
    mcs_values = (7, 9, 11, 13) if len(values) == 4 else (9, 11, 13)
    modes: list[dict[str, Any]] = []
    for index, byte in enumerate(values):
        for nss in (byte & 0x0F, (byte >> 4) & 0x0F):
            if 0 < nss < 0x0F:
                modes.append(
                    {
                        "standard": "EHT",
                        "spatial_streams": nss,
                        "mcs": mcs_values[index % len(mcs_values)],
                    }
                )
    return modes


def dict_value(value: Any, key: str) -> Any:
    if hasattr(value, "get"):
        return value.get(key)
    return None


def he_mcs_nss(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    max_nss = 0
    for index in range(8):
        code = (number >> (index * 2)) & 0x3
        if code != 0x3:
            max_nss = index + 1
    return max_nss or None


def eht_mcs_nss(value: Any) -> int | None:
    if isinstance(value, dict):
        candidates = value.values()
    else:
        candidates = value or []
    max_nss = 0
    for item in candidates:
        try:
            byte = int(item)
        except (TypeError, ValueError):
            continue
        for nibble in (byte & 0x0F, (byte >> 4) & 0x0F):
            if 0 < nibble < 0x0F:
                max_nss = max(max_nss, nibble)
    return max_nss or None


def bit_count(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    return number.bit_count()


def wireless_generation(wiphy: dict[str, Any]) -> str:
    bands = wiphy.get("bands") or []
    if any(band.get("eht") for band in bands):
        return "Wi-Fi 7"
    if any(band.get("he") for band in bands):
        if any(band.get("name") == "6GHz" for band in bands):
            return "Wi-Fi 6E"
        return "Wi-Fi 6"
    if any(band.get("vht") for band in bands):
        return "Wi-Fi 5"
    return "Wi-Fi"


def wireless_mlo_supported(wiphy: dict[str, Any]) -> bool:
    commands = {str(command) for command in wiphy.get("supported_commands") or []}
    return (
        any("MLO" in command.upper() for command in commands)
        or NL80211_CMD_ASSOC_MLO_RECONF_FALLBACK in commands
    )


def nla_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value.get("attrs") or [])
    return {}


def open_bluetooth_mgmt_socket() -> socket.socket:
    address_family = getattr(socket, "AF_BLUETOOTH", None)
    if address_family is None:
        raise OSError("AF_BLUETOOTH is unavailable")
    protocol = getattr(socket, "BTPROTO_HCI", 1)
    sock = socket.socket(address_family, socket.SOCK_RAW, protocol)
    try:
        bind_bluetooth_hci_control(sock, address_family)
        sock.settimeout(1.0)
        return sock
    except OSError:
        sock.close()
        raise


def bind_bluetooth_hci_control(sock: socket.socket, address_family: int) -> None:
    sockaddr = struct.pack("=HHH", address_family, HCI_DEV_NONE, HCI_CHANNEL_CONTROL)
    buffer = ctypes.create_string_buffer(sockaddr)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.bind(
        ctypes.c_int(sock.fileno()),
        ctypes.cast(buffer, ctypes.c_void_p),
        ctypes.c_uint32(len(sockaddr)),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def bluetooth_mgmt_command(
    sock: socket.socket,
    opcode: int,
    index: int = HCI_DEV_NONE,
    payload: bytes = b"",
) -> tuple[int, int, bytes]:
    sock.sendall(struct.pack("<HHH", opcode, index, len(payload)) + payload)
    for _ in range(32):
        data = sock.recv(4096)
        if len(data) < 6:
            continue
        event, event_index, length = struct.unpack_from("<HHH", data)
        params = data[6 : 6 + length]
        if event == MGMT_EV_CMD_COMPLETE and len(params) >= 3:
            completed_opcode, status = struct.unpack_from("<HB", params)
            if completed_opcode == opcode:
                return status, event_index, params[3:]
        if event == MGMT_EV_CMD_STATUS and len(params) >= 3:
            status, completed_opcode = struct.unpack_from("<BH", params)
            if completed_opcode == opcode:
                return status, event_index, b""
    raise TimeoutError(f"Bluetooth management command 0x{opcode:04x} timed out")


def parse_bluetooth_mgmt_controller_info(payload: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {}
    if len(payload) >= 6:
        info["address"] = ":".join(f"{byte:02X}" for byte in reversed(payload[:6]))
    if len(payload) >= 7:
        version_code = payload[6]
        info["bluetooth_version_code"] = version_code
        info["bluetooth_version"] = bluetooth_version_text(version_code)
    if len(payload) >= 9:
        info["manufacturer_id"] = struct.unpack_from("<H", payload, 7)[0]
    if len(payload) >= 13:
        supported_mask = struct.unpack_from("<I", payload, 9)[0]
        info["supported_settings_mask"] = supported_mask
        info["supported_settings"] = bluetooth_settings(supported_mask)
    if len(payload) >= 17:
        current_mask = struct.unpack_from("<I", payload, 13)[0]
        info["current_settings_mask"] = current_mask
        info["current_settings"] = bluetooth_settings(current_mask)
    if len(payload) >= 20:
        info["device_class"] = "0x" + payload[17:20].hex()
    if len(payload) > 20:
        info["name"] = decode_nul_terminated(payload[20:269])
    if len(payload) > 269:
        info["short_name"] = decode_nul_terminated(payload[269:280])
    return info


def bluetooth_version_text(version_code: int) -> str:
    version = BLUETOOTH_CORE_VERSIONS.get(version_code)
    if version:
        return f"Bluetooth {version}"
    return f"Bluetooth HCI {version_code}"


def bluetooth_settings(mask: int) -> list[str]:
    return [name for bit, name in BLUETOOTH_MGMT_SETTINGS if mask & (1 << bit)]


def decode_nul_terminated(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()


def collect_hda_elds_by_pin(proc_card: Path) -> dict[str, list[dict[str, Any]]]:
    elds_by_pin: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for eld_path in sorted_paths(proc_card.glob("eld#*")):
        eld = parse_hda_eld(read_text(eld_path, max_bytes=131_072))
        pin_id = normalize_hda_nid(eld.get("codec_pin_nid"))
        if not pin_id:
            continue
        eld["source"] = str(eld_path)
        elds_by_pin[pin_id].append(eld)
    return elds_by_pin


def parse_hda_eld(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    values: dict[str, Any] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        key = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""
        values[key] = value
    values["monitor_present_bool"] = (
        parse_int(str(values.get("monitor_present") or "")) == 1
    )
    values["eld_valid_bool"] = parse_int(str(values.get("eld_valid") or "")) == 1
    return values


def parse_hda_codec_pins(text: str) -> list[dict[str, Any]]:
    codec_name: str | None = None
    codec_address: str | None = None
    pins: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def finish_current() -> None:
        if current is not None:
            pins.append(current)

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Codec:"):
            codec_name = clean_value(stripped.split(":", 1)[1])
            continue
        if stripped.startswith("Address:"):
            codec_address = clean_value(stripped.split(":", 1)[1])
            continue
        node_match = HDA_NODE_PATTERN.match(stripped)
        if node_match:
            finish_current()
            node_id, widget, suffix = node_match.groups()
            if "Pin Complex" in widget:
                current = {
                    "node_id": normalize_hda_nid(node_id),
                    "widget": widget,
                    "widget_caps": suffix.strip() or None,
                    "codec_name": codec_name,
                    "codec_address": codec_address,
                    "controls": [],
                    "devices": [],
                    "devs": [],
                    "connections": [],
                }
            else:
                current = None
            continue
        if current is None:
            continue
        if stripped.startswith("Pincap "):
            _, value = stripped.split(":", 1) if ":" in stripped else ("", "")
            current["pincap"] = clean_value(value)
            continue
        default_match = HDA_PIN_DEFAULT_PATTERN.match(stripped)
        if default_match:
            pin_default, port_connectivity, default_device, default_location = (
                default_match.groups()
            )
            current.update(
                {
                    "pin_default": pin_default.lower(),
                    "port_connectivity": clean_value(port_connectivity),
                    "default_device": clean_value(default_device),
                    "default_location": clean_value(default_location),
                }
            )
            continue
        conn_match = HDA_CONN_PATTERN.match(stripped)
        if conn_match:
            current["connector"] = clean_value(conn_match.group(1))
            current["color"] = clean_value(conn_match.group(2))
            continue
        if stripped.startswith("Pin-ctls:"):
            _, value = stripped.split(":", 1)
            current["pin_ctls"] = clean_value(value)
            continue
        control_match = HDA_CONTROL_PATTERN.match(stripped)
        if control_match:
            current.setdefault("controls", []).append(control_match.group(1))
            continue
        device_match = HDA_DEVICE_PATTERN.match(stripped)
        if device_match:
            current.setdefault("devices", []).append(
                {
                    "name": device_match.group(1),
                    "device": parse_int(device_match.group(2)),
                }
            )
            continue
        dev_match = HDA_DEV_PATTERN.match(stripped)
        if dev_match:
            current.setdefault("devs", []).append(
                {
                    "device": parse_int(dev_match.group(1)),
                    "status": dev_match.group(2),
                }
            )
            continue
        if stripped.startswith("Connection:"):
            current["connection_count"] = parse_int(stripped.split(":", 1)[1].strip())
            continue
        if stripped.startswith("0x"):
            current.setdefault("connections", []).extend(stripped.split())
    finish_current()
    return pins


def should_show_hda_audio_pin(pin: dict[str, Any]) -> bool:
    if str(pin.get("port_connectivity") or "").casefold() == "n/a":
        return False
    if not pin.get("default_device"):
        return False
    return True


def hda_audio_port_from_pin(
    pin: dict[str, Any], eld: dict[str, Any] | None
) -> dict[str, Any] | None:
    label = hda_audio_pin_label(pin, eld)
    if not label:
        return None
    edge_label = hda_audio_edge_label(pin, eld)
    connected_devices = []
    eld_connected_device = hda_eld_connected_audio_device(eld)
    if eld_connected_device:
        connected_devices.append(eld_connected_device)
    return {
        "label": label,
        "edge_label": edge_label,
        "port_type": hda_audio_port_type(pin, eld),
        "default_device": pin.get("default_device"),
        "default_location": pin.get("default_location"),
        "connector": normalize_audio_connector(pin.get("connector")),
        "color": normalize_audio_color(pin.get("color")),
        "pincap": pin.get("pincap"),
        "pin_ctls": pin.get("pin_ctls"),
        "controls": pin.get("controls") or [],
        "pcm_devices": pin.get("devices") or [],
        "eld": eld,
        "connected_devices": connected_devices,
    }


def select_hda_pin_eld(elds: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not elds:
        return None
    return sorted(
        elds,
        key=lambda eld: (
            not bool(eld.get("eld_valid_bool")),
            not bool(eld.get("monitor_present_bool")),
            natural_key(str(eld.get("codec_dev_id") or "")),
        ),
    )[0]


def hda_audio_pin_label(pin: dict[str, Any], eld: dict[str, Any] | None) -> str:
    port_type = hda_audio_port_type(pin, eld)
    if port_type in {"DisplayPort", "HDMI", "HDMI/DP"}:
        return f"{port_type} Audio"
    default_device = str(pin.get("default_device") or "").strip()
    base = hda_default_device_label(default_device)
    location = hda_location_label(pin.get("default_location"))
    if location and location.casefold() not in base.casefold():
        base = f"{base} {location}"
    connector = audio_connector_label(pin.get("connector"), pin.get("color"))
    if connector:
        base = f"{base} ({connector})"
    return base.strip()


def hda_audio_edge_label(pin: dict[str, Any], eld: dict[str, Any] | None) -> str:
    port_type = hda_audio_port_type(pin, eld)
    if port_type == "DisplayPort":
        return "DisplayPort audio"
    if port_type == "HDMI":
        return "HDMI audio"
    if port_type == "HDMI/DP":
        return "HDMI/DP audio"
    if port_type == "S/PDIF":
        return "S/PDIF"
    if port_type == "Digital":
        return "Digital audio"
    return "Analog audio"


def hda_audio_port_type(pin: dict[str, Any], eld: dict[str, Any] | None) -> str:
    connection_type = clean_value(str((eld or {}).get("connection_type") or ""))
    if connection_type in {"DisplayPort", "HDMI"}:
        return connection_type
    combined = " ".join(
        str(pin.get(key) or "")
        for key in ("pincap", "default_device", "default_location", "connector")
    ).casefold()
    if "displayport" in combined:
        return "DisplayPort"
    if "hdmi" in combined and " dp" in f" {combined}":
        return "HDMI/DP"
    if "hdmi" in combined:
        return "HDMI"
    if "spdif" in combined or "s/pdif" in combined:
        return "S/PDIF"
    if "digital" in combined:
        return "Digital"
    return "Analog"


def hda_eld_connected_audio_device(eld: dict[str, Any] | None) -> dict[str, Any] | None:
    if not eld or not eld.get("monitor_present_bool") or not eld.get("eld_valid_bool"):
        return None
    monitor_name = clean_value(str(eld.get("monitor_name") or ""))
    if not monitor_name:
        monitor_name = "Display audio"
    label = (
        f"{monitor_name} Audio"
        if not monitor_name.casefold().endswith(" audio")
        else monitor_name
    )
    return {
        "id": f"eld:{eld.get('codec_pin_nid')}:{eld.get('codec_dev_id')}:{monitor_name}",
        "label": label,
        "edge_label": "Audio sink",
        "device_type": "display-audio-sink",
        "connection": eld.get("connection_type"),
        "speakers": eld.get("speakers"),
        "formats": hda_eld_audio_formats(eld),
        "max_channels": hda_eld_max_channels(eld),
    }


def hda_eld_audio_formats(eld: dict[str, Any]) -> list[str]:
    formats: list[str] = []
    count = parse_int(str(eld.get("sad_count") or ""))
    if count is None:
        count = 0
    for index in range(count):
        value = str(eld.get(f"sad{index}_coding_type") or "").strip()
        if not value:
            continue
        if "]" in value:
            value = value.split("]", 1)[1].strip()
        if value and value not in formats:
            formats.append(value)
    return formats


def hda_eld_max_channels(eld: dict[str, Any]) -> int | None:
    channels = [
        parse_int(str(eld.get(f"sad{index}_channels") or ""))
        for index in range(parse_int(str(eld.get("sad_count") or "")) or 0)
    ]
    values = [channel for channel in channels if channel is not None]
    return max(values) if values else None


def select_hda_jack_for_pin(
    pin: dict[str, Any], jacks: list[dict[str, Any]]
) -> dict[str, Any] | None:
    expected_switch = hda_pin_expected_switch(pin)
    if not expected_switch:
        return None
    candidates = [
        jack
        for jack in jacks
        if expected_switch in (jack.get("supported_switches") or [])
    ]
    if not candidates:
        return None
    pin_location = hda_pin_location(pin)
    pin_role = hda_pin_role(pin)
    return min(
        candidates,
        key=lambda jack: (
            0 if jack_matches_location(jack, pin_location) else 1,
            0 if jack_matches_role(jack, pin_role) else 1,
            natural_key(str(jack.get("name") or "")),
        ),
    )


def hda_pin_expected_switch(pin: dict[str, Any]) -> str:
    text = str(pin.get("default_device") or "").casefold()
    if "mic" in text:
        return "microphone"
    if "hp" in text or "headphone" in text:
        return "headphone"
    if "line out" in text or "speaker" in text:
        return "lineout"
    if "line in" in text:
        return "linein"
    return ""


def hda_pin_role(pin: dict[str, Any]) -> str:
    text = str(pin.get("default_device") or "").casefold()
    if "mic" in text:
        return "mic"
    if "hp" in text or "headphone" in text:
        return "headphone"
    if "line out" in text:
        return "line out"
    if "line in" in text:
        return "line in"
    if "speaker" in text:
        return "speaker"
    return text.strip()


def hda_pin_location(pin: dict[str, Any]) -> str:
    text = str(pin.get("default_location") or "").casefold()
    for value in ("front", "rear", "internal", "external"):
        if value in text:
            return value
    return ""


def jack_matches_location(jack: dict[str, Any], location: str) -> bool:
    if not location:
        return True
    name = str(jack.get("name") or "").casefold()
    aliases = {
        "rear": ("rear",),
        "front": ("front",),
        "internal": ("internal",),
        "external": ("external",),
    }
    return any(alias in name for alias in aliases.get(location, (location,)))


def jack_matches_role(jack: dict[str, Any], role: str) -> bool:
    if not role:
        return True
    name = str(jack.get("name") or "").casefold()
    if role == "headphone":
        return "headphone" in name or "hp" in name
    return all(part in name for part in role.split())


def hda_analog_connected_audio_device(
    pin: dict[str, Any], jack: dict[str, Any]
) -> dict[str, Any] | None:
    if not jack.get("inserted"):
        return None
    label = hda_analog_connected_audio_label(pin)
    return {
        "id": f"jack:{pin.get('node_id')}:{jack.get('sysfs_name')}",
        "label": label,
        "edge_label": "Analog jack",
        "device_type": "analog-audio-device",
        "jack": jack.get("name"),
        "switches": jack.get("active_switches") or [],
    }


def hda_analog_connected_audio_label(pin: dict[str, Any]) -> str:
    role = hda_pin_role(pin)
    if role == "mic":
        return "Microphone"
    if role == "headphone":
        return "Headphones"
    if role == "line in":
        return "Line-in device"
    if role in {"line out", "speaker"}:
        return "Speakers"
    return "Audio device"


def hda_default_device_label(default_device: str) -> str:
    return re.sub(r"\s+", " ", default_device).strip() or "Audio port"


def hda_location_label(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    pieces = [
        piece for piece in text.split() if piece.lower() not in {"ext", "int", "n/a"}
    ]
    return " ".join(pieces).strip()


def audio_connector_label(connector: Any, color: Any) -> str:
    connector_text = normalize_audio_connector(connector)
    color_text = normalize_audio_color(color)
    parts = [part for part in (connector_text, color_text) if part]
    return ", ".join(parts)


def normalize_audio_connector(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text.casefold() in {"", "unknown", "n/a"} else text


def normalize_audio_color(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text.casefold() in {"", "unknown", "n/a"} else text


def normalize_hda_nid(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    number = parse_int(text, base=16 if text.startswith("0x") else 10)
    if number is None:
        return text
    return f"0x{number:02x}"


def first_input_event_name(input_dir: Path) -> str | None:
    for event_dir in sorted_paths(input_dir.glob("event*")):
        return event_dir.name
    return None


def parse_input_switch_mask(value: str | None) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    mask = 0
    for index, word in enumerate(reversed(text.split())):
        parsed = parse_int(word, base=16)
        if parsed is None:
            continue
        mask |= parsed << (index * 64)
    return mask


def input_switch_names(mask: int) -> list[str]:
    return [
        name for bit, name in sorted(INPUT_SWITCH_NAMES.items()) if mask & (1 << bit)
    ]


def parse_usb_audio_stream_ports(text: str) -> list[dict[str, Any]]:
    raw_ports: list[dict[str, Any]] = []
    direction: str | None = None
    section_status: str | None = None
    current: dict[str, Any] | None = None

    def finish_current() -> None:
        if current and current.get("endpoint_address"):
            raw_ports.append(dict(current))

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        section_match = USB_AUDIO_SECTION_PATTERN.match(stripped)
        if section_match:
            finish_current()
            current = None
            direction = section_match.group(1).casefold()
            section_status = None
            continue
        if direction and stripped.startswith("Status:"):
            section_status = clean_value(stripped.split(":", 1)[1])
            continue
        interface_match = USB_AUDIO_INTERFACE_PATTERN.match(stripped)
        if interface_match and direction:
            finish_current()
            current = {
                "direction": direction,
                "interface": parse_int(interface_match.group(1)),
                "status": section_status,
            }
            continue
        if current is None or ":" not in stripped:
            continue
        key, value = [part.strip() for part in stripped.split(":", 1)]
        if key == "Altset":
            current["altset"] = parse_int(value)
        elif key == "Format":
            current["format"] = clean_value(value)
        elif key == "Channels":
            current["channels"] = parse_int(value)
        elif key == "Endpoint":
            current.update(parse_usb_audio_endpoint(value))
        elif key == "Rates":
            current["rates"] = parse_usb_audio_rates(value)
        elif key == "Bits":
            current["bits"] = parse_int(value)
        elif key == "Channel map":
            current["channel_map"] = clean_value(value)
        elif key == "Data packet interval":
            current["packet_interval"] = clean_value(value)
        elif key == "Sync Endpoint":
            current["sync_endpoint"] = clean_value(value)
    finish_current()
    return aggregate_usb_audio_stream_ports(raw_ports)


def parse_usb_audio_endpoint(value: str) -> dict[str, Any]:
    match = USB_AUDIO_ENDPOINT_PATTERN.match(value.strip())
    if not match:
        return {"endpoint": clean_value(value)}
    address, direction_text, mode = match.groups()
    pieces = direction_text.split()
    endpoint_number = parse_int(pieces[0]) if pieces else None
    endpoint_direction = pieces[1] if len(pieces) > 1 else None
    return {
        "endpoint": clean_value(value),
        "endpoint_address": address.lower(),
        "endpoint_number": endpoint_number,
        "endpoint_direction": endpoint_direction,
        "endpoint_mode": clean_value(mode),
    }


def parse_usb_audio_rates(value: str) -> list[int]:
    rates: list[int] = []
    for part in value.split(","):
        rate = parse_int(part.strip())
        if rate is not None:
            rates.append(rate)
    return sorted(set(rates))


def aggregate_usb_audio_stream_ports(
    raw_ports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for port in raw_ports:
        key = (
            port.get("direction"),
            port.get("interface"),
            port.get("endpoint_address"),
        )
        aggregate = grouped.setdefault(
            key,
            {
                **port,
                "rates": [],
                "formats": [],
                "altsets": [],
            },
        )
        aggregate["channels"] = max_int(aggregate.get("channels"), port.get("channels"))
        aggregate["bits"] = max_int(aggregate.get("bits"), port.get("bits"))
        aggregate["rates"] = sorted(
            set((aggregate.get("rates") or []) + (port.get("rates") or []))
        )
        if port.get("format") and port.get("format") not in aggregate["formats"]:
            aggregate["formats"].append(port.get("format"))
        if (
            port.get("altset") is not None
            and port.get("altset") not in aggregate["altsets"]
        ):
            aggregate["altsets"].append(port.get("altset"))
    return sorted(grouped.values(), key=usb_audio_stream_port_sort_key)


def usb_audio_stream_port_sort_key(port: dict[str, Any]) -> tuple[Any, ...]:
    direction_rank = 0 if port.get("direction") == "playback" else 1
    return (
        direction_rank,
        port.get("interface") if port.get("interface") is not None else 999,
        port.get("endpoint_number") if port.get("endpoint_number") is not None else 999,
        str(port.get("endpoint_address") or ""),
    )


def max_int(left: Any, right: Any) -> int | None:
    values = [value for value in (left, right) if isinstance(value, int)]
    return max(values) if values else None


def usb_audio_stream_port_label(port: dict[str, Any]) -> str:
    direction = str(port.get("direction") or "stream").casefold()
    endpoint_direction = str(port.get("endpoint_direction") or "").upper()
    if not endpoint_direction:
        endpoint_direction = "OUT" if direction == "playback" else "IN"
    summary = usb_audio_stream_summary(port)
    prefix = f"{direction} {endpoint_direction}"
    return f"{prefix}: {summary}" if summary else prefix


def usb_audio_stream_summary(port: dict[str, Any]) -> str:
    parts: list[str] = []
    channels = port.get("channels")
    if isinstance(channels, int):
        parts.append(f"{channels}ch")
    bits = port.get("bits")
    if isinstance(bits, int):
        parts.append(f"{bits}-bit")
    rates = format_audio_rates(port.get("rates") or [])
    if rates:
        parts.append(rates)
    return " ".join(parts)


def format_audio_rates(rates: list[int]) -> str:
    if not rates:
        return ""
    if len(rates) == 1:
        return format_audio_rate(rates[0])
    return f"{format_audio_rate(min(rates))}-{format_audio_rate(max(rates))}"


def format_audio_rate(rate: int) -> str:
    khz = rate / 1000
    if khz.is_integer():
        return f"{int(khz)}k"
    return f"{khz:g}k"


def drm_get_connector(
    fd: int,
    connector_id: int,
) -> tuple[DrmModeGetConnector, list[DrmModeModeInfo], dict[str, Any]]:
    connector = DrmModeGetConnector()
    connector.connector_id = connector_id
    connector.count_modes = 1
    temporary_mode = DrmModeModeInfo()
    connector.modes_ptr = ctypes.addressof(temporary_mode)
    fcntl.ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, connector)

    modes_array = DrmModeModeInfo * connector.count_modes
    props_array = ctypes.c_uint32 * connector.count_props
    values_array = ctypes.c_uint64 * connector.count_props
    encoders_array = ctypes.c_uint32 * connector.count_encoders
    modes = modes_array()
    props = props_array()
    values = values_array()
    encoders = encoders_array()

    connector.modes_ptr = ctypes.addressof(modes) if connector.count_modes else 0
    connector.props_ptr = ctypes.addressof(props) if connector.count_props else 0
    connector.prop_values_ptr = ctypes.addressof(values) if connector.count_props else 0
    connector.encoders_ptr = (
        ctypes.addressof(encoders) if connector.count_encoders else 0
    )
    fcntl.ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, connector)

    property_values: dict[str, Any] = {}
    for property_id, property_value in zip(props, values):
        name, value = drm_property_value(fd, int(property_id), int(property_value))
        if name:
            property_values[name] = value
    return connector, list(modes), property_values


def drm_property_value(fd: int, property_id: int, value: int) -> tuple[str, Any]:
    prop = DrmModeGetProperty()
    prop.prop_id = property_id
    fcntl.ioctl(fd, DRM_IOCTL_MODE_GETPROPERTY, prop)
    name = prop.name.decode("ascii", errors="ignore").rstrip("\x00")
    if prop.count_values or prop.count_enum_blobs:
        values = (ctypes.c_uint64 * prop.count_values)() if prop.count_values else None
        if values is not None:
            prop.values_ptr = ctypes.addressof(values)
    if prop.count_enum_blobs:
        enum_array_type = DrmModePropertyEnum * prop.count_enum_blobs
        enums = enum_array_type()
        prop.enum_blob_ptr = ctypes.addressof(enums)
        fcntl.ioctl(fd, DRM_IOCTL_MODE_GETPROPERTY, prop)
        for enum in enums:
            if int(enum.value) == value:
                enum_name = enum.name.decode("ascii", errors="ignore").rstrip("\x00")
                return name, enum_name or value
    return name, value


def drm_current_mode(fd: int, encoder_id: int) -> str | None:
    if not encoder_id:
        return None
    encoder = DrmModeGetEncoder()
    encoder.encoder_id = encoder_id
    fcntl.ioctl(fd, DRM_IOCTL_MODE_GETENCODER, encoder)
    if not encoder.crtc_id:
        return None
    crtc = DrmModeCrtc()
    crtc.crtc_id = encoder.crtc_id
    fcntl.ioctl(fd, DRM_IOCTL_MODE_GETCRTC, crtc)
    if not crtc.mode_valid:
        return None
    return format_drm_mode(crtc.mode)


def format_drm_mode(mode: DrmModeModeInfo) -> str:
    refresh = mode.vrefresh or drm_mode_refresh(mode)
    return f"{mode.hdisplay}x{mode.vdisplay}@{format_refresh_hz(refresh)}"


def drm_mode_refresh(mode: DrmModeModeInfo) -> float:
    if not mode.clock or not mode.htotal or not mode.vtotal:
        return 0.0
    return (mode.clock * 1000) / (mode.htotal * mode.vtotal)


def edid_manufacturer_id(high: int, low: int) -> str:
    value = (high << 8) | low
    return "".join(chr(((value >> shift) & 0x1F) + 64) for shift in (10, 5, 0))


def parse_edid_descriptors(base: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for offset in range(54, 126, 18):
        descriptor = base[offset : offset + 18]
        if len(descriptor) < 18 or descriptor[:3] != b"\x00\x00\x00":
            continue
        text = edid_descriptor_text(descriptor)
        if not text:
            continue
        tag = descriptor[3]
        if tag == 0xFC:
            result.setdefault("display_name", text)
        elif tag == 0xFF:
            result.setdefault("serial", text)
        elif tag == 0xFE:
            result.setdefault("text", text)
    return result


def parse_edid_refresh_range(base: bytes) -> str | None:
    for offset in range(54, 126, 18):
        descriptor = base[offset : offset + 18]
        if len(descriptor) < 18 or descriptor[:4] != b"\x00\x00\x00\xfd":
            continue
        min_v = descriptor[5]
        max_v = descriptor[6]
        if min_v and max_v:
            return f"{min_v}-{max_v} Hz"
    return None


def edid_descriptor_text(descriptor: bytes) -> str:
    text = descriptor[5:18].split(b"\x0a", 1)[0].split(b"\x00", 1)[0]
    return text.decode("ascii", errors="replace").strip()


def parse_edid_preferred_mode(base: bytes) -> str | None:
    descriptor = base[54:72]
    if len(descriptor) < 18:
        return None
    pixel_clock_hz = int.from_bytes(descriptor[0:2], "little") * 10_000
    if pixel_clock_hz <= 0:
        return None
    h_active = descriptor[2] + ((descriptor[4] >> 4) & 0x0F) * 256
    h_blank = descriptor[3] + (descriptor[4] & 0x0F) * 256
    v_active = descriptor[5] + ((descriptor[7] >> 4) & 0x0F) * 256
    v_blank = descriptor[6] + (descriptor[7] & 0x0F) * 256
    h_total = h_active + h_blank
    v_total = v_active + v_blank
    if not h_active or not v_active or not h_total or not v_total:
        return None
    refresh = pixel_clock_hz / (h_total * v_total)
    return f"{h_active}x{v_active}@{format_refresh_hz(refresh)}"


def parse_edid_detailed_modes(edid: bytes) -> list[str]:
    modes: list[str] = []

    def add_mode(descriptor: bytes) -> None:
        mode = parse_edid_detailed_timing(descriptor)
        if mode and mode not in modes:
            modes.append(mode)

    base = edid[:128]
    for offset in range(54, 126, 18):
        add_mode(base[offset : offset + 18])
    for block_index in range(1, len(edid) // 128):
        block = edid[block_index * 128 : (block_index + 1) * 128]
        if len(block) < 128 or block[0] != 0x02:
            continue
        dtd_offset = block[2]
        if dtd_offset <= 4 or dtd_offset >= 127:
            continue
        for offset in range(dtd_offset, 127, 18):
            add_mode(block[offset : offset + 18])
    return modes


def parse_edid_detailed_timing(descriptor: bytes) -> str | None:
    if len(descriptor) < 18:
        return None
    pixel_clock_hz = int.from_bytes(descriptor[0:2], "little") * 10_000
    if pixel_clock_hz <= 0:
        return None
    h_active = descriptor[2] + ((descriptor[4] >> 4) & 0x0F) * 256
    h_blank = descriptor[3] + (descriptor[4] & 0x0F) * 256
    v_active = descriptor[5] + ((descriptor[7] >> 4) & 0x0F) * 256
    v_blank = descriptor[6] + (descriptor[7] & 0x0F) * 256
    h_total = h_active + h_blank
    v_total = v_active + v_blank
    if not h_active or not v_active or not h_total or not v_total:
        return None
    refresh = pixel_clock_hz / (h_total * v_total)
    return f"{h_active}x{v_active}@{format_refresh_hz(refresh)}"


def parse_edid_hdr_static_metadata(edid: bytes) -> dict[str, Any]:
    eotfs: list[str] = []
    for block_index in range(1, len(edid) // 128):
        block = edid[block_index * 128 : (block_index + 1) * 128]
        if len(block) < 128 or block[0] != 0x02:
            continue
        data_end = block[2] if 4 < block[2] < 127 else 127
        offset = 4
        while offset < data_end:
            header = block[offset]
            tag = header >> 5
            length = header & 0x1F
            payload = block[offset + 1 : offset + 1 + length]
            if tag == 7 and len(payload) >= 2 and payload[0] == 0x06:
                eotfs.extend(edid_hdr_eotfs(payload[1]))
            offset += 1 + length
    unique_eotfs = list(dict.fromkeys(eotfs))
    return {
        "hdr_supported": any(eotf != "SDR" for eotf in unique_eotfs),
        "hdr_eotfs": unique_eotfs,
    }


def edid_hdr_eotfs(flags: int) -> list[str]:
    names = [
        (0, "SDR"),
        (1, "Traditional HDR"),
        (2, "PQ"),
        (3, "HLG"),
    ]
    return [name for bit, name in names if flags & (1 << bit)]


def format_refresh_hz(refresh: float) -> str:
    rounded = round(refresh)
    if abs(refresh - rounded) < 0.01:
        return f"{rounded}Hz"
    return f"{refresh:.2f}".rstrip("0").rstrip(".") + "Hz"
