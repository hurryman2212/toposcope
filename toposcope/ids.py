from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .util import parse_hex_id, read_text

PCI_IDS_PATHS = (
    Path("/usr/share/hwdata/pci.ids"),
    Path("/usr/share/misc/pci.ids"),
    Path("/usr/share/pci.ids"),
)

USB_IDS_PATHS = (
    Path("/usr/share/hwdata/usb.ids"),
    Path("/usr/share/misc/usb.ids"),
    Path("/usr/share/usb.ids"),
)

PNP_IDS_PATHS = (
    Path("/usr/share/hwdata/pnp.ids"),
    Path("/usr/share/misc/pnp.ids"),
    Path("/usr/share/pnp.ids"),
)


PCI_CLASS_NAMES = {
    "00": "Unclassified",
    "01": "Mass storage controller",
    "02": "Network controller",
    "03": "Display controller",
    "04": "Multimedia controller",
    "05": "Memory controller",
    "06": "Bridge",
    "07": "Communication controller",
    "08": "System peripheral",
    "09": "Input device controller",
    "0a": "Docking station",
    "0b": "Processor",
    "0c": "Serial bus controller",
    "0d": "Wireless controller",
    "0e": "Intelligent controller",
    "0f": "Satellite communications controller",
    "10": "Encryption controller",
    "11": "Signal processing controller",
    "12": "Processing accelerator",
    "13": "Non-essential instrumentation",
    "40": "Co-processor",
    "ff": "Unassigned class",
}


USB_CLASS_NAMES = {
    "00": "Device",
    "01": "Audio",
    "02": "Communications",
    "03": "Human Interface",
    "05": "Physical",
    "06": "Still Imaging",
    "07": "Printer",
    "08": "Mass Storage",
    "09": "Hub",
    "0a": "CDC Data",
    "0b": "Smart Card",
    "0d": "Content Security",
    "0e": "Video",
    "0f": "Personal Healthcare",
    "10": "Audio/Video",
    "11": "Billboard",
    "12": "USB Type-C Bridge",
    "dc": "Diagnostic",
    "e0": "Wireless",
    "ef": "Miscellaneous",
    "fe": "Application Specific",
    "ff": "Vendor Specific",
}


@dataclass(slots=True)
class PciIds:
    vendors: dict[str, str] = field(default_factory=dict)
    devices: dict[tuple[str, str], str] = field(default_factory=dict)
    source: str | None = None

    @classmethod
    def load(cls, root: Path = Path("/")) -> "PciIds":
        ids = cls()
        ids._load(root)
        return ids

    def _root_path(self, root: Path, path: Path) -> Path:
        if root == Path("/"):
            return path
        return root / path.relative_to("/")

    def _load(self, root: Path) -> None:
        for candidate in PCI_IDS_PATHS:
            path = self._root_path(root, candidate)
            text = read_text(path, max_bytes=16_000_000)
            if text is None:
                continue
            self.source = str(candidate)
            self.parse(text)
            return

    def parse(self, text: str) -> None:
        current_vendor: str | None = None
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            if line.startswith("C "):
                current_vendor = None
                continue
            if line.startswith("\t\t"):
                continue
            if line.startswith("\t"):
                if current_vendor is None:
                    continue
                stripped = line.strip()
                if "  " not in stripped:
                    continue
                device_id, name = stripped.split(None, 1)
                device_id = parse_hex_id(device_id, width=4)
                if device_id and name:
                    self.devices[(current_vendor, device_id)] = name.strip()
                continue
            if line[0].isspace() or "  " not in line:
                continue
            vendor_id, name = line.split(None, 1)
            vendor_id = parse_hex_id(vendor_id, width=4)
            if vendor_id and name:
                current_vendor = vendor_id
                self.vendors[vendor_id] = name.strip()

    def vendor_name(self, vendor_id: str | None) -> str | None:
        return self.vendors.get(vendor_id or "")

    def device_name(self, vendor_id: str | None, device_id: str | None) -> str | None:
        if vendor_id is None or device_id is None:
            return None
        return self.devices.get((vendor_id, device_id))


@dataclass(slots=True)
class UsbIds:
    vendors: dict[str, str] = field(default_factory=dict)
    devices: dict[tuple[str, str], str] = field(default_factory=dict)
    source: str | None = None

    @classmethod
    def load(cls, root: Path = Path("/")) -> "UsbIds":
        ids = cls()
        ids._load(root)
        return ids

    def _root_path(self, root: Path, path: Path) -> Path:
        if root == Path("/"):
            return path
        return root / path.relative_to("/")

    def _load(self, root: Path) -> None:
        for candidate in USB_IDS_PATHS:
            path = self._root_path(root, candidate)
            text = read_text(path, max_bytes=16_000_000)
            if text is None:
                continue
            self.source = str(candidate)
            self.parse(text)
            return

    def parse(self, text: str) -> None:
        current_vendor: str | None = None
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            if line.startswith("C "):
                current_vendor = None
                continue
            if line.startswith("\t\t"):
                continue
            if line.startswith("\t"):
                if current_vendor is None:
                    continue
                stripped = line.strip()
                if "  " not in stripped:
                    continue
                product_id, name = stripped.split(None, 1)
                product_id = parse_hex_id(product_id, width=4)
                if product_id and name:
                    self.devices[(current_vendor, product_id)] = name.strip()
                continue
            if line[0].isspace() or "  " not in line:
                continue
            vendor_id, name = line.split(None, 1)
            vendor_id = parse_hex_id(vendor_id, width=4)
            if vendor_id and name:
                current_vendor = vendor_id
                self.vendors[vendor_id] = name.strip()

    def vendor_name(self, vendor_id: str | None) -> str | None:
        return self.vendors.get(vendor_id or "")

    def device_name(self, vendor_id: str | None, product_id: str | None) -> str | None:
        if vendor_id is None or product_id is None:
            return None
        return self.devices.get((vendor_id, product_id))


@dataclass(slots=True)
class PnpIds:
    vendors: dict[str, str] = field(default_factory=dict)
    source: str | None = None

    @classmethod
    def load(cls, root: Path = Path("/")) -> "PnpIds":
        ids = cls()
        ids._load(root)
        return ids

    def _root_path(self, root: Path, path: Path) -> Path:
        if root == Path("/"):
            return path
        return root / path.relative_to("/")

    def _load(self, root: Path) -> None:
        for candidate in PNP_IDS_PATHS:
            path = self._root_path(root, candidate)
            text = read_text(path, max_bytes=4_000_000)
            if text is None:
                continue
            self.source = str(candidate)
            self.parse(text)
            return

    def parse(self, text: str) -> None:
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            vendor_id, name = parts
            vendor_id = vendor_id.strip().upper()
            if len(vendor_id) == 3 and vendor_id.isalnum() and name.strip():
                self.vendors[vendor_id] = name.strip()

    def vendor_name(self, vendor_id: str | None) -> str | None:
        return self.vendors.get(str(vendor_id or "").upper())


def pci_class_name(class_id: str | None) -> str | None:
    if not class_id:
        return None
    cleaned = class_id.lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) < 2:
        return None
    return PCI_CLASS_NAMES.get(cleaned[:2], f"PCI class 0x{cleaned[:2]}")


def usb_class_name(class_id: str | None) -> str | None:
    cleaned = parse_hex_id(class_id, width=2)
    if cleaned is None:
        return None
    return USB_CLASS_NAMES.get(cleaned, f"USB class 0x{cleaned}")
