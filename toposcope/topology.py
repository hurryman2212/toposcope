from __future__ import annotations

import re

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import human_bytes, natural_key, parse_int

PCI_DOMAIN_PATTERN = re.compile(r"^pci[0-9a-fA-F]{4}:[0-9a-fA-F]{2}$")
PCI_SLOT_PATTERN = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
PCI_SLOT_ADDRESS_PATTERN = re.compile(
    r"^([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])$"
)
USB_ROOT_PATTERN = re.compile(r"^usb\d+$")
USB_DEVICE_PATTERN = re.compile(r"^\d+(?:-\d+(?:\.\d+)*)?$")
I2C_BUS_PATTERN = re.compile(r"^i2c-\d+$")
I2C_DEVICE_PATTERN = re.compile(r"^\d+-[0-9a-fA-F]{4}$")
SPI_BUS_PATTERN = re.compile(r"^spi\d+$")
SPI_DEVICE_PATTERN = re.compile(r"^spi\d+\.\d+$")
ACPI_MODALIAS_PATTERN = re.compile(r"^acpi:([^:]+)", re.IGNORECASE)
ACPI_INSTANCE_PATTERN = re.compile(r"^[A-Z0-9]{3,12}:\d+$")
NETWORK_VF_PORT_PATTERN = re.compile(r"^(?:pf\d+)?vf\d+$", re.IGNORECASE)
NETWORK_PHYSICAL_PORT_PATTERN = re.compile(r"^p(\d+)$", re.IGNORECASE)
NETWORK_MODE_SPEED_PATTERN = re.compile(r"^(\d+)base", re.IGNORECASE)
DRM_CONNECTOR_PREFIX_PATTERN = re.compile(r"^card\d+-")
DISPLAY_MODE_PATTERN = re.compile(r"^(\d+)x(\d+)(?:@(\d+(?:\.\d+)?)Hz)?$")


ACPI_HID_LABELS = {
    "ACPI000C": "Processor Aggregator",
    "ACPI0017": "Non-Volatile Memory Device",
    "INT33A1": "Power Engine Plugin",
    "LNXPWRBN": "Power Button",
    "MSFT0101": "Trusted Platform Module",
    "PNP0103": "High Precision Event Timer",
    "PNP0303": "Keyboard Controller",
    "PNP0501": "Serial Port",
    "PNP0800": "PC Speaker",
    "PNP0A03": "PCI Bus",
    "PNP0A08": "PCI Express Bus",
    "PNP0B00": "Real Time Clock",
    "PNP0C02": "Motherboard Resources",
    "PNP0C04": "Math Coprocessor",
    "PNP0C09": "Embedded Controller",
    "PNP0C0A": "Control Method Battery",
    "PNP0C0B": "Fan",
    "PNP0C0C": "Power Button",
    "PNP0C0D": "Lid Switch",
    "PNP0C0E": "Sleep Button",
    "PNP0C14": "WMI Controller",
}

PLATFORM_DRIVER_LABELS = {
    "acpi-ec": "Embedded Controller",
    "gpio-amdpt": "GPIO Controller",
    "gpio_amdpt": "GPIO Controller",
    "gpio-amd-fch": "GPIO Controller",
    "pcspkr": "PC Speaker",
}

PLATFORM_DRIVER_PATTERNS = (
    ("gpio", "GPIO Controller"),
    ("i2c", "I2C Controller"),
    ("spi", "SPI Controller"),
    ("wmi", "WMI Controller"),
    ("tpm", "Trusted Platform Module"),
)


KIND_ORDER = {
    "cpu": 0,
    "numa": 5,
    "memory-controller": 10,
    "dimm": 11,
    "pcie-fabric": 20,
    "pcie-endpoint": 23,
    "usb-root": 30,
    "usb-hub": 31,
    "usb-device": 32,
    "storage-controller": 40,
    "block-device": 41,
    "partition": 42,
    "network-interface": 50,
    "network-port": 51,
    "bluetooth-adapter": 52,
    "graphics-device": 60,
    "display-connector": 61,
    "display-device": 62,
    "sound-card": 63,
    "audio-port": 64,
    "audio-stream-port": 65,
    "audio-device": 66,
    "platform-bus": 70,
    "platform-device": 71,
    "i2c-bus": 80,
    "i2c-device": 81,
    "spi-bus": 82,
    "spi-device": 83,
    "serio-bus": 92,
    "serio-device": 93,
    "resource": 94,
    "sensor-device": 100,
    "power-device": 101,
    "thermal-device": 102,
    "other": 999,
}


@dataclass
class TopologyNode:
    id: str
    label: str
    kind: str
    details: list[str] = field(default_factory=list)
    path: str | None = None
    children: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    incoming_label: str | None = None


class TopologyBuilder:
    def __init__(self, report: dict[str, Any]) -> None:
        self.report = report
        self.nodes: dict[str, TopologyNode] = {}
        self.path_to_id: dict[str, str] = {}
        self.parent_by_id: dict[str, str] = {}
        self.pci_root_complex_by_domain: dict[str, str] = {}
        self.hidden_pci_bridge_slots: set[str] = set()
        self.hidden_pci_bridge_by_slot: dict[str, dict[str, Any]] = {}
        self.root_id = "topology:root"
        self.cpu_root_ids: list[str] = []
        self.cpu_root_ids_by_numa: dict[int, str] = {}

    def build(self) -> dict[str, Any]:
        self.add_cpu_roots()
        self.add_memory()
        self.add_platform_bus()
        self.add_pci()
        self.reparent_pci_attached_platform_devices()
        self.add_usb()
        self.add_expansion_ports()
        self.add_simple_bus("i2c")
        self.add_simple_bus("spi")
        self.add_simple_bus("serio")
        self.add_platform_kernel_interfaces()
        self.reparent_acpi_resource_backed_platform_devices()
        self.add_sensors()
        self.add_power()
        self.add_thermal()
        self.remove_duplicate_platform_kernel_devices()
        self.clone_test_numa_device_trees()
        self.prune_unreachable()
        self.sort_children()
        return {
            "root": self.to_tree(self.root_id),
            "nodes": [self.node_to_dict(node) for node in self.nodes.values()],
            "edges": [
                {
                    "parent": parent,
                    "child": child,
                    "label": self.nodes[child].incoming_label,
                }
                for child, parent in sorted(
                    self.parent_by_id.items(), key=lambda item: item[0]
                )
            ],
            "summary": {
                "node_count": len(self.nodes),
                "edge_count": len(self.parent_by_id),
                "strategy": "sysfs ancestor topology; endpoints attach to their nearest collected parent device",
            },
        }

    def add_cpu_roots(self) -> None:
        self.add_node(
            self.root_id, "Topology", "topology-root", metadata={"hidden": True}
        )
        cpu = self.report.get("cpu", {})
        memory = self.report.get("memory", {})
        summary = cpu.get("summary", {})
        models = summary.get("models") or {}
        model = next(iter(models.keys()), "CPU / SoC")
        numa_nodes = sorted(
            self.report.get("cpu", {}).get("numa", {}).get("nodes", []),
            key=lambda node: numa_sort_key(node.get("node")),
        )
        if not numa_nodes:
            node_id = "cpu:root"
            details = [
                detail("Model", model),
                detail("Logical CPUs", summary.get("logical_processors")),
                detail("Cores", summary.get("cores")),
                detail("RAM", memory.get("summary", {}).get("total_human")),
            ]
            self.add_node(
                node_id,
                self.hardware_label(model, fallback="Processor"),
                "cpu",
                details,
            )
            self.add_cpu_root(node_id, None)
            return

        show_numa_label = len(numa_nodes) > 1
        cpu_label = self.hardware_label(model, fallback="Processor")
        for fallback_index, node in enumerate(numa_nodes):
            node_index = normalize_numa_index(node.get("node"))
            node_suffix = node_index if node_index is not None else fallback_index
            node_id = f"cpu:numa:{node_suffix}"
            mem_total = node.get("meminfo", {}).get("MemTotal")
            self.add_node(
                node_id,
                cpu_node_label(cpu_label, node_index if show_numa_label else None),
                "cpu",
                [
                    detail("Model", model),
                    detail("NUMA", node_index),
                    detail("CPUs", node.get("cpulist")),
                    detail("Cores", summary.get("cores")),
                    detail(
                        "RAM",
                        human_bytes(mem_total) if isinstance(mem_total, int) else None,
                    ),
                ],
            )
            self.add_cpu_root(node_id, node_index)

    def add_cpu_root(self, node_id: str, node_index: int | None) -> None:
        if node_id not in self.cpu_root_ids:
            self.cpu_root_ids.append(node_id)
        if node_index is not None:
            self.cpu_root_ids_by_numa.setdefault(node_index, node_id)
        self.add_edge(self.root_id, node_id, "")

    def primary_cpu_root_id(self) -> str:
        return self.cpu_root_ids[0] if self.cpu_root_ids else self.root_id

    def should_show_addresses(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_addr"))

    def should_show_vendor_names(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_vendor"))

    def should_show_network_devices(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_net_dev"))

    def should_show_network_status(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_net_status"))

    def should_show_wifi_devices(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_wifi"))

    def should_show_bluetooth_devices(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_bluetooth"))

    def should_show_display_devices(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_display"))

    def should_show_display_status(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_display_status"))

    def should_show_audio_jacks(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_audio_jack"))

    def should_read_sensor_values(self) -> bool:
        return bool((self.report.get("options") or {}).get("read_sensors"))

    def should_show_sensors(self) -> bool:
        return not bool((self.report.get("options") or {}).get("no_sensors"))

    def label_with_addr(self, address: Any, label: str) -> str:
        return (
            label_with_address(address, label)
            if self.should_show_addresses()
            else label
        )

    def hardware_label(
        self, *candidates: Any, vendor: Any = None, fallback: str = "Unknown device"
    ) -> str:
        label = raw_hardware_label(*candidates, fallback=fallback)
        if self.should_show_vendor_names():
            return label_with_vendor(vendor, label)
        return strip_company_name(label, vendor) or label

    def cpu_root_id_for_numa(self, node_index: Any) -> str:
        if self.is_test_numa():
            return self.primary_cpu_root_id()
        normalized = normalize_numa_index(node_index)
        if normalized is not None and normalized >= 0:
            node_id = self.cpu_root_ids_by_numa.get(normalized)
            if node_id:
                return node_id
        return self.primary_cpu_root_id()

    def is_cpu_root(self, node_id: str | None) -> bool:
        return bool(node_id and node_id in self.cpu_root_ids)

    def is_test_numa(self) -> bool:
        try:
            return int(self.report.get("debug", {}).get("test_numa")) > 0
        except (TypeError, ValueError):
            return False

    def clone_test_numa_device_trees(self) -> None:
        if not self.is_test_numa() or len(self.cpu_root_ids) < 2:
            return
        source_cpu = self.primary_cpu_root_id()
        if source_cpu not in self.nodes:
            return
        source_children = list(self.nodes[source_cpu].children)
        for target_cpu in self.cpu_root_ids[1:]:
            if target_cpu not in self.nodes:
                continue
            for child_id in list(self.nodes[target_cpu].children):
                self.remove_subtree(child_id)
            self.nodes[target_cpu].children = []
            for child_id in source_children:
                clone_id = self.clone_subtree_for_cpu(child_id, target_cpu)
                self.add_edge(
                    target_cpu, clone_id, self.nodes[child_id].incoming_label or ""
                )

    def clone_subtree_for_cpu(self, source_id: str, target_cpu: str) -> str:
        source = self.nodes[source_id]
        clone_id = f"{source_id}@{target_cpu}"
        self.nodes[clone_id] = TopologyNode(
            clone_id,
            source.label,
            source.kind,
            list(source.details),
            source.path,
            metadata=dict(source.metadata),
        )
        self.nodes[clone_id].incoming_label = source.incoming_label
        for child_id in source.children:
            cloned_child_id = self.clone_subtree_for_cpu(child_id, target_cpu)
            self.nodes[clone_id].children.append(cloned_child_id)
            self.parent_by_id[cloned_child_id] = clone_id
            self.nodes[cloned_child_id].incoming_label = self.nodes[
                child_id
            ].incoming_label
        return clone_id

    def remove_subtree(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node is None:
            return
        for child_id in list(node.children):
            self.remove_subtree(child_id)
        self.remove_node(node_id)

    def add_memory(self) -> None:
        memory = self.report.get("memory", {})
        dmi_slots = [
            slot
            for slot in memory.get("dmi_memory_devices", [])
            if slot.get("populated")
        ]
        if dmi_slots:
            controller_id = "memory:slots"
            self.add_node(
                controller_id,
                "Memory Controller",
                "memory-controller",
                [
                    detail("Slots", len(dmi_slots)),
                    detail("Total", memory.get("summary", {}).get("total_human")),
                ],
            )
            self.add_edge(self.primary_cpu_root_id(), controller_id, "")
            for slot in sorted(
                dmi_slots, key=lambda item: natural_key(memory_slot_label(item))
            ):
                slot_label = memory_slot_label(
                    slot, show_vendor=self.should_show_vendor_names()
                )
                slot_id = f"dimm:{slot.get('entry') or slot_label}"
                self.add_node(
                    slot_id,
                    slot_label,
                    "dimm",
                    [
                        detail("Size", slot.get("size_human")),
                        detail("Type", slot.get("memory_type")),
                        detail(
                            "Speed",
                            suffix(
                                slot.get("configured_speed_mt_s")
                                or slot.get("speed_mt_s"),
                                "MT/s",
                            ),
                        ),
                        detail("Part", slot.get("part_number")),
                    ],
                    path=slot.get("sysfs_path"),
                    metadata={
                        "memory_type": slot.get("memory_type"),
                        "configured_speed_mt_s": slot.get("configured_speed_mt_s"),
                        "speed_mt_s": slot.get("speed_mt_s"),
                        "size_bytes": slot.get("size_bytes"),
                        "ecc": slot.get("ecc"),
                    },
                )
                self.add_edge(controller_id, slot_id)
            return

        edac = memory.get("edac", [])
        if not edac:
            controller_id = "memory:system"
            summary = memory.get("summary", {})
            self.add_node(
                controller_id,
                "Memory controller",
                "memory-controller",
                [
                    detail("Total", summary.get("total_human")),
                    detail("Blocks", summary.get("memory_blocks")),
                ],
            )
            self.add_edge(self.primary_cpu_root_id(), controller_id, "")
            return

        for controller in edac:
            controller_id = f"memory-controller:{controller.get('name')}"
            self.add_node(
                controller_id,
                self.hardware_label(
                    controller.get("mc_name")
                    or f"Memory controller {controller.get('name')}",
                    fallback="Memory controller",
                ),
                "memory-controller",
                [
                    detail("Name", controller.get("mc_name")),
                    detail(
                        "Size",
                        (
                            f"{controller.get('size_mb')} MiB"
                            if controller.get("size_mb")
                            else None
                        ),
                    ),
                    detail("CE", controller.get("ce_count")),
                    detail("UE", controller.get("ue_count")),
                ],
                path=controller.get("physical_path") or controller.get("sysfs_path"),
            )
            self.add_edge(self.primary_cpu_root_id(), controller_id, "")

            dimms = controller.get("dimms") or []
            if not dimms:
                continue
            for dimm in dimms:
                label = dimm.get("label") or dimm.get("location") or dimm.get("name")
                dimm_id = f"dimm:{controller.get('name')}:{dimm.get('name')}"
                self.add_node(
                    dimm_id,
                    self.label_with_addr(
                        label or dimm.get("name"),
                        self.hardware_label(label or "DIMM", fallback="DIMM"),
                    ),
                    "dimm",
                    [
                        detail("Slot", dimm.get("location")),
                        detail(
                            "Size",
                            (
                                f"{dimm.get('size_mb')} MiB"
                                if dimm.get("size_mb")
                                else None
                            ),
                        ),
                        detail("Type", dimm.get("mem_type") or dimm.get("dev_type")),
                        detail("EDAC", dimm.get("edac_mode")),
                    ],
                    path=dimm.get("physical_path") or dimm.get("sysfs_path"),
                )
                self.add_edge(controller_id, dimm_id, "DIMM channel")

    def add_platform_bus(self) -> None:
        self.add_node("bus:platform", "ACPI", "platform-bus")
        self.add_edge(self.primary_cpu_root_id(), "bus:platform", "")
        for device in (
            self.report.get("buses", {}).get("platform", {}).get("devices", [])
        ):
            name = device.get("name")
            if not name:
                continue
            path = device.get("physical_path")
            node_id = f"platform:{name}"
            self.add_node(
                node_id,
                self.platform_device_label(device),
                "platform-device",
                [
                    detail("Driver", device.get("driver")),
                    detail("Modalias", device.get("modalias")),
                ],
                path=path,
                metadata={
                    "bus": "platform",
                    "platform_name": name,
                    "modalias": device.get("modalias"),
                    "driver": device.get("driver"),
                    "subsystem": device.get("subsystem"),
                    "firmware_node_path": device.get("firmware_node_path"),
                    "physical_node_paths": device.get("physical_node_paths") or [],
                    "hardware_identity": platform_hardware_identity(device),
                },
            )
            parent = self.find_parent_by_path(path, self_id=node_id) or "bus:platform"
            if self.is_cpu_root(parent):
                parent = "bus:platform"
            self.add_edge(parent, node_id)

    def platform_device_label(self, device: dict[str, Any]) -> str:
        name = device.get("name")
        if not is_acpi_platform_device(name, device.get("modalias")):
            return str(name or "").strip() or "Platform device"
        label = platform_hardware_label(device)
        return self.label_with_addr(
            platform_display_address(name, device.get("modalias")), label
        )

    def reparent_pci_attached_platform_devices(self) -> None:
        for node_id, node in list(self.nodes.items()):
            if node.kind != "platform-device" or not path_has_pci_slot(node.path):
                continue
            parent = self.find_parent_by_path(node.path, self_id=node_id)
            if not parent or parent not in self.nodes:
                continue
            if self.nodes[parent].kind not in {"pcie-fabric", "pcie-endpoint"}:
                continue
            self.add_edge(
                parent, node_id, self.pci_attached_platform_edge_label(parent, node_id)
            )

    def pci_attached_platform_edge_label(self, parent_id: str, child_id: str) -> str:
        return self.platform_edge_label(parent_id, child_id)

    def platform_edge_label(self, parent_id: str, child_id: str) -> str:
        parent = self.nodes.get(parent_id)
        child = self.nodes.get(child_id)
        if parent is None or child is None:
            return ""
        if parent.kind in {"pcie-fabric", "pcie-endpoint"}:
            label = platform_physical_bus_label(parent, child)
            if label:
                return label
        return self.resource_access_label_for_node(child)

    def resource_access_label_for_node(self, node: TopologyNode) -> str:
        resource_kinds = {
            str(resource.get("kind") or "")
            for resource in self.direct_resources_for_node(node)
            if resource.get("kind")
        }
        if resource_kinds == {"iomem"}:
            return "MMIO"
        if resource_kinds == {"ioport"}:
            return "I/O port"
        if resource_kinds == {"iomem", "ioport"}:
            return "MMIO / I/O port"
        return ""

    def direct_resources_for_node(self, node: TopologyNode) -> list[dict[str, Any]]:
        candidates = resource_owner_candidates_for_node(node)
        if not candidates:
            return []
        return [
            resource
            for resource in self.iter_system_resources()
            if normalize_resource_owner(resource.get("owner")) in candidates
        ]

    def remove_duplicate_platform_kernel_devices(self) -> None:
        physical_by_identity: dict[str, list[str]] = {}
        for node_id, node in self.nodes.items():
            if node.kind != "platform-device":
                continue
            if not self.is_firmware_backed_platform_device(node):
                continue
            identity = platform_node_hardware_identity(node)
            if identity:
                physical_by_identity.setdefault(identity, []).append(node_id)

        for node_id, node in list(self.nodes.items()):
            if node.kind != "platform-device":
                continue
            if not self.is_kernel_platform_interface_device(node):
                continue
            identity = platform_node_hardware_identity(node)
            candidates = [
                candidate
                for candidate in physical_by_identity.get(identity, [])
                if candidate != node_id
            ]
            if not candidates:
                continue
            target_id = min(candidates, key=self.platform_duplicate_target_sort_key)
            self.merge_duplicate_node_into_target(node_id, target_id)

    def is_firmware_backed_platform_device(self, node: TopologyNode) -> bool:
        modalias = str(node.metadata.get("modalias") or "")
        return bool(
            ACPI_MODALIAS_PATTERN.match(modalias)
            or node.metadata.get("firmware_node_path")
            or node.metadata.get("physical_node_paths")
        )

    def is_kernel_platform_interface_device(self, node: TopologyNode) -> bool:
        modalias = str(node.metadata.get("modalias") or "")
        if not modalias.startswith("platform:"):
            return False
        if node.metadata.get("firmware_node_path") or node.metadata.get(
            "physical_node_paths"
        ):
            return False
        return is_direct_platform_device_path(node.path)

    def platform_duplicate_target_sort_key(
        self, node_id: str
    ) -> tuple[int, list[tuple[int, int | str]], str]:
        node = self.nodes[node_id]
        parent = self.nodes.get(self.parent_by_id.get(node_id, ""))
        parent_is_physical_bus = bool(
            parent and parent.kind in {"pcie-fabric", "pcie-endpoint"}
        )
        return (
            0 if parent_is_physical_bus else 1,
            natural_key(node.path or node.id),
            node_id,
        )

    def merge_duplicate_node_into_target(
        self, duplicate_id: str, target_id: str
    ) -> None:
        duplicate = self.nodes.get(duplicate_id)
        if duplicate is None or target_id not in self.nodes:
            return
        for child_id in list(duplicate.children):
            if child_id in self.nodes:
                self.add_edge(
                    target_id, child_id, self.nodes[child_id].incoming_label or ""
                )
        self.remove_node(duplicate_id)

    def reparent_acpi_resource_backed_platform_devices(self) -> None:
        acpi_by_name, acpi_by_path = self.acpi_indexes()
        if not acpi_by_name or not acpi_by_path:
            return
        for node_id, node in list(self.nodes.items()):
            if node.kind != "platform-device":
                continue
            if not self.is_kernel_platform_interface_device(node):
                continue
            match = self.resource_match_for_platform_node(node, acpi_by_name)
            if match is None:
                continue
            acpi_device = acpi_by_name.get(str(match.get("acpi_owner") or ""))
            if acpi_device is None:
                continue
            root_device = self.closest_physical_acpi_ancestor(acpi_device, acpi_by_path)
            if root_device is None:
                continue
            parent_id = self.acpi_physical_parent_id(root_device)
            if not parent_id:
                continue
            root_id = self.ensure_acpi_namespace_node(root_device, parent_id)
            owner_parent_id = self.ensure_acpi_path_between(
                root_device, acpi_device, acpi_by_path, root_id
            )
            resource_id = self.ensure_resource_node(match, owner_parent_id, node)
            self.add_edge(resource_id, node_id, "")

    def acpi_indexes(
        self,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        by_name: dict[str, dict[str, Any]] = {}
        by_path: dict[str, dict[str, Any]] = {}
        for device in self.report.get("acpi", {}).get("devices", []):
            name = str(device.get("name") or "").strip()
            acpi_path = normalize_acpi_path(device.get("acpi_path"))
            if name:
                by_name[name] = device
            if acpi_path:
                by_path[acpi_path] = device
        return by_name, by_path

    def resource_match_for_platform_node(
        self,
        node: TopologyNode,
        acpi_by_name: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        candidates = platform_resource_owner_candidates(node)
        if not candidates:
            return None
        matches: list[dict[str, Any]] = []
        for resource in self.iter_system_resources():
            if normalize_resource_owner(resource.get("owner")) not in candidates:
                continue
            acpi_owner = nearest_acpi_resource_owner(resource, acpi_by_name)
            if not acpi_owner:
                continue
            matches.append({**resource, "acpi_owner": acpi_owner})
        if not matches:
            return None
        return min(matches, key=resource_match_sort_key)

    def iter_system_resources(self) -> list[dict[str, Any]]:
        resources = self.report.get("resources", {})
        return list(resources.get("ioports") or []) + list(resources.get("iomem") or [])

    def closest_physical_acpi_ancestor(
        self,
        acpi_device: dict[str, Any],
        acpi_by_path: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        acpi_path = normalize_acpi_path(acpi_device.get("acpi_path"))
        for prefix in reversed(acpi_path_prefixes(acpi_path)):
            candidate = acpi_by_path.get(prefix)
            if candidate and self.acpi_physical_parent_id(candidate):
                return candidate
        return None

    def acpi_physical_parent_id(self, acpi_device: dict[str, Any]) -> str | None:
        for physical_path in acpi_device.get("physical_node_paths") or []:
            parent_id = self.find_parent_by_path(physical_path)
            if parent_id and parent_id in self.nodes:
                if self.nodes[parent_id].kind in {
                    "pcie-fabric",
                    "pcie-endpoint",
                    "cpu",
                }:
                    return parent_id
                grandparent_id = self.parent_by_id.get(parent_id)
                if grandparent_id and grandparent_id in self.nodes:
                    return grandparent_id
        return None

    def ensure_acpi_path_between(
        self,
        root_device: dict[str, Any],
        target_device: dict[str, Any],
        acpi_by_path: dict[str, dict[str, Any]],
        root_id: str,
    ) -> str:
        root_path = normalize_acpi_path(root_device.get("acpi_path"))
        target_path = normalize_acpi_path(target_device.get("acpi_path"))
        parent_id = root_id
        for prefix in acpi_path_prefixes_between(root_path, target_path):
            device = acpi_by_path.get(prefix)
            if device is None:
                continue
            parent_id = self.ensure_acpi_namespace_node(device, parent_id)
        if (
            normalize_acpi_path(self.nodes[parent_id].metadata.get("acpi_path"))
            != target_path
        ):
            parent_id = self.ensure_acpi_namespace_node(target_device, parent_id)
        return parent_id

    def ensure_acpi_namespace_node(
        self, acpi_device: dict[str, Any], parent_id: str
    ) -> str:
        node_id = acpi_node_id(acpi_device)
        self.add_node(
            node_id,
            acpi_node_label(acpi_device),
            "platform-device",
            [
                detail("ACPI", acpi_device.get("acpi_path")),
                detail("HID", acpi_device.get("hid")),
            ],
            path=acpi_device.get("physical_path"),
            metadata={
                "bus": "acpi",
                "acpi_name": acpi_device.get("name"),
                "acpi_path": normalize_acpi_path(acpi_device.get("acpi_path")),
                "modalias": acpi_device.get("modalias"),
                "firmware_node_path": acpi_device.get("firmware_node_path"),
                "physical_node_paths": acpi_device.get("physical_node_paths") or [],
            },
        )
        self.add_edge(parent_id, node_id)
        return node_id

    def ensure_resource_node(
        self, resource: dict[str, Any], parent_id: str, platform_node: TopologyNode
    ) -> str:
        node_id = resource_node_id(resource, platform_node)
        self.add_node(
            node_id,
            resource_node_label(resource, platform_node),
            "resource",
            [
                detail("Owner", resource.get("owner")),
                detail("Parent", resource.get("parent_owner")),
            ],
            metadata={
                "resource_kind": resource.get("kind"),
                "resource_owner": resource.get("owner"),
                "resource_start": resource.get("start"),
                "resource_end": resource.get("end"),
            },
        )
        self.add_edge(parent_id, node_id, resource_edge_label(resource))
        return node_id

    def add_pci(self) -> None:
        devices = self.report.get("pci", {}).get("devices", [])
        if not devices:
            return
        self.pci_root_complex_by_domain = pci_root_complex_by_domain(devices)
        hide_pci_bridges = self.should_hide_pci_bridges()
        self.hidden_pci_bridge_by_slot = {}
        if hide_pci_bridges:
            self.hidden_pci_bridge_by_slot = {
                str(device.get("slot")): device
                for device in devices
                if device.get("slot") and self.is_pci_to_pci_bridge_device(device)
            }
        self.hidden_pci_bridge_slots = set(self.hidden_pci_bridge_by_slot)

        for device in sorted(
            devices, key=lambda item: path_depth(item.get("physical_path"))
        ):
            slot = device.get("slot")
            if not slot:
                continue
            path = device.get("physical_path")
            node_id = f"pci:{slot}"
            is_pci_bridge = self.is_pci_to_pci_bridge_device(device)
            if (
                hide_pci_bridges
                and is_pci_bridge
                and not self.is_pci_root_complex_slot(path, slot)
            ):
                continue
            kind = (
                "pcie-fabric"
                if self.is_pci_root_complex_slot(path, slot) or is_pci_bridge
                else "pcie-endpoint"
            )
            name = device.get("device_name") or device.get("class_name") or "PCI device"
            iommu_group = normalize_iommu_group(device.get("iommu_group"))
            label = pci_label_with_iommu_group(
                self.hardware_label(
                    name, vendor=device.get("vendor_name"), fallback="PCI device"
                ),
                iommu_group,
            )
            self.add_node(
                node_id,
                self.label_with_addr(short_pci_address(slot), label),
                kind,
                [
                    detail("Class", device.get("class_name")),
                    detail("Vendor", device.get("vendor_name")),
                    detail("Driver", device.get("driver")),
                    detail("NUMA", device.get("numa_node")),
                ],
                path=path,
                metadata={
                    "bus": "pcie",
                    **pcie_device_link_metadata(device),
                    "pci_bridge": is_pci_bridge,
                    "pci_class_id": device.get("class_id"),
                    "pci_vendor_id": device.get("vendor_id"),
                    "pci_device_id": device.get("device_id"),
                    "pci_subsystem_vendor_id": device.get("subsystem_vendor_id"),
                    "pci_subsystem_device_id": device.get("subsystem_device_id"),
                    "pci_slot": slot,
                    "iommu_group": iommu_group,
                },
            )

        for device in sorted(
            devices, key=lambda item: path_depth(item.get("physical_path"))
        ):
            slot = device.get("slot")
            if not slot:
                continue
            path = device.get("physical_path")
            if (
                hide_pci_bridges
                and self.is_pci_to_pci_bridge_device(device)
                and not self.is_pci_root_complex_slot(path, slot)
            ):
                continue
            node_id = f"pci:{slot}"
            parent = self.find_pci_parent(path, slot) or self.cpu_root_id_for_numa(
                device.get("numa_node")
            )
            edge_label = (
                ""
                if self.is_cpu_root(parent)
                and self.is_pci_root_complex_slot(path, slot)
                else None
            )
            hidden_bridge_slots = self.hidden_pci_bridge_slots_between(
                path, slot, parent
            )
            self.nodes[node_id].metadata["behind_hidden_pci_bridge"] = bool(
                hidden_bridge_slots
            )
            if hidden_bridge_slots:
                group_slot, bridge_label = self.representative_hidden_pci_bridge_link(
                    hidden_bridge_slots
                )
                self.nodes[node_id].metadata["hidden_pci_bridge_group"] = group_slot
                self.nodes[node_id].metadata["hidden_pci_bridge_label"] = bridge_label
                self.nodes[node_id].metadata["hidden_pci_bridge_sort_slot"] = (
                    hidden_bridge_slots[0]
                )
                edge_label = bridge_label
            self.add_edge(parent, node_id, edge_label)

    def should_hide_pci_bridges(self) -> bool:
        return bool((self.report.get("options") or {}).get("no_pci_bridge"))

    def add_usb(self) -> None:
        devices = self.report.get("usb", {}).get("devices", [])
        if not devices:
            return
        for device in sorted(
            devices, key=lambda item: path_depth(item.get("physical_path"))
        ):
            name = device.get("name")
            if not name:
                continue
            path = device.get("physical_path")
            vendor = device.get("vendor_name") or device.get("manufacturer")
            product = strip_company_name(
                device.get("product"),
                vendor,
                device.get("manufacturer"),
                device.get("vendor_name"),
            )
            class_name = device.get("device_class_name")
            is_root = bool(USB_ROOT_PATTERN.match(name))
            is_hub = is_root or class_name == "Hub" or bool(device.get("max_children"))
            kind = "usb-root" if is_root else ("usb-hub" if is_hub else "usb-device")
            if is_root:
                label = usb_root_hub_label(device)
            else:
                fallback = (
                    "Hub"
                    if is_hub
                    else (class_name if class_name and class_name != "Device" else name)
                )
                label = raw_hardware_label(
                    device.get("product_name_from_ids"),
                    product,
                    fallback=fallback,
                )
                if self.should_show_vendor_names():
                    label = label_with_vendor(vendor, label)
            node_id = f"usb:{name}"
            self.add_node(
                node_id,
                self.label_with_addr(name, label),
                kind,
                [
                    detail("Class", class_name),
                    detail(
                        "Vendor",
                        device.get("manufacturer") or device.get("vendor_name"),
                    ),
                    detail("Speed", suffix(device.get("speed_mbps"), "Mb/s")),
                    detail("Driver", device.get("driver")),
                ],
                path=path,
                metadata={
                    "bus": "usb",
                    "usb_version": device.get("usb_version"),
                    "speed_mbps": device.get("speed_mbps"),
                },
            )
            parent = self.find_parent_by_path(path, self_id=node_id)
            if (
                parent is None
                and is_platform_path(path)
                and "bus:platform" in self.nodes
            ):
                parent = "bus:platform"
            if parent:
                self.add_edge(parent, node_id)

    def add_platform_kernel_interfaces(self) -> None:
        self.add_storage(platform_only=True)
        self.add_network(platform_only=True)
        self.add_graphics(platform_only=True)
        self.add_sound(platform_only=True)

    def add_expansion_ports(self) -> None:
        if self.should_show_network_devices() or self.should_show_wifi_devices():
            self.add_network_ports()
        if self.should_show_network_devices():
            self.add_infiniband_ports()
        if self.should_show_bluetooth_devices():
            self.add_bluetooth_adapters()
        self.add_display_ports()
        self.add_audio_ports()

    def add_network_ports(self) -> None:
        for interface in self.report.get("network", {}).get("interfaces", []):
            name = interface.get("name")
            if not name or not should_show_network_port(interface):
                continue
            if interface.get("is_wireless"):
                if not self.should_show_wifi_devices():
                    continue
            elif not self.should_show_network_devices():
                continue
            if interface.get(
                "kind"
            ) == "infiniband" and self.has_infiniband_port_for_device(
                interface.get("device_path")
            ):
                continue
            node_id = f"net-port:{name}"
            parent = self.platform_aware_parent(
                interface.get("device_path"), self_id=node_id
            )
            if not parent:
                continue
            self.add_node(
                node_id,
                network_port_label(
                    interface, show_status=self.should_show_network_status()
                ),
                "network-port",
                [
                    detail("Interface", name),
                    detail("MAC", interface.get("mac_address")),
                    detail("State", interface.get("operstate")),
                    detail("Driver", interface.get("driver")),
                ],
                metadata={
                    "network_kind": interface.get("kind"),
                    "port_type": interface.get("port_type"),
                    "phys_port_name": interface.get("phys_port_name"),
                    "dev_port": interface.get("dev_port"),
                },
            )
            self.add_edge(parent, node_id, network_port_edge_label(interface))

    def add_infiniband_ports(self) -> None:
        for port in self.report.get("network", {}).get("infiniband_ports", []):
            if not should_show_infiniband_port(port):
                continue
            node_id = infiniband_port_node_id(port)
            parent = self.platform_aware_parent(
                port.get("device_path"), self_id=node_id
            )
            if not parent:
                continue
            self.add_node(
                node_id,
                infiniband_port_label(
                    port, show_status=self.should_show_network_status()
                ),
                "network-port",
                [
                    detail("HCA", port.get("hca")),
                    detail("State", port.get("state")),
                    detail("Physical state", port.get("physical_state")),
                    detail("Rate", port.get("rate")),
                    detail("LID", port.get("lid")),
                    detail("Node GUID", port.get("node_guid")),
                ],
                path=port.get("physical_path"),
                metadata={
                    "network_kind": "infiniband",
                    "hca": port.get("hca"),
                    "port": port.get("port"),
                    "link_layer": port.get("link_layer"),
                    "rate": port.get("rate"),
                },
            )
            self.add_edge(parent, node_id, infiniband_port_edge_label(port))

    def has_infiniband_port_for_device(self, device_path: str | None) -> bool:
        normalized_device_path = normalize_path(device_path)
        if not normalized_device_path:
            return False
        for port in self.report.get("network", {}).get("infiniband_ports", []):
            if not should_show_infiniband_port(port):
                continue
            if normalize_path(port.get("device_path")) == normalized_device_path:
                return True
        return False

    def add_bluetooth_adapters(self) -> None:
        for adapter in self.report.get("bluetooth", {}).get("adapters", []):
            name = adapter.get("name")
            if not name:
                continue
            node_id = f"bluetooth:{safe_node_id(name)}"
            path = adapter.get("device_path") or adapter.get("physical_path")
            parent = self.platform_aware_parent(path, self_id=node_id)
            if not parent:
                continue
            self.add_node(
                node_id,
                bluetooth_adapter_label(adapter),
                "bluetooth-adapter",
                [
                    detail("Interface", name),
                    detail("Address", adapter.get("address")),
                    detail("Version", adapter.get("bluetooth_version")),
                    detail(
                        "Supported",
                        join_nonempty(*(adapter.get("supported_settings") or [])),
                    ),
                    detail(
                        "Current",
                        join_nonempty(*(adapter.get("current_settings") or [])),
                    ),
                    detail("Driver", adapter.get("driver")),
                ],
                path=adapter.get("physical_path"),
                metadata={
                    "bluetooth": True,
                    "bluetooth_index": adapter.get("index"),
                    "bluetooth_version": adapter.get("bluetooth_version"),
                },
            )
            self.add_edge(parent, node_id, "Bluetooth")

    def add_display_ports(self) -> None:
        for connector in self.report.get("graphics", {}).get("connectors", []):
            name = connector.get("name")
            if not name or not should_show_display_connector(connector):
                continue
            node_id = f"display-port:{name}"
            path = connector.get("physical_path") or connector.get("device_path")
            parent = self.platform_aware_parent(path, self_id=node_id)
            if not parent:
                continue
            modes = connector.get("modes") or []
            self.add_node(
                node_id,
                display_connector_label(name),
                "display-connector",
                [
                    detail("Status", connector.get("status")),
                    detail("Enabled", connector.get("enabled")),
                    detail("Mode", modes[0] if modes else None),
                ],
                path=path,
                metadata={"connector_type": display_connector_type(name)},
            )
            self.add_edge(parent, node_id, display_connector_edge_label(name))
            if self.should_show_display_devices():
                self.add_connected_display(connector, node_id)

    def add_connected_display(
        self, connector: dict[str, Any], connector_id: str
    ) -> None:
        if connector.get("status") != "connected":
            return
        name = connector.get("name")
        if not name:
            return
        edid = connector.get("edid") or {}
        runtime = connector.get("runtime") or {}
        modes = connector.get("modes") or []
        node_id = f"display-device:{name}"
        self.add_node(
            node_id,
            display_device_label(
                connector,
                show_vendor=self.should_show_vendor_names(),
                show_status=self.should_show_display_status(),
            ),
            "display-device",
            [
                detail(
                    "Manufacturer",
                    edid.get("manufacturer_name") or edid.get("manufacturer_id"),
                ),
                detail("Product", edid.get("product_code")),
                detail("Serial", edid.get("serial_number")),
                detail("Size", edid.get("physical_size")),
                detail("Current mode", runtime.get("current_mode")),
                detail(
                    "Preferred mode",
                    edid.get("preferred_mode") or (modes[0] if modes else None),
                ),
                detail("Refresh range", edid.get("refresh_range")),
                detail("Color depth", display_color_depth_text(runtime)),
                detail("HDR", display_hdr_text(connector)),
                detail("VRR", display_vrr_text(runtime)),
                detail("Manufactured", display_manufacture_text(edid)),
            ],
            metadata={
                "connector": name,
                "manufacturer_id": edid.get("manufacturer_id"),
                "manufacturer_name": edid.get("manufacturer_name"),
                "product_code": edid.get("product_code"),
            },
        )
        self.add_edge(connector_id, node_id, display_connector_edge_label(name))

    def add_audio_ports(self) -> None:
        for port in self.report.get("sound", {}).get("ports", []):
            port_id = port.get("id")
            label = port.get("label")
            if not port_id or not label:
                continue
            node_id = f"audio-port:{safe_node_id(port_id)}"
            path = port.get("physical_path") or port.get("device_path")
            parent = self.platform_aware_parent(path, self_id=node_id)
            if not parent:
                continue
            eld = port.get("eld") or {}
            self.add_node(
                node_id,
                self.label_with_addr(port.get("address"), str(label)),
                str(port.get("node_kind") or "audio-port"),
                [
                    detail("Codec", port.get("codec_name")),
                    detail("Connector", port.get("connector")),
                    detail("Color", port.get("color")),
                    detail("Pin control", port.get("pin_ctls")),
                    detail("Monitor", eld.get("monitor_name")),
                    detail("Connection", eld.get("connection_type")),
                    detail("Status", port.get("status")),
                    detail("Format", join_nonempty(*(port.get("formats") or []))),
                    detail("Channel map", port.get("channel_map")),
                ],
                path=None,
                metadata={
                    "audio_port": True,
                    "audio_address": port.get("address"),
                    "audio_path": path,
                    "audio_port_type": port.get("port_type"),
                    "audio_edge_label": port.get("edge_label"),
                },
            )
            self.add_edge(parent, node_id, port.get("edge_label") or "Audio")
            if self.should_show_audio_jacks():
                self.add_connected_audio_devices(port, node_id)

    def add_connected_audio_devices(
        self, port: dict[str, Any], port_node_id: str
    ) -> None:
        port_id = port.get("id")
        for device in port.get("connected_devices") or []:
            label = device.get("label")
            if not label:
                continue
            node_id = f"audio-device:{safe_node_id(port_id)}:{safe_node_id(device.get('id') or label)}"
            self.add_node(
                node_id,
                str(label),
                "audio-device",
                [
                    detail("Type", device.get("device_type")),
                    detail("Connection", device.get("connection")),
                    detail("Speakers", device.get("speakers")),
                    detail("Formats", join_nonempty(*(device.get("formats") or []))),
                    detail("Max channels", device.get("max_channels")),
                    detail("Jack", device.get("jack")),
                    detail("Switches", join_nonempty(*(device.get("switches") or []))),
                ],
                metadata={
                    "audio_device": True,
                    "audio_device_type": device.get("device_type"),
                },
            )
            self.add_edge(port_node_id, node_id, device.get("edge_label") or "Audio")

    def add_storage(self, *, platform_only: bool = False) -> None:
        nvme_controllers = self.report.get("storage", {}).get("nvme_controllers", [])
        for controller in nvme_controllers:
            name = controller.get("name")
            if not name:
                continue
            node_id = f"nvme:{name}"
            path = controller.get("physical_path")
            parent = self.platform_aware_parent(path, self_id=node_id)
            if platform_only and not self.is_platform_branch(parent):
                continue
            self.add_node(
                node_id,
                self.hardware_label(controller.get("model"), name),
                "storage-controller",
                [
                    detail("Serial", controller.get("serial")),
                    detail("Firmware", controller.get("firmware_rev")),
                    detail("State", controller.get("state")),
                    detail("Driver", controller.get("driver")),
                ],
                path=path,
            )
            if parent:
                self.add_edge(parent, node_id)

        for device in self.report.get("storage", {}).get("block_devices", []):
            name = device.get("name")
            if not name:
                continue
            node_id = f"block:{name}"
            path = device.get("physical_path")
            kind = "block-device"
            parent = self.platform_aware_parent(path, self_id=node_id)
            if platform_only and not self.is_platform_branch(parent):
                continue
            self.add_node(
                node_id,
                self.hardware_label(device.get("device", {}).get("model"), name),
                kind,
                [
                    detail("Model", device.get("device", {}).get("model")),
                    detail("Driver", device.get("driver")),
                    detail("Partitions", len(device.get("partitions", []))),
                ],
                path=path,
            )
            if not parent:
                continue
            self.add_edge(parent, node_id)

    def add_network(self, *, platform_only: bool = False) -> None:
        for interface in self.report.get("network", {}).get("interfaces", []):
            name = interface.get("name")
            if not name or name == "lo":
                continue
            node_id = f"net:{name}"
            path = interface.get("device_path")
            parent = self.platform_aware_parent(path, self_id=node_id)
            if platform_only and not self.is_platform_branch(parent):
                continue
            parent_label = self.nodes[parent].label if parent in self.nodes else None
            self.add_node(
                node_id,
                self.hardware_label(parent_label, name),
                "network-interface",
                [
                    detail("MAC", interface.get("mac_address")),
                    detail("State", interface.get("operstate")),
                    detail("Speed", suffix(interface.get("speed_mbps"), "Mb/s")),
                    detail("Driver", interface.get("driver")),
                ],
                path=None,
            )
            if parent:
                self.add_edge(parent, node_id)

    def add_graphics(self, *, platform_only: bool = False) -> None:
        for card in self.report.get("graphics", {}).get("drm_devices", []):
            name = card.get("name")
            if not name:
                continue
            node_id = f"drm:{name}"
            path = card.get("physical_path") or card.get("device_path")
            parent = self.platform_aware_parent(path, self_id=node_id)
            if platform_only and not self.is_platform_branch(parent):
                continue
            parent_label = self.nodes[parent].label if parent in self.nodes else None
            self.add_node(
                node_id,
                self.hardware_label(parent_label, name),
                "graphics-device",
                [
                    detail("Driver", card.get("driver")),
                    detail("Dev", card.get("dev")),
                ],
                path=path,
            )
            if parent:
                self.add_edge(parent, node_id)

        for connector in self.report.get("graphics", {}).get("connectors", []):
            name = connector.get("name")
            if not name:
                continue
            node_id = f"display:{name}"
            path = connector.get("physical_path") or connector.get("device_path")
            modes = connector.get("modes") or []
            parent = self.platform_aware_parent(path, self_id=node_id)
            if platform_only and not self.is_platform_branch(parent):
                continue
            self.add_node(
                node_id,
                self.hardware_label(name),
                "display-connector",
                [
                    detail("Enabled", connector.get("enabled")),
                    detail("Mode", modes[0] if modes else None),
                ],
                path=path,
            )
            if parent:
                self.add_edge(parent, node_id)

    def add_sound(self, *, platform_only: bool = False) -> None:
        for card in self.report.get("sound", {}).get("cards", []):
            name = card.get("id") or card.get("name")
            if not name:
                continue
            node_id = f"sound:{card.get('name')}"
            path = card.get("physical_path") or card.get("device_path")
            parent = self.platform_aware_parent(path, self_id=node_id)
            if platform_only and not self.is_platform_branch(parent):
                continue
            parent_label = self.nodes[parent].label if parent in self.nodes else None
            self.add_node(
                node_id,
                self.hardware_label(parent_label, name),
                "sound-card",
                [detail("Driver", card.get("driver"))],
                path=path,
            )
            if parent:
                self.add_edge(parent, node_id)

    def add_simple_bus(self, bus_name: str) -> None:
        devices = self.report.get("buses", {}).get(bus_name, {}).get("devices", [])
        if not devices:
            return
        aggregate_id = f"bus:{bus_name}"
        aggregate_label = {
            "i2c": "I2C Controller",
            "spi": "SPI Controller",
            "serio": "Serio Controller",
        }.get(bus_name, f"{bus_name.upper()} bus")
        aggregate_kind = {
            "i2c": "i2c-bus",
            "spi": "spi-bus",
            "serio": "serio-bus",
        }.get(bus_name, "other")
        self.add_node(aggregate_id, aggregate_label, aggregate_kind)

        for device in sorted(
            devices, key=lambda item: path_depth(item.get("physical_path"))
        ):
            name = device.get("name")
            if not name:
                continue
            path = device.get("physical_path")
            node_id, label, kind = self.classify_bus_device(bus_name, name)
            label = self.hardware_label(simple_bus_device_hardware_name(device), label)
            self.add_node(
                node_id,
                self.label_with_addr(name, label),
                kind,
                [
                    detail("Driver", device.get("driver")),
                    detail("Modalias", device.get("modalias")),
                ],
                path=path,
            )
            parent = self.find_parent_by_path(path, self_id=node_id)
            if (
                parent is None
                and is_platform_path(path)
                and "bus:platform" in self.nodes
            ):
                parent = "bus:platform"
            if parent:
                self.add_edge(parent, node_id)

        if aggregate_id in self.nodes and not self.nodes[aggregate_id].children:
            self.remove_node(aggregate_id)

    def classify_bus_device(self, bus_name: str, name: str) -> tuple[str, str, str]:
        if bus_name == "i2c":
            if I2C_BUS_PATTERN.match(name):
                return f"i2c-bus:{name}", clean_hardware_name(name), "i2c-bus"
            if I2C_DEVICE_PATTERN.match(name) or name.startswith("i2c-"):
                return f"i2c-device:{name}", clean_hardware_name(name), "i2c-device"
        if bus_name == "spi":
            if SPI_BUS_PATTERN.match(name):
                return f"spi-bus:{name}", clean_hardware_name(name), "spi-bus"
            if SPI_DEVICE_PATTERN.match(name):
                return f"spi-device:{name}", clean_hardware_name(name), "spi-device"
        if bus_name == "serio":
            return f"serio:{name}", clean_hardware_name(name), "serio-device"
        return f"{bus_name}:{name}", clean_hardware_name(name), "other"

    def add_sensors(self) -> None:
        if not self.should_show_sensors():
            return
        for sensor in self.report.get("sensors", {}).get("devices", []):
            channels = sensor.get("channels", {})
            if not channels:
                continue
            path = sensor.get("device_path")
            parent = self.find_parent_by_path(
                path, self_id=f"sensor:{sensor.get('sysfs_name')}"
            )
            if not parent:
                continue
            self.apply_hwmon_label_to_sensor_parent(parent, sensor)
            for channel_key, channel in sorted(
                channels.items(), key=lambda item: natural_key(item[0])
            ):
                label = sensor_channel_label(
                    channel_key, channel, read_value=self.should_read_sensor_values()
                )
                if not label:
                    continue
                node_id = f"sensor:{sensor.get('sysfs_name')}:{channel_key}"
                self.add_node(
                    node_id,
                    label,
                    "sensor-device",
                    metadata={"attached": True},
                )
                self.add_edge(parent, node_id, "")

    def apply_hwmon_label_to_sensor_parent(
        self, parent_id: str, sensor: dict[str, Any]
    ) -> None:
        parent = self.nodes.get(parent_id)
        if parent is None or not should_replace_label_with_hwmon_name(parent):
            return
        hwmon_name = clean_hardware_name(sensor.get("name"), fallback="")
        if not hwmon_name:
            return
        parent.label = self.hwmon_parent_label(parent, hwmon_name)

    def hwmon_parent_label(self, parent: TopologyNode, hwmon_name: str) -> str:
        hwmon_label = f"(hwmon) {hwmon_name}"
        address = node_bus_address(parent)
        if parent.kind == "i2c-device" and I2C_DEVICE_PATTERN.match(address):
            return self.label_with_addr(address, hwmon_label)
        if parent.kind == "spi-device" and SPI_DEVICE_PATTERN.match(address):
            return self.label_with_addr(address, hwmon_label)
        return hwmon_label

    def add_power(self) -> None:
        supplies = self.report.get("power", {}).get("supplies", [])
        if not supplies:
            return
        bus_id = "bus:power"
        self.add_node(bus_id, "Power Controller", "power-device")
        self.add_edge(self.primary_cpu_root_id(), bus_id, "")
        for supply in supplies:
            name = supply.get("name")
            if not name:
                continue
            node_id = f"power:{name}"
            self.add_node(
                node_id,
                self.hardware_label(
                    supply.get("model_name"), name, vendor=supply.get("manufacturer")
                ),
                "power-device",
                [
                    detail("Status", supply.get("status")),
                    detail("Capacity", suffix(supply.get("capacity"), "%")),
                    detail(
                        "Model",
                        join_nonempty(
                            supply.get("manufacturer"), supply.get("model_name")
                        ),
                    ),
                ],
            )
            self.add_edge(bus_id, node_id)

    def add_thermal(self) -> None:
        zones = self.report.get("thermal", {}).get("zones", [])
        if not zones:
            return
        bus_id = "bus:thermal"
        self.add_node(bus_id, "Thermal Controller", "thermal-device")
        self.add_edge(self.primary_cpu_root_id(), bus_id, "")
        for zone in zones:
            name = zone.get("type") or zone.get("name")
            if not name:
                continue
            temp = zone.get("temp_millicelsius")
            temp_text = f"{temp / 1000:.1f} C" if isinstance(temp, int) else None
            node_id = f"thermal:{zone.get('name')}"
            self.add_node(
                node_id,
                self.hardware_label(name, zone.get("name")),
                "thermal-device",
                [
                    detail("Temp", temp_text),
                    detail("Mode", zone.get("mode")),
                    detail("Trips", len(zone.get("trips", []))),
                ],
            )
            self.add_edge(bus_id, node_id)

    def add_node(
        self,
        node_id: str,
        label: str,
        kind: str,
        details: list[str | None] | None = None,
        *,
        path: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        cleaned_path = normalize_path(path)
        cleaned_details = [line for line in (details or []) if line]
        cleaned_metadata = metadata or {}
        if node_id in self.nodes:
            node = self.nodes[node_id]
            if node.label == node.id and label:
                node.label = label
            if node.kind == "other" and kind:
                node.kind = kind
            for line in cleaned_details:
                if line not in node.details:
                    node.details.append(line)
            if cleaned_path and not node.path:
                node.path = cleaned_path
                self.path_to_id[cleaned_path] = node_id
            node.metadata.update(cleaned_metadata)
            return
        self.nodes[node_id] = TopologyNode(
            node_id,
            label or node_id,
            kind,
            cleaned_details,
            cleaned_path,
            metadata=cleaned_metadata,
        )
        if cleaned_path:
            self.path_to_id[cleaned_path] = node_id

    def remove_node(self, node_id: str) -> None:
        node = self.nodes.pop(node_id, None)
        if node is None:
            return
        if node.path and self.path_to_id.get(node.path) == node_id:
            del self.path_to_id[node.path]
        parent = self.parent_by_id.pop(node_id, None)
        if parent and parent in self.nodes:
            self.nodes[parent].children = [
                child for child in self.nodes[parent].children if child != node_id
            ]
        for child in list(node.children):
            self.parent_by_id.pop(child, None)

    def prune_unreachable(self) -> None:
        reachable: set[str] = set()
        stack = [self.root_id]
        while stack:
            node_id = stack.pop()
            if node_id in reachable or node_id not in self.nodes:
                continue
            reachable.add(node_id)
            stack.extend(self.nodes[node_id].children)
        self.nodes = {
            node_id: node
            for node_id, node in self.nodes.items()
            if node_id in reachable
        }
        self.parent_by_id = {
            child_id: parent_id
            for child_id, parent_id in self.parent_by_id.items()
            if child_id in reachable and parent_id in reachable
        }
        self.path_to_id = {
            path: node_id
            for path, node_id in self.path_to_id.items()
            if node_id in reachable
        }
        for node in self.nodes.values():
            node.children = [child for child in node.children if child in reachable]

    def add_edge(self, parent_id: str, child_id: str, label: str | None = None) -> None:
        if parent_id == child_id:
            return
        if parent_id not in self.nodes:
            self.add_node(parent_id, parent_id, "other")
        if child_id not in self.nodes:
            self.add_node(child_id, child_id, "other")
        if self.is_descendant(parent_id, child_id):
            return
        old_parent = self.parent_by_id.get(child_id)
        if old_parent == parent_id:
            return
        if old_parent and old_parent in self.nodes:
            self.nodes[old_parent].children = [
                child for child in self.nodes[old_parent].children if child != child_id
            ]
        self.parent_by_id[child_id] = parent_id
        edge_label = (
            label if label is not None else self.infer_edge_label(parent_id, child_id)
        )
        self.nodes[child_id].incoming_label = normalize_edge_label(edge_label)
        if child_id not in self.nodes[parent_id].children:
            self.nodes[parent_id].children.append(child_id)

    def infer_edge_label(self, parent_id: str, child_id: str) -> str:
        parent = self.nodes[parent_id]
        child = self.nodes[child_id]
        if child.kind in {"pcie-fabric", "pcie-endpoint"}:
            return pcie_edge_label(child.metadata)
        if child.kind in {"usb-root", "usb-hub", "usb-device"}:
            return usb_edge_label(child.metadata)
        if child.kind in {"i2c-bus", "i2c-device"}:
            return "I2C"
        if child.kind in {"spi-bus", "spi-device"}:
            return "SPI"
        if child.kind in {"serio-bus", "serio-device"}:
            return "Serio/input bus"
        if child.kind in {"storage-controller", "block-device", "partition"}:
            if parent.kind in {"pcie-fabric", "pcie-endpoint"}:
                return pcie_edge_label(parent.metadata)
            return "storage bus"
        if child.kind in {
            "network-interface",
            "network-port",
            "graphics-device",
            "display-connector",
            "display-device",
            "sound-card",
            "audio-port",
            "audio-stream-port",
            "audio-device",
            "sensor-device",
        }:
            if parent.kind in {"pcie-fabric", "pcie-endpoint"}:
                return pcie_edge_label(parent.metadata)
            if parent.kind in {"usb-root", "usb-hub", "usb-device"}:
                return usb_edge_label(parent.metadata)
            if parent.kind in {"i2c-bus", "i2c-device"}:
                return "I2C"
            return "device bus"
        if child.kind == "platform-device":
            return self.platform_edge_label(parent_id, child_id)
        if child.kind in {
            "platform-bus",
            "platform-device",
            "power-device",
            "thermal-device",
        }:
            return ""
        if child.kind == "dimm":
            return memory_edge_label(child.metadata)
        if child.kind == "memory-controller":
            return "memory bus"
        return "bus"

    def is_descendant(self, candidate_parent: str, node_id: str) -> bool:
        current = self.parent_by_id.get(candidate_parent)
        while current:
            if current == node_id:
                return True
            current = self.parent_by_id.get(current)
        return False

    def find_pci_parent(self, path: str | None, slot: str) -> str | None:
        if not path:
            return None
        parts = Path(path).parts
        matching_indexes = [
            index for index, part in enumerate(parts) if PCI_SLOT_PATTERN.match(part)
        ]
        if not matching_indexes:
            return None
        current_index = None
        for index in matching_indexes:
            if parts[index] == slot:
                current_index = index
                break
        if current_index is None:
            current_index = matching_indexes[-1]
        previous_slots = [
            parts[index] for index in matching_indexes if index < current_index
        ]
        for previous_slot in reversed(previous_slots):
            candidate = f"pci:{previous_slot}"
            if candidate in self.nodes:
                return candidate
        root_complex_id = self.pci_root_complex_id_for_path(path)
        if root_complex_id and root_complex_id != f"pci:{slot}":
            return root_complex_id
        return None

    def hidden_pci_bridge_slots_between(
        self, path: str | None, slot: str, parent_id: str | None
    ) -> list[str]:
        if not path:
            return []
        chain = pci_slot_chain(path)
        if not chain:
            return []
        try:
            current_index = chain.index(slot)
        except ValueError:
            current_index = len(chain) - 1
        parent_slot = pci_slot_from_node_id(parent_id)
        parent_index = -1
        if parent_slot:
            for index in range(current_index - 1, -1, -1):
                if chain[index] == parent_slot:
                    parent_index = index
                    break
        previous_slots = chain[parent_index + 1 : current_index]
        return [
            previous_slot
            for previous_slot in previous_slots
            if previous_slot in self.hidden_pci_bridge_slots
        ]

    def representative_hidden_pci_bridge_link(
        self, bridge_slots: list[str]
    ) -> tuple[str, str]:
        if not bridge_slots:
            return "", ""
        for bridge_slot in bridge_slots:
            bridge = self.hidden_pci_bridge_by_slot.get(bridge_slot)
            bridge_label = pcie_edge_label(pcie_device_link_metadata(bridge or {}))
            if bridge_label:
                return bridge_slot, bridge_label
        return bridge_slots[0], ""

    def is_pci_to_pci_bridge_device(self, device: dict[str, Any]) -> bool:
        class_id = str(device.get("class_id") or "").lower()
        return class_id.startswith(("0604", "0609"))

    def is_pci_root_complex_slot(self, path: str | None, slot: str) -> bool:
        return self.pci_root_complex_id_for_path(path) == f"pci:{slot}"

    def pci_root_complex_id_for_path(self, path: str | None) -> str | None:
        domain = pci_domain_from_path(path)
        if domain is None:
            return None
        slot = self.pci_root_complex_by_domain.get(domain[0])
        return f"pci:{slot}" if slot else None

    def find_parent_by_path(
        self, path: str | None, *, self_id: str | None = None
    ) -> str | None:
        cleaned = normalize_path(path)
        if not cleaned:
            return None
        exact_node = self.path_to_id.get(cleaned)
        if exact_node and exact_node != self_id:
            return exact_node
        current = Path(cleaned)
        for parent in current.parents:
            parent_text = normalize_path(str(parent))
            if not parent_text:
                continue
            node_id = self.path_to_id.get(parent_text)
            if node_id and node_id != self_id:
                return node_id
        return self.find_component_parent(cleaned, self_id=self_id)

    def find_component_parent(
        self, path: str, *, self_id: str | None = None
    ) -> str | None:
        parts = Path(path).parts
        for index in range(len(parts) - 1, -1, -1):
            part = parts[index]
            if PCI_SLOT_PATTERN.match(part):
                node_id = f"pci:{part}"
            elif PCI_DOMAIN_PATTERN.match(part):
                node_id = (
                    self.pci_root_complex_id_for_domain(part)
                    or self.primary_cpu_root_id()
                )
            elif USB_ROOT_PATTERN.match(part) or USB_DEVICE_PATTERN.match(part):
                node_id = f"usb:{part}"
            elif I2C_BUS_PATTERN.match(part):
                node_id = f"i2c-bus:{part}"
            elif SPI_BUS_PATTERN.match(part):
                node_id = f"spi-bus:{part}"
            else:
                node_id = ""
            if node_id and node_id in self.nodes and node_id != self_id:
                return node_id
        return None

    def pci_root_complex_id_for_domain(self, domain_name: str) -> str | None:
        slot = self.pci_root_complex_by_domain.get(domain_name)
        return f"pci:{slot}" if slot else None

    def platform_aware_parent(
        self, path: str | None, *, self_id: str | None = None
    ) -> str | None:
        parent = self.find_parent_by_path(path, self_id=self_id)
        if parent is None and is_platform_path(path) and "bus:platform" in self.nodes:
            return "bus:platform"
        return parent

    def is_platform_branch(self, node_id: str | None) -> bool:
        current = node_id
        while current:
            if current == "bus:platform":
                return True
            node = self.nodes.get(current)
            if node and node.kind == "platform-device":
                return True
            current = self.parent_by_id.get(current)
        return False

    def sort_children(self) -> None:
        for node_id, node in self.nodes.items():
            if node.kind in {"pcie-fabric", "pcie-endpoint"}:
                if self.is_pci_root_complex_node(node_id):
                    bridge_kind_counts = self.pci_bridge_kind_counts(node.children)
                    node.children.sort(
                        key=lambda child_id, counts=bridge_kind_counts: self.pci_root_complex_child_sort_key(
                            child_id,
                            counts,
                        )
                    )
                else:
                    node.children.sort(key=self.pci_child_sort_key)
            else:
                node.children.sort(key=self.sort_key)

    def sort_key(self, node_id: str) -> tuple[int, list[tuple[int, int | str]], str]:
        node = self.nodes[node_id]
        return (KIND_ORDER.get(node.kind, 999), stable_node_sort_key(node), node.id)

    def pci_root_complex_child_sort_key(
        self,
        node_id: str,
        bridge_kind_counts: dict[tuple[str, str, str, str, str], int],
    ) -> tuple[Any, ...]:
        node = self.nodes[node_id]
        if self.has_empty_edge_label(node_id):
            return (
                0,
                self.child_bus_address_sort_key(node_id),
                KIND_ORDER.get(node.kind, 999),
                stable_node_sort_key(node),
                node.id,
            )
        if node.kind in {"pcie-fabric", "pcie-endpoint"}:
            if node.metadata.get("behind_hidden_pci_bridge"):
                hidden_slot = str(
                    node.metadata.get("hidden_pci_bridge_sort_slot")
                    or node.metadata.get("hidden_pci_bridge_group")
                    or ""
                )
                hidden_kind_key = self.hidden_pci_bridge_kind_key(hidden_slot)
                bridge_kind_count = (
                    bridge_kind_counts.get(hidden_kind_key, 0) if hidden_kind_key else 0
                )
                return (
                    1,
                    0,
                    1,
                    bridge_kind_count,
                    self.hidden_pci_bridge_depth(hidden_slot),
                    pci_slot_sort_key(hidden_slot),
                    self.child_bus_address_sort_key(node_id),
                    KIND_ORDER.get(node.kind, 999),
                    stable_node_sort_key(node),
                    node.id,
                )
            slot = str(
                node.metadata.get("pci_slot") or pci_slot_from_node_id(node.id) or ""
            )
            hidden_group = 1 if node.metadata.get("behind_hidden_pci_bridge") else 0
            bridge_group = 1 if node.metadata.get("pci_bridge") else 0
            bridge_depth = (
                self.consecutive_pci_bridge_depth(node_id) if bridge_group else 0
            )
            bridge_kind_count = (
                bridge_kind_counts.get(pci_bridge_kind_key(node), 0)
                if bridge_group
                else 0
            )
            return (
                1,
                hidden_group,
                bridge_group,
                bridge_kind_count,
                bridge_depth,
                pci_slot_sort_key(slot),
                KIND_ORDER.get(node.kind, 999),
                stable_node_sort_key(node),
                node.id,
            )
        return (
            2,
            0,
            0,
            0,
            0,
            pci_slot_sort_key(""),
            KIND_ORDER.get(node.kind, 999),
            stable_node_sort_key(node),
            node.id,
        )

    def pci_child_sort_key(self, node_id: str) -> tuple[Any, ...]:
        node = self.nodes[node_id]
        if self.has_empty_edge_label(node_id):
            return (
                0,
                self.child_bus_address_sort_key(node_id),
                KIND_ORDER.get(node.kind, 999),
                stable_node_sort_key(node),
                node.id,
            )
        return (1, self.pci_address_sort_key(node_id))

    def has_empty_edge_label(self, node_id: str) -> bool:
        node = self.nodes[node_id]
        label = (
            node.metadata.get("hidden_pci_bridge_label") or node.incoming_label or ""
        )
        return not str(label).strip()

    def child_bus_address_sort_key(self, node_id: str) -> tuple[Any, ...]:
        node = self.nodes[node_id]
        slot = str(
            node.metadata.get("pci_slot") or pci_slot_from_node_id(node.id) or ""
        )
        if slot:
            return (0, pci_slot_sort_key(slot))
        return (1, natural_key(node_bus_address(node)), node.id)

    def pci_address_sort_key(self, node_id: str) -> tuple[Any, ...]:
        node = self.nodes[node_id]
        if node.kind in {"pcie-fabric", "pcie-endpoint"}:
            slot = str(
                node.metadata.get("pci_slot") or pci_slot_from_node_id(node.id) or ""
            )
            return (
                0,
                pci_slot_sort_key(slot),
                KIND_ORDER.get(node.kind, 999),
                stable_node_sort_key(node),
                node.id,
            )
        return (
            1,
            pci_slot_sort_key(""),
            KIND_ORDER.get(node.kind, 999),
            stable_node_sort_key(node),
            node.id,
        )

    def pci_bridge_kind_counts(
        self, child_ids: list[str]
    ) -> dict[tuple[str, str, str, str, str], int]:
        counts: dict[tuple[str, str, str, str, str], int] = {}
        hidden_slots: set[str] = set()
        for child_id in child_ids:
            child = self.nodes.get(child_id)
            if child is None:
                continue
            if child.metadata.get("behind_hidden_pci_bridge"):
                hidden_slot = str(
                    child.metadata.get("hidden_pci_bridge_sort_slot")
                    or child.metadata.get("hidden_pci_bridge_group")
                    or ""
                )
                if not hidden_slot or hidden_slot in hidden_slots:
                    continue
                hidden_slots.add(hidden_slot)
                key = self.hidden_pci_bridge_kind_key(hidden_slot)
            elif child.metadata.get("pci_bridge"):
                key = pci_bridge_kind_key(child)
            else:
                continue
            if not key:
                continue
            counts[key] = counts.get(key, 0) + 1
        return counts

    def hidden_pci_bridge_kind_key(self, slot: str) -> tuple[str, str, str, str, str]:
        bridge = self.hidden_pci_bridge_by_slot.get(slot) or {}
        return pci_bridge_kind_key_from_metadata(bridge)

    def hidden_pci_bridge_depth(self, slot: str) -> int:
        if not slot:
            return 0
        depth = 1
        for candidate_slot, bridge in self.hidden_pci_bridge_by_slot.items():
            chain = pci_slot_chain(bridge.get("physical_path"))
            if slot not in chain or candidate_slot not in chain:
                continue
            start = chain.index(slot)
            end = chain.index(candidate_slot)
            if end < start:
                continue
            candidate_depth = sum(
                1
                for item in chain[start : end + 1]
                if item in self.hidden_pci_bridge_slots
            )
            depth = max(depth, candidate_depth)
        return depth

    def is_pci_root_complex_node(self, node_id: str) -> bool:
        return any(
            node_id == f"pci:{slot}"
            for slot in self.pci_root_complex_by_domain.values()
        )

    def consecutive_pci_bridge_depth(self, node_id: str) -> int:
        node = self.nodes.get(node_id)
        if node is None or not node.metadata.get("pci_bridge"):
            return 0
        child_depths = [
            self.consecutive_pci_bridge_depth(child_id)
            for child_id in node.children
            if self.nodes.get(child_id)
            and self.nodes[child_id].metadata.get("pci_bridge")
        ]
        return 1 + max(child_depths, default=0)

    def to_tree(self, node_id: str) -> dict[str, Any]:
        node = self.nodes[node_id]
        return {
            "id": node.id,
            "label": node.label,
            "kind": node.kind,
            "link": node.incoming_label,
            "attached": bool(node.metadata.get("attached")),
            "hidden": bool(node.metadata.get("hidden")),
            "edge_group": node.metadata.get("hidden_pci_bridge_group"),
            "edge_group_label": node.metadata.get("hidden_pci_bridge_label"),
            "iommu_group": node.metadata.get("iommu_group"),
            "details": node.details,
            "path": node.path,
            "children": [self.to_tree(child_id) for child_id in node.children],
        }

    def node_to_dict(self, node: TopologyNode) -> dict[str, Any]:
        return {
            "id": node.id,
            "label": node.label,
            "kind": node.kind,
            "link": node.incoming_label,
            "attached": bool(node.metadata.get("attached")),
            "hidden": bool(node.metadata.get("hidden")),
            "edge_group": node.metadata.get("hidden_pci_bridge_group"),
            "edge_group_label": node.metadata.get("hidden_pci_bridge_label"),
            "iommu_group": node.metadata.get("iommu_group"),
            "details": node.details,
            "path": node.path,
        }


def build_topology_report(report: dict[str, Any]) -> dict[str, Any]:
    return TopologyBuilder(report).build()


def normalize_edge_label(label: Any) -> str:
    text = str(label).strip() if label is not None else ""
    if text.lower() == "platform bus":
        return ""
    return text


def normalize_path(path: str | None) -> str | None:
    if not path:
        return None
    cleaned = str(path).rstrip("/")
    return cleaned or None


def path_depth(path: str | None) -> int:
    if not path:
        return 0
    return len(Path(path).parts)


def is_platform_path(path: str | None) -> bool:
    return bool(path and "/sys/devices/platform/" in path)


def is_direct_platform_device_path(path: str | None) -> bool:
    if not path:
        return False
    parts = Path(path).parts
    return len(parts) == 5 and parts[:4] == ("/", "sys", "devices", "platform")


def normalize_acpi_path(path: Any) -> str:
    text = str(path).strip() if path is not None else ""
    text = re.sub(r"\.+", ".", text)
    return text.rstrip(".")


def acpi_path_prefixes(path: Any) -> list[str]:
    normalized = normalize_acpi_path(path)
    if not normalized:
        return []
    rooted = normalized.startswith("\\")
    body = normalized[1:] if rooted else normalized
    parts = [part for part in body.split(".") if part]
    prefixes: list[str] = []
    for index in range(1, len(parts) + 1):
        prefix = ".".join(parts[:index])
        prefixes.append(f"\\{prefix}" if rooted else prefix)
    return prefixes


def acpi_path_prefixes_between(root_path: Any, target_path: Any) -> list[str]:
    root = normalize_acpi_path(root_path)
    target = normalize_acpi_path(target_path)
    if not root or not target or root == target:
        return []
    return [
        prefix
        for prefix in acpi_path_prefixes(target)
        if prefix != root and prefix.startswith(f"{root}.")
    ]


def acpi_node_id(acpi_device: dict[str, Any]) -> str:
    acpi_path = normalize_acpi_path(acpi_device.get("acpi_path"))
    return f"acpi:{safe_node_id(acpi_path or acpi_device.get('name'))}"


def acpi_node_label(acpi_device: dict[str, Any]) -> str:
    acpi_path = normalize_acpi_path(acpi_device.get("acpi_path"))
    name = str(acpi_device.get("name") or "").strip()
    if name and ACPI_INSTANCE_PATTERN.match(name):
        return f"ACPI {acpi_path} / {name}"
    return f"ACPI {acpi_path}" if acpi_path else f"ACPI {name}"


def safe_node_id(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"[^A-Za-z0-9_.:-]+", "_", text)
    return text.strip("_") or "unknown"


def pci_domain_from_path(path: str | None) -> tuple[str, str] | None:
    if not path:
        return None
    parts = Path(path).parts
    for index, part in enumerate(parts):
        if PCI_DOMAIN_PATTERN.match(part):
            return part, str(Path(*parts[: index + 1]))
    return None


def pci_slot_chain(path: str | None) -> list[str]:
    if not path:
        return []
    return [part for part in Path(path).parts if PCI_SLOT_PATTERN.match(part)]


def path_has_pci_slot(path: str | None) -> bool:
    return bool(pci_slot_chain(path))


def pci_slot_from_node_id(node_id: str | None) -> str | None:
    if not node_id or not node_id.startswith("pci:"):
        return None
    slot = node_id.removeprefix("pci:")
    return slot if PCI_SLOT_PATTERN.match(slot) else None


def pci_slot_sort_key(slot: str | None) -> tuple[int, int, int, int, str]:
    if not slot:
        return (0xFFFF, 0xFF, 0xFF, 0xFF, "")
    match = PCI_SLOT_ADDRESS_PATTERN.match(slot)
    if not match:
        return (0xFFFF, 0xFF, 0xFF, 0xFF, slot)
    domain, bus, device, function = match.groups()
    return (int(domain, 16), int(bus, 16), int(device, 16), int(function, 16), "")


def pci_bridge_kind_key(node: TopologyNode) -> tuple[str, str, str, str, str]:
    return pci_bridge_kind_key_from_metadata(node.metadata)


def pci_bridge_kind_key_from_metadata(
    metadata: dict[str, Any],
) -> tuple[str, str, str, str, str]:
    return (
        pci_kind_value(metadata.get("pci_class_id") or metadata.get("class_id")),
        pci_kind_value(metadata.get("pci_vendor_id") or metadata.get("vendor_id")),
        pci_kind_value(metadata.get("pci_device_id") or metadata.get("device_id")),
        pci_kind_value(
            metadata.get("pci_subsystem_vendor_id")
            or metadata.get("subsystem_vendor_id")
        ),
        pci_kind_value(
            metadata.get("pci_subsystem_device_id")
            or metadata.get("subsystem_device_id")
        ),
    )


def pci_kind_value(value: Any) -> str:
    return str(value or "").strip().lower()


def short_pci_address(slot: Any) -> str:
    text = str(slot).strip()
    match = PCI_SLOT_ADDRESS_PATTERN.match(text)
    if not match:
        return text
    domain, bus, device, function = match.groups()
    if domain.lower() == "0000":
        return f"{bus}:{device}.{function}"
    return text


def label_with_address(address: Any, label: str) -> str:
    address_text = str(address).strip() if address is not None else ""
    label_text = str(label).strip() if label is not None else ""
    if not address_text:
        return label_text
    if not label_text:
        return address_text
    if label_text == address_text or label_text.startswith(f"{address_text} "):
        return label_text
    return f"{address_text} {label_text}"


def platform_display_address(name: Any, modalias: Any) -> str:
    name_text = str(name).strip() if name is not None else ""
    if not name_text:
        return ""
    return name_text


def platform_hardware_label(device: dict[str, Any]) -> str:
    hid = acpi_hid_from_platform_device(device.get("name"), device.get("modalias"))
    if hid:
        label = ACPI_HID_LABELS.get(hid.upper())
        if label:
            return label
    driver_label = platform_driver_hardware_label(device.get("driver"))
    if driver_label:
        return driver_label
    return clean_hardware_name(device.get("name"), fallback="Platform device")


def simple_bus_device_hardware_name(device: dict[str, Any]) -> str | None:
    name = device.get("device_name")
    hid = acpi_hid_from_platform_device(name, device.get("modalias"))
    if hid and is_acpi_instance_name(name):
        return hid
    return strip_acpi_instance_suffix(name)


def should_show_network_port(interface: dict[str, Any]) -> bool:
    if interface.get("name") == "lo":
        return False
    if not interface.get("device_path"):
        return False
    if interface.get("is_wireless"):
        return True
    phys_port_name = str(interface.get("phys_port_name") or "").strip()
    if NETWORK_VF_PORT_PATTERN.match(phys_port_name):
        return False
    return interface.get("kind") in {"ethernet", "infiniband"} or bool(
        interface.get("supported_modes")
    )


def should_show_infiniband_port(port: dict[str, Any]) -> bool:
    if not port.get("device_path"):
        return False
    return str(port.get("link_layer") or "").casefold() == "infiniband"


def infiniband_port_node_id(port: dict[str, Any]) -> str:
    return f"ib-port:{port.get('hca')}:{port.get('port')}"


def infiniband_port_label(port: dict[str, Any], *, show_status: bool = True) -> str:
    name = f"port {port.get('port')}" if port.get("port") else "InfiniBand port"
    descriptor = infiniband_port_descriptor(port, show_status=show_status)
    if descriptor:
        separator = " " if show_status else ": "
        return f"{name}{separator}{descriptor}"
    return name


def infiniband_port_descriptor(
    port: dict[str, Any], *, show_status: bool = True
) -> str:
    link_layer = str(port.get("link_layer") or "").strip()
    rate = infiniband_rate_text(port.get("rate"))
    if not show_status:
        return rate
    prefix = f"({link_layer})" if link_layer else ""
    if rate:
        return f"{prefix}: {rate}" if prefix else rate
    return prefix


def infiniband_rate_text(rate: Any) -> str:
    text = str(rate or "").strip()
    if not text:
        return ""
    return text.replace("Gb/sec", "Gb/s").replace("Mb/sec", "Mb/s")


def infiniband_port_edge_label(port: dict[str, Any]) -> str:
    return "InfiniBand"


def bluetooth_adapter_label(adapter: dict[str, Any]) -> str:
    version = str(adapter.get("bluetooth_version") or "Bluetooth").strip()
    if version.casefold().startswith("bluetooth"):
        label = version
    else:
        label = f"Bluetooth {version}"
    capabilities = bluetooth_capability_summary(adapter)
    return f"{label} ({capabilities})" if capabilities else label


def bluetooth_capability_summary(adapter: dict[str, Any]) -> str:
    supported = set(adapter.get("supported_settings") or [])
    parts: list[str] = []
    radio = bluetooth_radio_capabilities(supported)
    if radio:
        parts.extend(radio)
    if "Secure Connections" in supported:
        parts.append("Secure Connections")
    if supported.intersection(
        {"CIS Central", "CIS Peripheral", "ISO Broadcaster", "Synchronized Receiver"}
    ):
        parts.append("Isochronous Channels")
    if "PHY Configuration" in supported:
        parts.append("PHY Configuration")
    if "Wideband Speech" in supported:
        parts.append("Wideband Speech")
    return ", ".join(parts)


def bluetooth_radio_capabilities(settings: set[str]) -> list[str]:
    has_combined = "BR/EDR" in settings
    has_br = "BR" in settings
    has_edr = "EDR" in settings
    radios: list[str] = []
    if has_combined or (has_br and has_edr):
        radios.append("BR/EDR")
    elif has_br:
        radios.append("BR")
    elif has_edr:
        radios.append("EDR")
    if "LE" in settings:
        radios.append("LE")
    return radios


def network_port_label(interface: dict[str, Any], *, show_status: bool = True) -> str:
    if interface.get("is_wireless"):
        return wireless_port_label(interface)
    name = network_port_name(interface)
    descriptor = network_port_descriptor(interface, show_status=show_status)
    if name and descriptor:
        separator = " " if show_status else ": "
        return f"{name}{separator}{descriptor}"
    return name or descriptor or "Network port"


def wireless_port_label(interface: dict[str, Any]) -> str:
    wireless = interface.get("wireless") or {}
    generation = str(wireless.get("generation") or "Wi-Fi").strip()
    bands = list(wireless.get("bands") or [])
    header_parts: list[str] = []
    band_summary = wireless_band_summary(bands)
    if band_summary:
        header_parts.append(band_summary)
    if wireless.get("mlo_supported"):
        header_parts.append("MLO: supported")
    header = f"{generation} ({'; '.join(header_parts)})" if header_parts else generation
    lines = [header]
    for band in sorted(bands, key=wireless_band_label_sort_key):
        line = wireless_band_line(band)
        if line:
            lines.append(line)
    return "\n".join(lines)


def wireless_band_summary(bands: list[dict[str, Any]]) -> str:
    labels = [
        {"2.4GHz": "2.4", "5GHz": "5", "6GHz": "6"}.get(str(band.get("name")), "")
        for band in sorted(bands, key=wireless_band_label_sort_key)
    ]
    labels = [label for label in labels if label]
    return f"{'/'.join(labels)} GHz" if labels else ""


def wireless_band_line(band: dict[str, Any]) -> str:
    name = str(band.get("name") or "").strip()
    if not name:
        return ""
    parts: list[str] = []
    if band.get("mimo"):
        parts.append(f"Upto {band.get('mimo')}")
    if band.get("max_width_mhz"):
        parts.append(f"{band.get('max_width_mhz')}MHz")
    best_mode = wireless_band_best_mode_label(band.get("best_mode") or {})
    if best_mode:
        parts.append(best_mode)
    return f"- {name}: {', '.join(parts)}" if parts else f"- {name}"


def wireless_band_best_mode_label(mode: dict[str, Any]) -> str:
    standard = str(mode.get("standard") or "").strip()
    spatial_streams = mode.get("spatial_streams")
    mcs = mode.get("mcs")
    if not standard or spatial_streams is None or mcs is None:
        return ""
    return f"{standard} NSS{spatial_streams}/MCS{mcs}"


def wireless_band_label_sort_key(band: dict[str, Any]) -> int:
    return {"2.4GHz": 0, "5GHz": 1, "6GHz": 2}.get(str(band.get("name")), 99)


def network_port_name(interface: dict[str, Any]) -> str:
    phys_port_name = str(interface.get("phys_port_name") or "").strip()
    if phys_port_name:
        normalized = normalized_network_phys_port_name(phys_port_name)
        if normalized:
            return normalized
        return phys_port_name
    dev_port = interface.get("dev_port")
    if dev_port is not None:
        return f"port {dev_port}"
    return str(interface.get("name") or "").strip()


def normalized_network_phys_port_name(name: str) -> str:
    match = NETWORK_PHYSICAL_PORT_PATTERN.match(name)
    if match:
        return f"port {int(match.group(1))}"
    return ""


def network_port_descriptor(
    interface: dict[str, Any], *, show_status: bool = True
) -> str:
    if not show_status:
        return network_port_speed_capability_text(interface)
    port_type = network_port_type_text(interface)
    speeds = supported_network_speeds_text(interface.get("supported_modes") or [])
    current = network_current_speed_text(interface)
    prefix = f"({port_type})" if port_type else ""
    if speeds:
        descriptor = f"{prefix}: {speeds}" if prefix else speeds
    elif current:
        descriptor = f"{prefix}: {current}" if prefix else current
    else:
        descriptor = prefix
    if current and speeds and current not in speeds.split("/"):
        descriptor = f"{descriptor} (current = {current})"
    elif current and speeds:
        descriptor = f"{descriptor} (current = {current})"
    return descriptor.strip()


def network_port_speed_capability_text(interface: dict[str, Any]) -> str:
    speeds = supported_network_speeds_text(interface.get("supported_modes") or [])
    if speeds:
        return speeds
    return network_current_speed_text(interface)


def network_current_speed_text(interface: dict[str, Any]) -> str:
    if not network_link_is_active(interface):
        return ""
    return format_network_speed(
        interface.get("speed_mbps") or interface.get("negotiated_speed_mbps")
    )


def network_link_is_active(interface: dict[str, Any]) -> bool:
    carrier = interface.get("carrier")
    if carrier is True:
        return True
    if carrier is False:
        return False
    operstate = str(interface.get("operstate") or "").strip().casefold()
    if operstate == "up":
        return True
    if operstate in {"down", "lowerlayerdown", "dormant", "notpresent", "testing"}:
        return False
    return False


def network_port_type_text(interface: dict[str, Any]) -> str:
    port_type = str(interface.get("port_type") or "").strip()
    if port_type:
        return port_type
    ports = [
        str(port).strip()
        for port in interface.get("supported_ports") or []
        if str(port).strip()
    ]
    if ports:
        return "/".join(ports)
    return ""


def supported_network_speeds_text(modes: list[Any]) -> str:
    speeds = sorted(
        {speed for speed in (network_mode_speed_mbps(mode) for mode in modes) if speed}
    )
    return "/".join(
        format_network_speed(speed) for speed in speeds if format_network_speed(speed)
    )


def network_mode_speed_mbps(mode: Any) -> int | None:
    match = NETWORK_MODE_SPEED_PATTERN.match(str(mode or "").strip())
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def format_network_speed(speed_mbps: Any) -> str:
    try:
        speed = int(speed_mbps)
    except (TypeError, ValueError):
        return ""
    if speed <= 0:
        return ""
    if speed >= 1000:
        gbps = speed / 1000
        if gbps.is_integer():
            return f"{int(gbps)}G"
        return f"{gbps:g}G"
    return f"{speed}M"


def network_port_edge_label(interface: dict[str, Any]) -> str:
    if interface.get("is_wireless"):
        return "Wi-Fi"
    if interface.get("kind") == "infiniband":
        return "InfiniBand"
    return "Ethernet"


def should_show_display_connector(connector: dict[str, Any]) -> bool:
    connector_type = display_connector_type(connector.get("name"))
    return connector_type not in {"", "Virtual", "Writeback", "Unknown"}


def display_connector_label(name: Any) -> str:
    return (
        DRM_CONNECTOR_PREFIX_PATTERN.sub("", str(name or "").strip())
        or "Display connector"
    )


def display_connector_type(name: Any) -> str:
    label = display_connector_label(name)
    if label.startswith("HDMI"):
        return "HDMI"
    if label.startswith("DP"):
        return "DisplayPort"
    if label.startswith("eDP"):
        return "eDP"
    if label.startswith("DVI"):
        return "DVI"
    if label.startswith("VGA"):
        return "VGA"
    if label.startswith("LVDS"):
        return "LVDS"
    if label.startswith("Writeback"):
        return "Writeback"
    if label.startswith("Virtual"):
        return "Virtual"
    if label.startswith("Unknown"):
        return "Unknown"
    return label.split("-", 1)[0] if label else ""


def display_connector_edge_label(name: Any) -> str:
    connector_type = display_connector_type(name)
    return connector_type if connector_type else "display"


def display_device_label(
    connector: dict[str, Any], *, show_vendor: bool, show_status: bool = True
) -> str:
    edid = connector.get("edid") or {}
    modes = connector.get("modes") or []
    label = raw_hardware_label(
        edid.get("display_name"),
        edid.get("text"),
        modes[0] if modes else None,
        fallback="Connected display",
    )
    vendor = edid.get("manufacturer_name") or edid.get("manufacturer_id")
    if show_vendor:
        label = label_with_vendor(vendor, label)
    else:
        label = strip_company_name(label, vendor) or label
    summary = (
        display_summary_text(connector)
        if show_status
        else display_capability_summary_text(connector)
    )
    return f"{label}\n({summary})" if summary else label


def display_summary_text(connector: dict[str, Any]) -> str:
    runtime = connector.get("runtime") or {}
    edid = connector.get("edid") or {}
    modes = connector.get("modes") or []
    primary = [
        runtime.get("current_mode")
        or edid.get("preferred_mode")
        or (modes[0] if modes else None),
        display_current_color_depth_text(runtime),
    ]
    state = [
        display_hdr_summary_text(runtime),
        display_vrr_summary_text(runtime),
    ]
    return join_display_summary(primary, state)


def display_color_depth_text(runtime: dict[str, Any]) -> str:
    return display_current_color_depth_text(runtime)


def display_current_color_depth_text(runtime: dict[str, Any]) -> str:
    bpc = runtime.get("max_bpc")
    return f"{bpc} bpc" if bpc else "? bpc"


def display_max_color_depth_text(runtime: dict[str, Any]) -> str:
    bpc = runtime.get("max_bpc")
    return f"max {bpc} bpc" if bpc else "max ? bpc"


def display_capability_summary_text(connector: dict[str, Any]) -> str:
    runtime = connector.get("runtime") or {}
    edid = connector.get("edid") or {}
    primary = [
        display_max_resolution_text(connector),
        display_max_refresh_text(connector),
        display_max_color_depth_text(runtime),
    ]
    state = [
        display_hdr_support_summary_text(edid),
        display_vrr_support_summary_text(runtime),
    ]
    return join_display_summary(primary, state)


def join_display_summary(primary: list[Any], state: list[Any]) -> str:
    primary_text = ", ".join(str(part) for part in primary if part)
    state_text = ", ".join(str(part) for part in state if part)
    if primary_text and state_text:
        return f"{primary_text},\n{state_text}"
    return primary_text or state_text


def display_max_resolution_text(connector: dict[str, Any]) -> str | None:
    modes = display_mode_infos(connector)
    if not modes:
        return None
    width, height, _ = max(
        modes, key=lambda mode: (mode[0] * mode[1], mode[0], mode[1], mode[2] or 0)
    )
    return f"~{width}x{height}"


def display_max_refresh_text(connector: dict[str, Any]) -> str | None:
    modes = [mode for mode in display_mode_infos(connector) if mode[2] is not None]
    if not modes:
        return None
    refresh = max(mode[2] for mode in modes if mode[2] is not None)
    return f"~{format_display_refresh_hz(refresh)}"


def display_mode_infos(
    connector: dict[str, Any],
) -> list[tuple[int, int, float | None]]:
    runtime = connector.get("runtime") or {}
    edid = connector.get("edid") or {}
    candidates = [
        *(runtime.get("modes") or []),
        *(edid.get("detailed_modes") or []),
        edid.get("preferred_mode"),
        *(connector.get("modes") or []),
    ]
    modes: list[tuple[int, int, float | None]] = []
    seen: set[tuple[int, int, float | None]] = set()
    for candidate in candidates:
        parsed = parse_display_mode_text(candidate)
        if not parsed or parsed in seen:
            continue
        seen.add(parsed)
        modes.append(parsed)
    return modes


def parse_display_mode_text(value: Any) -> tuple[int, int, float | None] | None:
    match = DISPLAY_MODE_PATTERN.match(str(value or "").strip())
    if not match:
        return None
    width_text, height_text, refresh_text = match.groups()
    refresh = None
    if refresh_text:
        try:
            refresh = float(refresh_text)
        except ValueError:
            refresh = None
    return int(width_text), int(height_text), refresh


def format_display_refresh_hz(refresh: float) -> str:
    rounded = round(refresh)
    if abs(refresh - rounded) < 0.2:
        return f"{rounded}Hz"
    return f"{refresh:.2f}".rstrip("0").rstrip(".") + "Hz"


def display_hdr_summary_text(runtime: dict[str, Any]) -> str:
    return f"HDR: {yes_no(display_hdr_active(runtime))}"


def display_hdr_support_summary_text(edid: dict[str, Any]) -> str:
    supported = edid.get("hdr_supported")
    if supported is True:
        return "HDR: supported"
    if supported is False:
        return "HDR: unsupported"
    return "HDR: unknown"


def display_hdr_text(connector: dict[str, Any]) -> str:
    runtime = connector.get("runtime") or {}
    edid = connector.get("edid") or {}
    active = display_hdr_active(runtime)
    supported = display_hdr_capability_text(edid)
    if active:
        return f"yes ({supported})" if supported else "yes"
    return f"no (supported: {supported})" if supported else "no"


def display_hdr_active(runtime: dict[str, Any]) -> bool:
    properties = runtime.get("properties") or {}
    metadata = properties.get("HDR_OUTPUT_METADATA")
    if isinstance(metadata, int):
        return metadata != 0
    parsed = parse_int(str(metadata)) if metadata is not None else None
    return bool(parsed)


def display_hdr_capability_text(edid: dict[str, Any]) -> str | None:
    if edid.get("hdr_supported") is True:
        eotfs = [
            str(item)
            for item in edid.get("hdr_eotfs") or []
            if str(item) and str(item) != "SDR"
        ]
        return ", ".join(eotfs) if eotfs else "yes"
    return None


def display_vrr_text(runtime: dict[str, Any]) -> str:
    return yes_no(bool(runtime.get("vrr_capable")))


def display_vrr_summary_text(runtime: dict[str, Any]) -> str:
    return f"VRR: {display_vrr_text(runtime)}"


def display_vrr_support_summary_text(runtime: dict[str, Any]) -> str:
    if "vrr_capable" not in runtime:
        return "VRR: unknown"
    return "VRR: supported" if runtime.get("vrr_capable") else "VRR: unsupported"


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def display_manufacture_text(edid: dict[str, Any]) -> str | None:
    year = edid.get("manufacture_year")
    week = edid.get("manufacture_week")
    if year and week:
        return f"week {week}, {year}"
    return str(year) if year else None


def platform_hardware_identity(device: dict[str, Any]) -> str:
    return normalize_hardware_identity(platform_hardware_label(device))


def platform_node_hardware_identity(node: TopologyNode) -> str:
    return normalize_hardware_identity(
        node.metadata.get("hardware_identity") or node.label
    )


def normalize_hardware_identity(value: Any) -> str:
    text = normalize_hardware_label_text(value, fallback="")
    text = re.sub(r"^[A-Z0-9]{3,12}:\d+\s+", "", text)
    text = re.sub(r"\s+", " ", text).strip(" -_:,")
    return text.casefold()


def node_bus_address(node: TopologyNode) -> str:
    platform_name = str(node.metadata.get("platform_name") or "").strip()
    if platform_name:
        return platform_name
    node_id = str(node.id or "")
    if ":" in node_id:
        return node_id.split(":", 1)[1]
    label = str(node.label or "").strip()
    return label.split(maxsplit=1)[0] if label else node_id


def stable_node_sort_key(node: TopologyNode) -> list[tuple[int, int | str]]:
    return natural_key(f"{node_bus_address(node)} {node.id}")


def should_replace_label_with_hwmon_name(node: TopologyNode) -> bool:
    return node.kind in {"platform-device", "spi-device"}


def resource_owner_candidates_for_node(node: TopologyNode) -> set[str]:
    candidates: set[str] = set()

    def add(value: Any) -> None:
        text = str(value or "").strip()
        if not text:
            return
        candidates.add(normalize_resource_owner(text))
        match = re.match(r"^(.+)\.(\d+)$", text)
        if match:
            candidates.add(normalize_resource_owner(match.group(1)))

    add(node.metadata.get("platform_name"))
    add(node.metadata.get("acpi_name"))
    add(node.metadata.get("driver"))
    modalias = str(node.metadata.get("modalias") or "")
    if modalias.startswith("platform:"):
        add(modalias.split(":", 1)[1])
    add(node_bus_address(node))
    return {candidate for candidate in candidates if candidate}


def platform_resource_owner_candidates(node: TopologyNode) -> set[str]:
    return resource_owner_candidates_for_node(node)


def normalize_resource_owner(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def nearest_acpi_resource_owner(
    resource: dict[str, Any],
    acpi_by_name: dict[str, dict[str, Any]],
) -> str | None:
    for owner in reversed(resource.get("ancestor_owners") or []):
        owner_text = str(owner or "").strip()
        if owner_text in acpi_by_name and ACPI_INSTANCE_PATTERN.match(owner_text):
            return owner_text
    return None


def resource_match_sort_key(resource: dict[str, Any]) -> tuple[int, int, int, int]:
    acpi_owner = str(resource.get("acpi_owner") or "")
    ancestors = [str(owner or "") for owner in resource.get("ancestor_owners") or []]
    try:
        owner_index = len(ancestors) - 1 - list(reversed(ancestors)).index(acpi_owner)
        distance = len(ancestors) - owner_index - 1
    except ValueError:
        distance = len(ancestors) + 1
    direct_parent = 0 if str(resource.get("parent_owner") or "") == acpi_owner else 1
    kind_order = 0 if resource.get("kind") == "ioport" else 1
    index = parse_int(str(resource.get("index"))) or 0
    return (direct_parent, distance, kind_order, index)


def resource_node_id(resource: dict[str, Any], platform_node: TopologyNode) -> str:
    return (
        f"resource:{safe_node_id(resource.get('kind'))}:"
        f"{safe_node_id(resource.get('acpi_owner'))}:"
        f"{safe_node_id(resource.get('owner'))}:"
        f"{safe_node_id(resource.get('index'))}:"
        f"{safe_node_id(platform_node.id)}"
    )


def resource_node_label(resource: dict[str, Any], platform_node: TopologyNode) -> str:
    label = "I/O port resource" if resource.get("kind") == "ioport" else "MMIO resource"
    base = resource_base_text(resource, platform_node)
    return f"{label}, base {base}" if base else label


def resource_base_text(resource: dict[str, Any], platform_node: TopologyNode) -> str:
    start = resource.get("start")
    if resource.get("address_known") and isinstance(start, int):
        return f"0x{start:x}"
    platform_name = str(platform_node.metadata.get("platform_name") or "")
    match = re.search(r"\.(\d+)$", platform_name)
    if match:
        return f"0x{int(match.group(1)):x}"
    return ""


def resource_edge_label(resource: dict[str, Any]) -> str:
    return "I/O port" if resource.get("kind") == "ioport" else "MMIO"


def is_acpi_platform_device(name: Any, modalias: Any) -> bool:
    modalias_text = str(modalias).strip() if modalias is not None else ""
    if ACPI_MODALIAS_PATTERN.match(modalias_text):
        return True
    name_text = str(name).strip() if name is not None else ""
    return bool(ACPI_INSTANCE_PATTERN.match(name_text))


def acpi_hid_from_platform_device(name: Any, modalias: Any) -> str | None:
    modalias_text = str(modalias).strip() if modalias is not None else ""
    match = ACPI_MODALIAS_PATTERN.match(modalias_text)
    if match:
        return match.group(1).upper()
    name_text = str(name).strip() if name is not None else ""
    if ACPI_INSTANCE_PATTERN.match(name_text):
        return name_text.split(":", 1)[0].upper()
    return None


def is_acpi_instance_name(value: Any) -> bool:
    return bool(
        ACPI_INSTANCE_PATTERN.match(str(value).strip() if value is not None else "")
    )


def strip_acpi_instance_suffix(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    if is_acpi_instance_name(text):
        return text.split(":", 1)[0]
    return text


def platform_driver_hardware_label(driver: Any) -> str | None:
    driver_text = str(driver).strip() if driver is not None else ""
    if not driver_text or driver_text == "driver":
        return None
    normalized = driver_text.lower()
    label = PLATFORM_DRIVER_LABELS.get(normalized)
    if label:
        return label
    for token, token_label in PLATFORM_DRIVER_PATTERNS:
        if token in normalized:
            return token_label
    return None


def platform_physical_bus_label(parent: TopologyNode, child: TopologyNode) -> str:
    parent_label = str(parent.label or "").lower()
    parent_class = pci_kind_value(parent.metadata.get("pci_class_id"))
    if "espi" in parent_label:
        return "eSPI"
    if "lpc" in parent_label:
        return "LPC"
    if parent_class.startswith("0601"):
        return "ISA/LPC"
    return ""


def raw_hardware_label(*candidates: Any, fallback: str = "Unknown device") -> str:
    first_cleaned: str | None = None
    for candidate in candidates:
        cleaned = normalize_hardware_label_text(candidate, fallback="")
        if not cleaned:
            continue
        if first_cleaned is None:
            first_cleaned = cleaned
        if not is_generic_hardware_label(clean_hardware_name(cleaned, fallback="")):
            return cleaned
    return first_cleaned or fallback


def normalize_hardware_label_text(value: Any, fallback: str = "Unknown device") -> str:
    text = str(value).strip() if value is not None else ""
    if not text:
        return fallback
    text = re.sub(r"\s*\[[0-9a-fA-F]{4}:[0-9a-fA-F]{4}\]\s*", " ", text)
    text = re.sub(r"\s+", " ", text).strip(" -_:,")
    return text or fallback


def label_with_vendor(vendor: Any, label: str) -> str:
    vendor_text = normalize_hardware_label_text(vendor, fallback="")
    label_text = str(label).strip() if label is not None else ""
    if not vendor_text or not label_text:
        return label_text or vendor_text
    if label_text.lower().startswith(vendor_text.lower()):
        return label_text
    return f"{vendor_text} {label_text}"


def pcie_device_link_metadata(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "current_link_speed": device.get("current_link_speed"),
        "current_link_width": device.get("current_link_width"),
        "max_link_speed": device.get("max_link_speed"),
        "max_link_width": device.get("max_link_width"),
    }


def normalize_iommu_group(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if re.fullmatch(r"\d+", text) else None


def pci_label_with_iommu_group(label: str, iommu_group: Any) -> str:
    group = normalize_iommu_group(iommu_group)
    return f"{label} [IOMMU Group: {group}]" if group else label


def pci_root_complex_by_domain(devices: list[dict[str, Any]]) -> dict[str, str]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        domain = pci_domain_from_path(device.get("physical_path"))
        slot = device.get("slot")
        if domain is None or not slot:
            continue
        grouped.setdefault(domain[0], []).append(device)

    result: dict[str, str] = {}
    for domain_name, domain_devices in grouped.items():
        preferred = [
            device
            for device in domain_devices
            if "root complex" in str(device.get("device_name") or "").lower()
        ]
        if not preferred:
            preferred = [
                device
                for device in domain_devices
                if str(device.get("class_id") or "").lower().startswith("0600")
            ]
        if not preferred:
            continue
        selected = sorted(
            preferred, key=lambda item: natural_key(str(item.get("slot") or ""))
        )[0]
        slot = selected.get("slot")
        if slot:
            result[domain_name] = slot
    return result


GENERIC_HARDWARE_LABELS = {
    "audio",
    "card",
    "device",
    "generic",
    "hub",
    "input",
    "nvme",
    "otg",
    "unknown",
    "unknowndevice",
    "amdgpu",
    "asus",
    "asusec",
    "drivetemp",
    "k10temp",
}


def clean_hardware_name(value: Any, fallback: str = "Unknown device") -> str:
    return normalize_hardware_label_text(value, fallback=fallback)


def strip_company_name(value: Any, *companies: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    for company in companies:
        raw_company = str(company).strip() if company is not None else ""
        normalized_company = normalize_hardware_label_text(raw_company, fallback="")
        for prefix in (raw_company, normalized_company):
            if not prefix:
                continue
            text = re.sub(
                rf"^{re.escape(prefix)}(?:\s+|[-_:,]+)", "", text, flags=re.IGNORECASE
            ).strip()
    return text or None


def is_generic_hardware_label(label: str) -> bool:
    normalized = re.sub(r"[^A-Za-z0-9]+", "", label).lower()
    if normalized in GENERIC_HARDWARE_LABELS:
        return True
    if re.fullmatch(
        r"(audio|card|event|generic|hidraw|input|mouse|otg|renderd|tty)\d*", normalized
    ):
        return True
    if re.fullmatch(
        r"(nvme\d+n\d+(p\d+)?|sd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*)", normalized
    ):
        return True
    return False


def sensor_channel_label(
    channel_key: str, channel: Any, *, read_value: bool = False
) -> str:
    if isinstance(channel, dict):
        label = str(channel.get("label") or "").strip()
        if not label and "input" not in channel:
            return ""
    else:
        label = ""
    label = label or str(channel_key).strip()
    sensor_type = sensor_channel_type(channel_key)
    label = f"{sensor_type}: {label}" if sensor_type else label
    if read_value and isinstance(channel, dict):
        value = sensor_channel_value_text(channel_key, channel)
        if value:
            label = f"{label}: {value}"
    return label


def sensor_channel_type(channel_key: str) -> str:
    match = re.match(r"([a-zA-Z]+)", channel_key)
    prefix = match.group(1).lower() if match else ""
    return {
        "curr": "current",
        "energy": "energy",
        "fan": "fan",
        "humidity": "humidity",
        "in": "voltage",
        "power": "power",
        "pwm": "pwm",
        "temp": "temperature",
    }.get(prefix, "")


def sensor_channel_value_text(channel_key: str, channel: dict[str, Any]) -> str:
    raw_value = channel.get("input")
    if raw_value is None:
        return ""
    value = parse_sensor_channel_value(raw_value)
    if value is None:
        return ""
    prefix = sensor_channel_prefix(channel_key)
    if prefix == "temp":
        return f"{value / 1000:.1f}C"
    if prefix == "fan":
        return f"{int(round(value))} RPM"
    if prefix == "in":
        return f"{value / 1000:g}V"
    if prefix == "curr":
        return f"{value / 1000:g}A"
    if prefix == "power":
        return f"{value / 1_000_000:g}W"
    if prefix == "energy":
        return f"{value / 1_000_000:g}J"
    if prefix == "humidity":
        return f"{value / 1000:g}%"
    if prefix == "pwm":
        return f"{int(round(value))}"
    return f"{value:g}"


def parse_sensor_channel_value(value: Any) -> float | None:
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def sensor_channel_prefix(channel_key: str) -> str:
    match = re.match(r"([a-zA-Z]+)", channel_key)
    return match.group(1).lower() if match else ""


def normalize_numa_index(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def numa_sort_key(value: Any) -> tuple[int, int | str]:
    normalized = normalize_numa_index(value)
    if normalized is None:
        return (1, str(value))
    return (0, normalized)


def cpu_node_label(model: Any, node_index: Any) -> str:
    label = normalize_hardware_label_text(model, fallback="Processor")
    normalized = normalize_numa_index(node_index)
    if normalized is None:
        return label
    return f"{label} (NUMA {normalized})"


def memory_slot_label(slot: dict[str, Any], *, show_vendor: bool = False) -> str:
    label = memory_slot_address(slot)
    module_text = memory_module_text(slot, show_vendor=show_vendor)
    return f"{label} ({module_text})" if module_text else label


def memory_slot_address(slot: dict[str, Any]) -> str:
    bank = clean_hardware_name(slot.get("bank_locator"), fallback="")
    locator = clean_hardware_name(slot.get("locator"), fallback="")
    if bank and locator and locator.lower() not in bank.lower():
        return f"{bank} {locator}"
    return bank or locator or clean_hardware_name(slot.get("entry"), fallback="DIMM")


def memory_module_text(slot: dict[str, Any], *, show_vendor: bool) -> str:
    parts: list[str] = []
    if show_vendor:
        manufacturer = normalize_hardware_label_text(
            slot.get("manufacturer"), fallback=""
        )
        if manufacturer:
            parts.append(manufacturer)
    part_number = normalize_hardware_label_text(slot.get("part_number"), fallback="")
    if part_number:
        parts.append(part_number)
    capacity = memory_capacity_text(slot.get("size_bytes"))
    if capacity:
        parts.append(capacity)
    if slot.get("ecc") is True:
        parts.append("ECC")
    return " ".join(parts)


def memory_capacity_text(size_bytes: Any) -> str:
    try:
        size = int(size_bytes)
    except (TypeError, ValueError):
        return ""
    if size <= 0:
        return ""
    gib = size / (1024**3)
    if gib.is_integer():
        capacity = f"{int(gib)}GB"
    else:
        capacity = f"{gib:.1f}".rstrip("0").rstrip(".") + "GB"
    return capacity


def memory_edge_label(metadata: dict[str, Any]) -> str:
    memory_type = clean_hardware_name(metadata.get("memory_type"), fallback="").replace(
        " ", ""
    )
    speed = metadata.get("configured_speed_mt_s") or metadata.get("speed_mt_s")
    if memory_type and speed:
        return f"{memory_type}-{speed} MT/s"
    return "DIMM channel"


def pcie_edge_label(metadata: dict[str, Any]) -> str:
    speed = metadata.get("current_link_speed") or metadata.get("max_link_speed")
    width = metadata.get("current_link_width") or metadata.get("max_link_width")
    generation = pcie_generation(speed)
    width_text = f"x{width}" if width else ""
    if generation and width_text:
        return f"PCIe {generation} {width_text}"
    return ""


def pcie_generation(speed: Any) -> str | None:
    if speed is None:
        return None
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", str(speed))
    if not match:
        return None
    value = match.group(1).rstrip("0").rstrip(".")
    return {
        "2.5": "1.0",
        "5": "2.0",
        "8": "3.0",
        "16": "4.0",
        "32": "5.0",
        "64": "6.0",
    }.get(value)


def usb_edge_label(metadata: dict[str, Any]) -> str:
    version = normalize_usb_version(metadata.get("usb_version"))
    speed = format_usb_speed(metadata.get("speed_mbps"))
    parts = ["USB"]
    if version:
        parts.append(version)
    if speed:
        parts.append(speed)
    return " ".join(parts) if version and speed else "USB"


def usb_root_hub_label(device: dict[str, Any]) -> str:
    version = normalize_usb_version(device.get("usb_version"))
    if version:
        return f"USB {version} Root Hub"
    return "USB Root Hub"


def normalize_usb_version(version: Any) -> str | None:
    if version is None:
        return None
    text = str(version).strip()
    if not text:
        return None
    if "." in text:
        major, minor = text.split(".", 1)
        major = major.lstrip("0") or "0"
        minor_value = parse_int(minor)
        if major == "2":
            return "2.0"
        if minor_value is not None:
            return f"{major}.{minor_value // 10 if minor_value >= 10 else minor_value}"
        minor = minor.rstrip("0")
        return f"{major}.{minor or '0'}"
    return text


def format_usb_speed(speed_mbps: Any) -> str | None:
    if speed_mbps is None or speed_mbps == "":
        return None
    try:
        value = float(str(speed_mbps).strip())
    except ValueError:
        return str(speed_mbps)
    if value >= 1000:
        gbps = value / 1000
        return f"{gbps:g} Gb/s"
    return f"{value:g} Mb/s"


def detail(label: str, value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        value = "yes" if value else "no"
    return f"{label}: {value}"


def suffix(value: Any, unit: str) -> str | None:
    if value is None or value == "":
        return None
    return f"{value} {unit}"


def join_nonempty(*parts: Any) -> str | None:
    values = [str(part) for part in parts if part is not None and str(part) != ""]
    if not values:
        return None
    return " ".join(values)
