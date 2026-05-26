# toposcope

`toposcope` collects Linux hardware topology from the machine it is running on and
renders the result as a CPU-centered SVG block diagram.

The collector intentionally avoids parsing command output from tools such as
`lspci`, `lsusb`, `lsblk`, `dmidecode`, or `ethtool`. It reads stable kernel and
firmware interfaces directly, primarily:

- `/sys/class/dmi/id`
- `/sys/firmware/dmi/entries`
- `/sys/devices/system/cpu`
- `/sys/devices/system/memory`
- `/sys/bus/pci/devices`
- `/sys/bus/usb/devices`
- `/sys/block`
- `/sys/class/net`
- `/sys/class/infiniband`
- `/sys/class/bluetooth`
- `/sys/class/drm`
- `/sys/class/sound`
- `/proc/asound/card*/codec#*`, `/proc/asound/card*/eld#*`, and `/proc/asound/card*/stream*`
- `/sys/class/input`
- `/sys/class/power_supply`
- `/sys/class/thermal`
- `/sys/class/hwmon`
- `/proc/cpuinfo`, `/proc/meminfo`, and a small set of other `/proc` files

Bluetooth controller version and capability fields are read through the kernel
Bluetooth management socket when it is available.

For PCI and USB device/vendor names, toposcope reads local `pci.ids` and
`usb.ids` databases directly when they are installed. This matches the data
source commonly used by tools such as `lspci`/`lsusb` without parsing command
output.

The diagram is topology-first. It does not place every device directly under the
CPU. Parent-child edges are derived from sysfs ancestry, so PCIe endpoints hang
from their upstream root port, bridge, or switch port; USB devices hang from
their real root bus or hub; I2C/SPI devices hang from their controller bus; and
hwmon sensors hang from the collected device that owns them. Kernel-only class
interfaces such as block devices, network interfaces, DRM nodes, sound cards,
and input devices are collected for context but are not rendered as topology
nodes, except when they belong to the ACPI branch. The renderer places
memory to the right of the CPU, PCIe below-right of the CPU, ACPI
below-left of the CPU, and other buses to the left.
Each CPU NUMA node is rendered as a separate top-level CPU node.

Each node box contains only the hardware name. By default, vendor/manufacturer
prefixes are included when the collector can read them; `--no-vendor` suppresses
those structured prefixes. Link labels carry the bus name and available link
bandwidth, such as `PCIe 4.0 x4` or `USB 3.2 5 Gb/s`.

Hostnames, virtual-only devices, SR-IOV virtual functions, and standalone
top-level ACPI namespace listings are intentionally omitted from the generated
outputs. Platform devices that originate from ACPI firmware remain under the
ACPI node.

## Setup

This repository path is also the virtual environment root. Activate it first:

```bash
source bin/activate
```

Install the package in editable mode so the `toposcope` command and its Python
dependencies are available in the venv:

```bash
python -m pip install -e .
```

The only runtime Python dependency is `pyroute2`, used for direct netlink
ethtool queries instead of parsing `ethtool` command output.

## Usage

Generate the default SVG diagram:

```bash
toposcope
```

By default this writes `./toposcope.svg`.

Choose a different SVG path:

```bash
toposcope -o hardware.svg
```

Exclude USB endpoint devices while keeping USB controllers, root buses, and hubs:

```bash
toposcope --no-usb-dev -o hardware.svg
```

Suppress vendor/manufacturer prefixes in node labels:

```bash
toposcope --no-vendor -o hardware.svg
```

Hide Ethernet and InfiniBand physical port nodes behind NIC devices while still
showing the NIC devices themselves:

```bash
toposcope --no-net-dev -o hardware.svg
```

Hide connected display device nodes while keeping GPU display port nodes:

```bash
toposcope --no-display -o hardware.svg
```

Hide connected audio endpoint nodes while keeping audio port nodes:

```bash
toposcope --no-audio-jack -o hardware.svg
```

Render a synthetic multi-NUMA view by copying NUMA node 0 and its visible
device tree four times. The synthetic CPU nodes are placed left-to-right, with
Memory, PCI, and ACPI branches aligned across NUMA nodes:

```bash
toposcope --test-numa 4 -o out/test-numa.svg
```

The command-line interface intentionally exposes:

- `-o, --output`
- `--no-usb-dev`
- `--no-pci-bridge`
- `--no-addr`
- `--no-vendor`
- `--no-net-dev`
- `--no-net-status`
- `--no-wifi`
- `--no-bluetooth`
- `--no-display`
- `--no-display-status`
- `--no-audio-jack`
- `--read-sensor`
- `--no-sensor`
- `--test-numa`

## Current Collector Coverage

- Platform, firmware, BIOS, baseboard, chassis, and device-tree identity
- CPU summary, logical processors, topology, frequency, caches, and NUMA
- Memory totals, populated SMBIOS Type 17 memory slots, memory blocks, EDAC memory controllers, DIMM/rank metadata, and NVDIMM metadata
- PCI devices, drivers, classes, resources, NUMA nodes, and IOMMU groups
- USB devices, configurations, classes, speeds, power, and interfaces
- Bluetooth host adapters, versions, and supported/current controller capabilities
- Block storage, network, RDMA/InfiniBand, DRM, sound, and input data for non-rendered context
- HDA analog/HDMI/DisplayPort audio pins and USB Audio stream endpoints as rendered port nodes
- Power supplies, batteries, thermal zones, cooling devices, and hwmon sensors
- I2C, SPI, platform, and serio bus device summaries
- CPU-centered hardware topology tree connecting buses, switches, hubs, controllers, endpoints, and sensors by sysfs parentage

Some firmware fields and serial numbers may require elevated privileges or may be
withheld by the kernel, firmware, hypervisor, or device driver. Missing fields
are omitted rather than guessed.
