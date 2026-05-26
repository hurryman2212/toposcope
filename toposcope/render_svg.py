from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path
from textwrap import wrap
from typing import Any

from .topology import build_topology_report

ATTACHED_NODE_GAP = 3
DIRECTIONAL_TREE_GAP = 20
VERTICAL_TREE_GAP = 14

PALETTE = {
    "cpu": ("#111111", "#ffffff", "#6b7280"),
    "numa": ("#e8f1ff", "#10213f", "#2d6cdf"),
    "memory-controller": ("#14532d", "#ffffff", "#22c55e"),
    "dimm": ("#ffffff", "#082516", "#047836"),
    "pcie-fabric": ("#fff4dd", "#35230a", "#c07a00"),
    "pcie-endpoint": ("#ffffff", "#1d2733", "#c07a00"),
    "usb-root": ("#0f5f63", "#ffffff", "#22c7cf"),
    "usb-hub": ("#edfafa", "#102728", "#178f96"),
    "usb-device": ("#ffffff", "#1d2733", "#178f96"),
    "storage-controller": ("#f1edff", "#21183a", "#7357d3"),
    "block-device": ("#ffffff", "#1d2733", "#7357d3"),
    "partition": ("#fbfaff", "#21183a", "#9b87e0"),
    "network-interface": ("#ecfdf3", "#102719", "#1f9d61"),
    "network-port": ("#ecfdf3", "#102719", "#1f9d61"),
    "bluetooth-adapter": ("#1e3a8a", "#ffffff", "#60a5fa"),
    "graphics-device": ("#eef7ff", "#10213f", "#2d83c6"),
    "display-connector": ("#f7fbff", "#10213f", "#5c9dd3"),
    "display-device": ("#ffffff", "#10213f", "#5c9dd3"),
    "sound-card": ("#f6f0ff", "#21183a", "#8a63d2"),
    "audio-port": ("#fff7fb", "#351527", "#c04f8d"),
    "audio-stream-port": ("#fff7fb", "#351527", "#c04f8d"),
    "audio-device": ("#ffffff", "#351527", "#c04f8d"),
    "platform-bus": ("#f3f5f8", "#1c2430", "#64748b"),
    "platform-device": ("#ffffff", "#1d2733", "#64748b"),
    "i2c-bus": ("#f5f0ff", "#25143f", "#7c3aed"),
    "i2c-device": ("#ffffff", "#25143f", "#7c3aed"),
    "spi-bus": ("#f0fdfa", "#102728", "#0f9488"),
    "spi-device": ("#ffffff", "#1d2733", "#0f9488"),
    "serio-bus": ("#fff7ed", "#35230a", "#d97706"),
    "serio-device": ("#ffffff", "#1d2733", "#d97706"),
    "resource": ("#f8fafc", "#1d2733", "#94a3b8"),
    "sensor-device": ("#fff0f0", "#391616", "#c24747"),
    "power-device": ("#fffbea", "#35230a", "#ca8a04"),
    "thermal-device": ("#fff0f0", "#391616", "#c24747"),
    "other": ("#ffffff", "#1d2733", "#9aa6b2"),
}


@dataclass
class Row:
    render_id: str
    node: dict[str, Any]
    depth: int
    parent_id: str | None
    zone: str = "right"
    attached: bool = False
    x: float = 0
    y: float = 0
    width: float = 0
    height: float = 0
    lines: list[str] | None = None

    @property
    def left(self) -> float:
        return self.x

    @property
    def right(self) -> float:
        return self.x + self.width

    @property
    def bottom(self) -> float:
        return self.y + self.height

    @property
    def cx(self) -> float:
        return self.x + self.width / 2

    @property
    def cy(self) -> float:
        return self.y + self.height / 2


def render_svg(
    report: dict[str, Any], output_path: Path, *, max_items_per_section: int = 0
) -> None:
    output_path.write_text(
        build_svg(report, max_items_per_section=max_items_per_section), encoding="utf-8"
    )


def build_svg(report: dict[str, Any], *, max_items_per_section: int = 0) -> str:
    topology = report.get("topology") or build_topology_report(report)
    root = topology.get("root") or {}
    row_groups = flatten_groups(root, max_children=max_items_per_section)
    if not row_groups:
        row_groups = [
            [
                Row(
                    "empty",
                    {"label": "No topology data", "kind": "other"},
                    0,
                    None,
                    "root",
                )
            ]
        ]
    rows = [row for group in row_groups for row in group]

    margin_x = 36
    margin_y = 32
    indent = 560
    box_width = 276
    section_gap = 64

    for row in rows:
        row.width = box_width
        row.lines = node_lines(row.node)
        row.height = box_height(row.lines, row.node.get("kind"))

    group_bottoms: list[float] = []
    if uses_multi_cpu_layout(row_groups):
        group_bottoms = layout_multi_cpu_groups(
            row_groups,
            margin_x,
            margin_y,
            indent,
            box_width,
            section_gap,
        )
    else:
        left_units = max((max(0, -relative_x_units(row)) for row in rows), default=0)
        cpu_x = margin_x + left_units * indent
        y_cursor = margin_y
        for group in row_groups:
            if not group:
                continue
            root_row = group[0]
            root_row.x = cpu_x
            root_row.y = y_cursor
            group_bottom = layout_group_branches(
                group, cpu_x, root_row.y, indent, section_gap
            )
            group_bottoms.append(group_bottom)
            y_cursor = group_bottom + section_gap

    shift_rows_into_view(rows, margin_x)
    canvas_width = max((row.right for row in rows), default=box_width) + margin_x
    canvas_height = max(group_bottoms or [margin_y]) + margin_y + 20
    row_by_id = {row.render_id: row for row in rows}

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas_width:.0f}" '
            f'height="{canvas_height:.0f}" viewBox="0 0 {canvas_width:.0f} {canvas_height:.0f}" '
            'role="img" aria-label="toposcope topology block diagram">'
        ),
        "<defs>",
        "<style>",
        """
        .bg { fill: #f8fafc; }
        .box { stroke-width: 1.15; rx: 7; ry: 7; }
        .node-text { font: 600 13px ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
        .edge-label { font: 10px ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
        .edge-label-bg { fill: #f8fafc; opacity: 0.96; rx: 3; ry: 3; }
        .meta { font: 11px ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
        .link { fill: none; stroke: #8aa0b6; stroke-width: 1.2; stroke-linecap: round; stroke-linejoin: round; }
        .unlabeled-link { stroke-dasharray: 5 5; }
        .iommu-group-box { fill: #fff7ed; fill-opacity: 0.16; stroke: #c07a00; stroke-width: 1.1; stroke-dasharray: 7 4; rx: 9; ry: 9; }
        .accent { opacity: 0.95; }
        """,
        "</style>",
        "</defs>",
        f'<rect class="bg" x="0" y="0" width="{canvas_width:.0f}" height="{canvas_height:.0f}"/>',
    ]

    parts.extend(render_iommu_group_boxes(rows, row_by_id))

    for edge in render_cpu_peer_edges(row_groups):
        parts.append(edge)

    edge_labels: list[str] = []
    bundled_child_ids: set[str] = set()
    for parent, children in collect_edge_bundles(rows, row_by_id):
        path, label = render_edge_bundle(parent, children)
        parts.append(path)
        bundled_child_ids.update(child.render_id for child in children)
        if label:
            edge_labels.append(label)

    for row in rows:
        if not row.parent_id:
            continue
        if row.attached:
            continue
        if row.render_id in bundled_child_ids:
            continue
        parent = row_by_id.get(row.parent_id)
        if parent is None:
            continue
        path, label = render_edge(parent, row)
        parts.append(path)
        if label:
            edge_labels.append(label)

    for row in rows:
        parts.extend(render_box(row))
    parts.extend(edge_labels)

    summary = topology.get("summary", {})
    summary_text = (
        f"nodes={summary.get('node_count', len(rows))} "
        f"edges={summary.get('edge_count', max(0, len(rows) - 1))} "
        "layout=topology"
    )
    parts.append(
        f'<text class="meta" x="{margin_x:.1f}" y="{canvas_height - 12:.1f}" fill="#475569">{escape(summary_text)}</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def flatten_groups(root: dict[str, Any], *, max_children: int) -> list[list[Row]]:
    if is_hidden_root(root):
        used_ids: set[str] = set()
        groups: list[list[Row]] = []
        for child in root.get("children") or []:
            if is_hidden_root(child):
                continue
            group = flatten_tree(child, max_children=max_children, used_ids=used_ids)
            if group:
                groups.append(group)
        return groups
    return [flatten_tree(root, max_children=max_children)]


def is_hidden_root(node: dict[str, Any]) -> bool:
    return bool(node.get("hidden")) or node.get("kind") == "topology-root"


def flatten_tree(
    root: dict[str, Any], *, max_children: int, used_ids: set[str] | None = None
) -> list[Row]:
    rows: list[Row] = []
    seen_ids = used_ids if used_ids is not None else set()

    def make_render_id(base_id: str) -> str:
        render_id = base_id
        if render_id in seen_ids:
            render_id = f"{base_id}#{len(seen_ids)}"
        seen_ids.add(render_id)
        return render_id

    def visit(
        node: dict[str, Any], depth: int, parent_id: str | None, zone: str
    ) -> None:
        base_id = str(node.get("id") or f"node-{len(rows)}")
        render_id = make_render_id(base_id)
        attached = bool(node.get("attached"))
        row = Row(render_id, node, depth, parent_id, zone, attached)
        rows.append(row)
        children = list(node.get("children") or [])
        attached_children = [child for child in children if child.get("attached")]
        normal_children = [child for child in children if not child.get("attached")]
        visible_children = children
        omitted = 0
        if max_children > 0 and len(normal_children) > max_children:
            visible_children = normal_children[:max_children]
            omitted = len(normal_children) - max_children
        else:
            visible_children = normal_children
        for child in attached_children:
            next_zone = child_zone(zone)
            visit(child, depth, render_id, next_zone)
        for child in visible_children:
            visit(child, depth + 1, render_id, child_zone(zone))
        if omitted:
            visit(
                {
                    "id": f"{base_id}:omitted",
                    "label": f"{omitted} more child nodes in JSON topology",
                    "kind": "other",
                    "details": [
                        "Render with a higher child limit or 0 for unlimited rendering"
                    ],
                },
                depth + 1,
                render_id,
                zone,
            )

    root_id = make_render_id(str(root.get("id") or "root"))
    rows.append(Row(root_id, root, 0, None, "root"))
    children = list(root.get("children") or [])
    memory_children = [
        child for child in children if child.get("kind") == "memory-controller"
    ]
    pci_children = [child for child in children if is_pci_child(child)]
    platform_children = [child for child in children if is_platform_child(child)]
    remaining_children = [
        child
        for child in children
        if child.get("kind") != "memory-controller"
        and not is_pci_child(child)
        and not is_platform_child(child)
    ]
    for child in memory_children:
        visit(child, 1, root_id, "right")
    for child in pci_children:
        visit(child, 1, root_id, "pci")
    for child in platform_children:
        visit(child, 1, root_id, "platform")
    for child in remaining_children:
        visit(child, 1, root_id, "left")
    return rows


def is_pci_child(node: dict[str, Any]) -> bool:
    return (
        str(node.get("id") or "").startswith("pci:")
        or node.get("kind") == "pcie-fabric"
    )


def is_platform_child(node: dict[str, Any]) -> bool:
    node_id = str(node.get("id") or "")
    return (
        node.get("kind") == "platform-bus"
        or node_id == "bus:platform"
        or node_id.startswith("bus:platform@")
    )


def child_zone(parent_zone: str) -> str:
    if parent_zone in {"right", "memory-right"}:
        return "memory-right"
    if parent_zone in {"pci", "pci-right"}:
        return "pci-right"
    if parent_zone in {"platform", "platform-left"}:
        return "platform-left"
    return parent_zone


def uses_multi_cpu_layout(row_groups: list[list[Row]]) -> bool:
    if len(row_groups) < 2:
        return False
    return all(group and group[0].node.get("kind") == "cpu" for group in row_groups)


def layout_multi_cpu_groups(
    row_groups: list[list[Row]],
    margin_x: float,
    margin_y: float,
    indent: float,
    box_width: float,
    section_gap: float,
) -> list[float]:
    group_sections = [split_group_sections(group) for group in row_groups]
    all_rows = [row for group in row_groups for row in group]
    left_units = max((max(0, -relative_x_units(row)) for row in all_rows), default=0)
    right_units = max((max(0, relative_x_units(row)) for row in all_rows), default=0)
    column_stride = max(
        box_width + 96,
        (left_units + right_units) * indent + box_width + 96,
    )
    first_cpu_x = margin_x + left_units * indent
    for index, group in enumerate(row_groups):
        if not group:
            continue
        root_row = group[0]
        root_row.x = first_cpu_x + index * column_stride
        root_row.y = margin_y

    cpu_bottom = max(
        (group[0].bottom for group in row_groups if group), default=margin_y
    )
    section_start_y = cpu_bottom + section_gap
    group_bottoms = [group[0].bottom if group else margin_y for group in row_groups]

    memory_bottom = layout_multi_cpu_section(
        row_groups,
        group_sections,
        "memory",
        section_start_y,
        indent,
        group_bottoms,
    )
    platform_bottom = layout_multi_cpu_section(
        row_groups,
        group_sections,
        "platform",
        section_start_y,
        indent,
        group_bottoms,
    )
    pci_start_y = max(cpu_bottom + section_gap, memory_bottom + section_gap)
    pci_bottom = layout_multi_cpu_section(
        row_groups,
        group_sections,
        "pci",
        pci_start_y,
        indent,
        group_bottoms,
    )
    other_start_y = max(pci_bottom, platform_bottom, pci_start_y)
    if other_start_y > pci_start_y:
        other_start_y += section_gap
    layout_multi_cpu_section(
        row_groups,
        group_sections,
        "other",
        other_start_y,
        indent,
        group_bottoms,
    )

    return group_bottoms


def layout_multi_cpu_section(
    row_groups: list[list[Row]],
    group_sections: list[dict[str, list[Row]]],
    section: str,
    start_y: float,
    indent: float,
    group_bottoms: list[float],
    zones: set[str] | None = None,
) -> float:
    section_bottom = start_y
    placed = False
    for group_index, (group, sections) in enumerate(zip(row_groups, group_sections)):
        if not group:
            continue
        rows = [
            row
            for row in sections.get(section, [])
            if zones is None or row.zone in zones
        ]
        if not rows:
            continue
        placed = True
        cpu_x = group[0].x
        if section in {"memory", "pci", "platform"}:
            bottom = layout_directional_tree(
                rows,
                start_y,
                lambda row, base_x=cpu_x: base_x + relative_x_units(row) * indent,
            )
        else:
            bottom = layout_vertical(
                rows,
                start_y,
                lambda row, base_x=cpu_x: base_x + relative_x_units(row) * indent,
            )
        section_bottom = max(section_bottom, bottom)
        group_bottoms[group_index] = max(group_bottoms[group_index], bottom)
    return section_bottom if placed else start_y


def split_group_sections(group: list[Row]) -> dict[str, list[Row]]:
    if not group:
        return {}
    root_id = group[0].render_id
    row_by_id = {row.render_id: row for row in group}
    result: dict[str, list[Row]] = {
        "memory": [],
        "pci": [],
        "platform": [],
        "other": [],
    }
    for row in group[1:]:
        top = top_level_row(row, root_id, row_by_id)
        result[section_for_top_level_row(top)].append(row)
    return result


def top_level_row(row: Row, root_id: str, row_by_id: dict[str, Row]) -> Row:
    current = row
    while current.parent_id and current.parent_id != root_id:
        parent = row_by_id.get(current.parent_id)
        if parent is None:
            break
        current = parent
    return current


def section_for_top_level_row(row: Row) -> str:
    node = row.node
    kind = node.get("kind")
    if kind == "memory-controller":
        return "memory"
    if is_pci_child(node):
        return "pci"
    if is_platform_child(node):
        return "platform"
    return "other"


def relative_x_units(row: Row) -> int:
    if row.zone == "right":
        return row.depth
    if row.zone == "pci":
        return 0
    if row.zone == "pci-right":
        return row.depth - 1
    if row.zone == "memory-right":
        return row.depth
    if row.zone == "platform":
        return -1
    if row.zone == "platform-left":
        return -row.depth
    if row.zone == "left":
        return -row.depth
    return row.depth


def shift_rows_into_view(rows: list[Row], margin_x: float) -> None:
    min_left = min((row.left for row in rows), default=margin_x)
    if min_left >= margin_x:
        return
    shift = margin_x - min_left
    for row in rows:
        row.x += shift


def layout_group_branches(
    group: list[Row],
    cpu_x: float,
    branch_start_y: float,
    indent: float,
    section_gap: float,
) -> float:
    if not group:
        return branch_start_y
    root_row = group[0]
    group_left_rows = [row for row in group if row.zone == "left"]
    group_memory_rows = [row for row in group if row.zone in {"right", "memory-right"}]
    group_pci_rows = [row for row in group if row.zone in {"pci", "pci-right"}]
    group_platform_rows = [
        row for row in group if row.zone in {"platform", "platform-left"}
    ]

    memory_start_y = directional_branch_start_y(
        root_row, group_memory_rows, branch_start_y
    )
    right_end = layout_directional_tree(
        group_memory_rows,
        memory_start_y,
        lambda row: cpu_x + relative_x_units(row) * indent,
    )
    platform_start_y = directional_branch_start_y(
        root_row, group_platform_rows, branch_start_y
    )
    platform_end = layout_directional_tree(
        group_platform_rows,
        platform_start_y,
        lambda row: cpu_x + relative_x_units(row) * indent,
    )
    pci_start = max(
        root_row.bottom + section_gap, right_end + section_gap, branch_start_y
    )
    pci_end = layout_directional_tree(
        group_pci_rows,
        pci_start,
        lambda row: cpu_x + relative_x_units(row) * indent,
    )
    other_start = max(pci_end, platform_end, pci_start)
    if group_left_rows and other_start > pci_start:
        other_start += section_gap
    left_end = layout_vertical(
        group_left_rows,
        other_start,
        lambda row: cpu_x + relative_x_units(row) * indent,
    )

    return max(root_row.bottom, left_end, right_end, pci_end, platform_end)


def layout_vertical(rows: list[Row], start_y: float, x_for_row: Any) -> float:
    y = start_y
    previous: Row | None = None
    for row in rows:
        row.x = x_for_row(row)
        if previous is None:
            row.y = y
        else:
            gap = ATTACHED_NODE_GAP if row.attached else VERTICAL_TREE_GAP
            row.y = previous.bottom + gap
        previous = row
        y = row.bottom + VERTICAL_TREE_GAP
    return y


def layout_directional_tree(rows: list[Row], start_y: float, x_for_row: Any) -> float:
    if not rows:
        return start_y

    for row in rows:
        row.x = x_for_row(row)

    children_by_parent, roots = directional_tree_relationships(rows)
    top_overhang_cache: dict[str, float] = {}

    def place_attached(parent: Row, attached_children: list[Row]) -> float:
        y = parent.bottom + ATTACHED_NODE_GAP
        bottom = parent.bottom
        for child in attached_children:
            child.x = parent.x
            child.y = y
            bottom = max(bottom, child.bottom)
            y = child.bottom + ATTACHED_NODE_GAP
        return bottom

    def place_subtree_at(row: Row, y: float) -> tuple[float, float]:
        row.y = y
        top = row.y
        children = children_by_parent.get(row.render_id, [])
        attached_children = [child for child in children if child.attached]
        normal_children = [child for child in children if not child.attached]

        bottom = place_attached(row, attached_children)
        next_y = max(row.bottom, bottom) + DIRECTIONAL_TREE_GAP
        for index, child in enumerate(normal_children):
            if index == 0:
                child_y = first_child_y(row, child)
            else:
                child_y = next_y + directional_subtree_top_overhang(
                    child, children_by_parent, top_overhang_cache
                )
            child_top, child_bottom = place_subtree_at(child, child_y)
            top = min(top, child_top)
            bottom = max(bottom, child_bottom)
            next_y = max(next_y, child_bottom + DIRECTIONAL_TREE_GAP)
        return top, max(bottom, row.bottom)

    cursor = start_y
    bottom = start_y
    for root in roots:
        root_top, root_bottom = place_subtree_at(
            root,
            cursor
            + directional_subtree_top_overhang(
                root, children_by_parent, top_overhang_cache
            ),
        )
        bottom = max(bottom, root_bottom)
        cursor = max(root_top, root_bottom) + DIRECTIONAL_TREE_GAP
    return bottom + DIRECTIONAL_TREE_GAP


def directional_tree_relationships(
    rows: list[Row],
) -> tuple[dict[str, list[Row]], list[Row]]:
    row_by_id = {row.render_id: row for row in rows}
    children_by_parent: dict[str, list[Row]] = {}
    roots: list[Row] = []
    for row in rows:
        parent_id = row.parent_id or ""
        if parent_id in row_by_id:
            children_by_parent.setdefault(parent_id, []).append(row)
        else:
            roots.append(row)
    return children_by_parent, roots


def directional_subtree_top_overhang(
    row: Row,
    children_by_parent: dict[str, list[Row]],
    cache: dict[str, float] | None = None,
) -> float:
    if cache is None:
        cache = {}
    cached = cache.get(row.render_id)
    if cached is not None:
        return cached
    children = children_by_parent.get(row.render_id, [])
    normal_children = [child for child in children if not child.attached]
    if not normal_children:
        cache[row.render_id] = 0
        return 0
    first = normal_children[0]
    first_top = first_child_relative_y(row, first) - directional_subtree_top_overhang(
        first, children_by_parent, cache
    )
    overhang = max(0.0, -first_top)
    cache[row.render_id] = overhang
    return overhang


def first_child_relative_y(parent: Row, child: Row) -> float:
    if aligns_first_child_center(parent, child):
        return parent.height / 2 - child.height / 2
    return 0


def first_child_y(parent: Row, child: Row) -> float:
    if aligns_first_child_center(parent, child):
        return parent.cy - child.height / 2
    return parent.y


def aligns_first_child_center(parent: Row, child: Row) -> bool:
    return (
        (parent.zone in {"pci", "pci-right"} and child.zone in {"pci", "pci-right"})
        or (parent.zone in {"right", "memory-right"} and child.zone == "memory-right")
        or (
            parent.zone in {"platform", "platform-left"}
            and child.zone == "platform-left"
        )
    )


def directional_branch_start_y(
    root: Row, branch_rows: list[Row], minimum_y: float
) -> float:
    if not branch_rows:
        return minimum_y
    first = branch_rows[0]
    children_by_parent, _ = directional_tree_relationships(branch_rows)
    top_overhang = directional_subtree_top_overhang(first, children_by_parent)
    return max(minimum_y, root.cy - first.height / 2 - top_overhang)


def render_edge(parent: Row, child: Row) -> tuple[str, str | None]:
    edge_label = str(child.node.get("link") or "")
    if child.zone == "memory-right" and child.left >= parent.right:
        return render_side_edge(parent, child, edge_label, parent_side="right")
    if child.zone == "pci-right" and child.left >= parent.right:
        return render_side_edge(parent, child, edge_label, parent_side="right")
    if child.zone == "platform-left" and child.right <= parent.left:
        return render_side_edge(parent, child, edge_label, parent_side="left")
    if child.y >= parent.bottom:
        if child.cx < parent.left:
            start_x = parent.left + parent.width * 0.36
        elif child.cx > parent.right:
            start_x = parent.left + parent.width * 0.64
        else:
            start_x = parent.cx
        mid_y = parent.bottom + (child.y - parent.bottom) / 2
        path = (
            f'<path class="{link_class(edge_label)}" d="M {start_x:.1f} {parent.bottom:.1f} '
            f'V {mid_y:.1f} H {child.cx:.1f} V {child.y:.1f}"/>'
        )
        label_x = start_x + (child.cx - start_x) / 2
        label_width = abs(child.cx - start_x)
        return path, render_edge_label(edge_label, label_x, mid_y - 5, label_width)
    if child.left >= parent.right:
        gap = max(48.0, child.left - parent.right)
        mid_x = parent.right + gap / 2
        if abs(parent.cy - child.cy) < 1.0:
            path = f'<path class="{link_class(edge_label)}" d="M {parent.right:.1f} {parent.cy:.1f} H {child.left:.1f}"/>'
            return path, render_edge_label(edge_label, mid_x, child.cy - 5, gap)
        path = (
            f'<path class="{link_class(edge_label)}" d="M {parent.right:.1f} {parent.cy:.1f} '
            f'H {mid_x:.1f} V {child.cy:.1f} H {child.left:.1f}"/>'
        )
        return path, render_edge_label(edge_label, mid_x, child.cy - 5, gap)
    if child.right <= parent.left:
        gap = max(48.0, parent.left - child.right)
        mid_x = child.right + gap / 2
        if abs(parent.cy - child.cy) < 1.0:
            path = f'<path class="{link_class(edge_label)}" d="M {parent.left:.1f} {parent.cy:.1f} H {child.right:.1f}"/>'
            return path, render_edge_label(edge_label, mid_x, child.cy - 5, gap)
        path = (
            f'<path class="{link_class(edge_label)}" d="M {parent.left:.1f} {parent.cy:.1f} '
            f'H {mid_x:.1f} V {child.cy:.1f} H {child.right:.1f}"/>'
        )
        return path, render_edge_label(edge_label, mid_x, child.cy - 5, gap)
    mid_y = child.bottom + (parent.y - child.bottom) / 2
    path = (
        f'<path class="{link_class(edge_label)}" d="M {parent.cx:.1f} {parent.y:.1f} '
        f'V {mid_y:.1f} H {child.cx:.1f} V {child.bottom:.1f}"/>'
    )
    label_x = max(parent.right, child.right) + 16
    return path, render_edge_label(edge_label, label_x, mid_y + 4, 220, centered=False)


def render_iommu_group_boxes(rows: list[Row], row_by_id: dict[str, Row]) -> list[str]:
    children_by_parent: dict[str, list[Row]] = {}
    for row in rows:
        if row.parent_id:
            children_by_parent.setdefault(row.parent_id, []).append(row)

    anchors: dict[tuple[str, str], list[Row]] = {}
    for row in rows:
        group = explicit_iommu_group(row)
        if not group:
            continue
        scope = root_scope_id(row, row_by_id)
        key = (scope, group)
        anchors.setdefault(key, []).append(row)

    boxes: list[str] = []
    for (_, group), anchor_rows in anchors.items():
        group_rows = rows_for_iommu_group_box(anchor_rows, group, children_by_parent)
        pci_count = sum(
            1
            for row in anchor_rows
            if row.node.get("kind") in {"pcie-fabric", "pcie-endpoint"}
        )
        if pci_count < 2 and len(group_rows) == pci_count:
            continue
        boxes.append(render_iommu_group_box(group_rows))
    return boxes


def rows_for_iommu_group_box(
    anchor_rows: list[Row],
    group: str,
    children_by_parent: dict[str, list[Row]],
) -> list[Row]:
    included: dict[str, Row] = {}

    def visit(row: Row) -> None:
        explicit_group = explicit_iommu_group(row)
        if explicit_group and explicit_group != group:
            return
        included[row.render_id] = row
        for child in children_by_parent.get(row.render_id, []):
            visit(child)

    for anchor in anchor_rows:
        visit(anchor)
    return list(included.values())


def explicit_iommu_group(row: Row) -> str:
    return str(row.node.get("iommu_group") or "").strip()


def root_scope_id(row: Row, row_by_id: dict[str, Row]) -> str:
    current = row
    while current.parent_id:
        parent = row_by_id.get(current.parent_id)
        if parent is None:
            break
        current = parent
    return current.render_id


def render_iommu_group_box(rows: list[Row]) -> str:
    padding_x = 12
    padding_y = 10
    left = min(row.left for row in rows) - padding_x
    top = min(row.y for row in rows) - padding_y
    right = max(row.right for row in rows) + padding_x
    bottom = max(row.bottom for row in rows) + padding_y
    return (
        f'<rect class="iommu-group-box" x="{left:.1f}" y="{top:.1f}" '
        f'width="{right - left:.1f}" height="{bottom - top:.1f}" rx="9" ry="9"/>'
    )


def collect_edge_bundles(
    rows: list[Row], row_by_id: dict[str, Row]
) -> list[tuple[Row, list[Row]]]:
    children_by_parent: dict[str, list[Row]] = {}
    for row in rows:
        if row.parent_id and not row.attached:
            children_by_parent.setdefault(row.parent_id, []).append(row)

    bundles: list[tuple[Row, list[Row]]] = []
    for parent_id, child_rows in children_by_parent.items():
        parent = row_by_id.get(parent_id)
        if parent is None or parent.zone not in {"pci", "pci-right"}:
            continue
        grouped: dict[str, list[Row]] = {}
        for child in child_rows:
            group_key = pci_edge_group_key(child)
            if not group_key:
                continue
            if not is_pci_side_child(parent, child):
                continue
            grouped.setdefault(group_key, []).append(child)
        for group_children in grouped.values():
            if len(group_children) < 2:
                continue
            bundles.append(
                (
                    parent,
                    sorted(
                        group_children, key=lambda row: (row.cy, row.x, row.render_id)
                    ),
                )
            )
        bundles.extend(collect_unlabeled_pci_bundles(parent, child_rows))
    return bundles


def pci_edge_group_key(row: Row) -> str:
    if row.node.get("kind") not in {"pcie-fabric", "pcie-endpoint"}:
        return ""
    return str(row.node.get("edge_group") or "")


def collect_unlabeled_pci_bundles(
    parent: Row, child_rows: list[Row]
) -> list[tuple[Row, list[Row]]]:
    ordered_children = sorted(
        child_rows, key=lambda row: (row.cy, row.x, row.render_id)
    )
    bundles: list[tuple[Row, list[Row]]] = []
    current_run: list[Row] = []

    def flush_current_run() -> None:
        if len(current_run) >= 2:
            bundles.append((parent, list(current_run)))
        current_run.clear()

    for child in ordered_children:
        if is_unlabeled_pci_side_child(parent, child):
            current_run.append(child)
        else:
            flush_current_run()
    flush_current_run()
    return bundles


def is_unlabeled_pci_side_child(parent: Row, child: Row) -> bool:
    if not is_pci_side_child(parent, child):
        return False
    if pci_edge_group_key(child):
        return False
    return not str(child.node.get("link") or "").strip()


def is_pci_side_child(parent: Row, child: Row) -> bool:
    if child.node.get("kind") not in {"pcie-fabric", "pcie-endpoint"}:
        return False
    if child.zone not in {"pci", "pci-right"}:
        return False
    return child.left >= parent.right


def render_edge_bundle(parent: Row, children: list[Row]) -> tuple[str, str | None]:
    edge_label = str(
        children[0].node.get("edge_group_label") or children[0].node.get("link") or ""
    )
    start_x = parent.right
    end_x = min(child.left for child in children)
    gap = max(48.0, end_x - start_x)
    rail_x = start_x + gap / 2
    branch_x = rail_x + (end_x - rail_x) / 2
    first_y = children[0].cy
    last_y = children[-1].cy
    commands = [f"M {start_x:.1f} {parent.cy:.1f} H {rail_x:.1f}"]
    if abs(parent.cy - first_y) >= 1.0:
        commands.append(f"V {first_y:.1f}")
    commands.append(f"H {end_x:.1f}")
    if abs(last_y - first_y) >= 1.0:
        commands.append(f"M {branch_x:.1f} {first_y:.1f} V {last_y:.1f}")
    for child in children[1:]:
        commands.append(f"M {branch_x:.1f} {child.cy:.1f} H {child.left:.1f}")
    path = f'<path class="{link_class(edge_label)}" d="{" ".join(commands)}"/>'
    label_x = rail_x + (branch_x - rail_x) / 2
    return path, render_edge_label(
        edge_label, label_x, first_y - 5, abs(branch_x - rail_x) + 72
    )


def render_side_edge(
    parent: Row, child: Row, edge_label: str, *, parent_side: str
) -> tuple[str, str | None]:
    if parent_side == "left":
        start_x = parent.left
        end_x = child.right
    else:
        start_x = parent.right
        end_x = child.left
    mid_x = start_x + (end_x - start_x) / 2
    if abs(parent.cy - child.cy) < 1.0:
        edge_y = parent.cy
        path = f'<path class="{link_class(edge_label)}" d="M {start_x:.1f} {edge_y:.1f} H {end_x:.1f}"/>'
        child_segment_x = mid_x + (end_x - mid_x) / 2
        return path, render_edge_label(
            edge_label, child_segment_x, edge_y - 5, abs(end_x - mid_x)
        )
    path = (
        f'<path class="{link_class(edge_label)}" d="M {start_x:.1f} {parent.cy:.1f} '
        f'H {mid_x:.1f} V {child.cy:.1f} H {end_x:.1f}"/>'
    )
    child_segment_x = mid_x + (end_x - mid_x) / 2
    return path, render_edge_label(
        edge_label, child_segment_x, child.cy - 5, abs(end_x - mid_x)
    )


def render_edge_label(
    label: str,
    x: float,
    baseline_y: float,
    available_width: float,
    *,
    centered: bool = True,
) -> str | None:
    if not label:
        return None
    max_width = max(44, min(240, available_width - 14))
    text = shorten_to_width(label, max_width)
    label_width = min(max_width, max(44, len(text) * 6 + 8))
    rect_x = x - label_width / 2 if centered else x
    text_x = rect_x + 4
    return (
        f'<rect class="edge-label-bg" x="{rect_x:.1f}" y="{baseline_y - 11:.1f}" width="{label_width:.1f}" '
        'height="14" rx="3" ry="3"/>'
        f'<text class="edge-label" x="{text_x:.1f}" y="{baseline_y:.1f}" fill="#475569">'
        f"{escape(text)}</text>"
    )


def link_class(label: str | None) -> str:
    return "link" if str(label or "").strip() else "link unlabeled-link"


def node_lines(node: dict[str, Any]) -> list[str]:
    width = 38 if node.get("kind") == "display-device" else 32
    label = str(node.get("label") or node.get("id") or "node")
    lines: list[str] = []
    for label_line in label.splitlines() or [label]:
        title_lines = wrap(
            label_line, width=width, break_long_words=True, replace_whitespace=False
        )
        lines.extend(title_lines or [label_line])
    return lines


def box_height(lines: list[str], kind: str | None) -> float:
    return 26 + max(1, len(lines)) * 16


def render_box(row: Row) -> list[str]:
    kind = row.node.get("kind") or "other"
    fill, text_color, accent = PALETTE.get(kind, PALETTE["other"])
    lines = row.lines or []
    parts = [
        (
            f'<rect class="box" x="{row.x:.1f}" y="{row.y:.1f}" width="{row.width:.1f}" '
            f'height="{row.height:.1f}" fill="{fill}" stroke="{accent}"/>'
        ),
        (
            f'<rect class="accent" x="{row.x:.1f}" y="{row.y:.1f}" width="6" '
            f'height="{row.height:.1f}" fill="{accent}" rx="4" ry="4"/>'
        ),
    ]
    y = row.y + 24
    for line in lines:
        parts.append(
            f'<text class="node-text" x="{row.x + 18:.1f}" y="{y:.1f}" fill="{text_color}">{escape(shorten(line, 44))}</text>'
        )
        y += 16
    return parts


def shorten(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def shorten_to_width(text: str, width: float) -> str:
    limit = max(4, int((width - 8) / 6))
    return shorten(text, limit)


def render_cpu_peer_edges(row_groups: list[list[Row]]) -> list[str]:
    cpu_rows = [
        group[0] for group in row_groups if group and group[0].node.get("kind") == "cpu"
    ]
    if len(cpu_rows) < 2:
        return []
    bus_y = min(row.y for row in cpu_rows) - 16
    left_x = min(row.cx for row in cpu_rows)
    right_x = max(row.cx for row in cpu_rows)
    edges = [
        f'<path class="{link_class("")}" d="M {left_x:.1f} {bus_y:.1f} H {right_x:.1f}"/>'
    ]
    for row in cpu_rows:
        edges.append(
            f'<path class="{link_class("")}" d="M {row.cx:.1f} {row.y:.1f} V {bus_y:.1f}"/>'
        )
    return edges
