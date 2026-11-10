"""Control Flow Graph (CFG) extraction, graph modeling, metrics, and visualization."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CFGDirectedEdge:
    source: str
    target: str
    edge_type: str  # "conditional_true", "conditional_false", "unconditional", "call", "fallthrough"
    label: str = ""
    is_back_edge: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CFGNode:
    id: str
    start_addr: str
    end_addr: str
    instructions: list[str] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False
    is_loop_head: bool = False
    terminator_mnemonic: str = ""

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CFGGraph:
    function_name: str
    entry_address: str
    nodes: dict[str, CFGNode] = field(default_factory=dict)
    edges: list[CFGDirectedEdge] = field(default_factory=list)
    arch: str = "x86-64"
    cyclomatic_complexity: int = 1
    loop_count: int = 0
    max_depth: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "entry_address": self.entry_address,
            "arch": self.arch,
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "loop_count": self.loop_count,
            "max_depth": self.max_depth,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_dot(self) -> str:
        """Export graph to Graphviz DOT representation with branch-colored edges."""
        lines = [
            f'digraph "CFG_{self.function_name}" {{',
            '  graph [rankdir=TB, bgcolor="#1e2227", fontname="Courier New", pad="0.4"];',
            '  node [shape=box, style="filled,rounded", fontname="Courier New", fontsize=10, '
            'fillcolor="#282c34", fontcolor="#abb2bf", color="#5c6370"];',
            '  edge [fontname="Courier New", fontsize=9, arrowsize=0.8];',
            "",
        ]

        # Nodes
        for nid, node in self.nodes.items():
            border_col = "#61afef" if node.is_entry else ("#e5c07b" if node.is_exit else ("#c678dd" if node.is_loop_head else "#5c6370"))
            fill_col = "#21252b" if node.is_entry else "#282c34"
            badge = "[ENTRY] " if node.is_entry else ("[EXIT] " if node.is_exit else "")
            if node.is_loop_head:
                badge += "[LOOP HEAD] "

            inst_text = "\\l".join(line.replace('"', '\\"').replace("<", "&lt;").replace(">", "&gt;")
                                   for line in node.instructions[:15])
            if len(node.instructions) > 15:
                inst_text += f"\\l... (+{len(node.instructions) - 15} instructions)"
            if inst_text:
                inst_text += "\\l"

            label = f"{{{badge}{nid} [{node.start_addr}..{node.end_addr}]\\l|{inst_text}}}"
            lines.append(f'  "{nid}" [label="{label}", shape=record, fillcolor="{fill_col}", color="{border_col}"];')

        lines.append("")

        # Edges
        for edge in self.edges:
            color = "#98c379" if edge.edge_type == "conditional_true" else (
                "#e06c75" if edge.edge_type == "conditional_false" else (
                    "#61afef" if edge.edge_type == "unconditional" else "#abb2bf"
                )
            )
            style = "dashed" if edge.is_back_edge else "solid"
            lbl_part = f'label="{edge.label}", ' if edge.label else ""
            lines.append(
                f'  "{edge.source}" -> "{edge.target}" [{lbl_part}color="{color}", fontcolor="{color}", style="{style}"];'
            )

        lines.append("}")
        return "\n".join(lines)

    def to_ascii_diagram(self) -> str:
        """Render a clean textual ASCII / Unicode block diagram of the control flow."""
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════════╗",
            f"║ CONTROL FLOW GRAPH: {self.function_name:<40} M={self.cyclomatic_complexity:<4} Loops={self.loop_count:<4} ║",
            f"║ Entry: {self.entry_address:<16} Basic Blocks: {len(self.nodes):<4} Edges: {len(self.edges):<4} Arch: {self.arch:<12} ║",
            "╚══════════════════════════════════════════════════════════════════════════════════╝",
            "",
        ]

        for nid, node in self.nodes.items():
            tag = " [ENTRY]" if node.is_entry else (" [EXIT]" if node.is_exit else "")
            if node.is_loop_head:
                tag += " [LOOP-HEAD]"

            lines.append(f"┌── Block {nid}{tag} [{node.start_addr}..{node.end_addr}] ({len(node.instructions)} insns)")
            for insn in node.instructions[:12]:
                lines.append(f"│   {insn}")
            if len(node.instructions) > 12:
                lines.append(f"│   ... (+{len(node.instructions) - 12} more instructions)")

            out_edges = [e for e in self.edges if e.source == nid]
            if out_edges:
                lines.append("├── Branches:")
                for e in out_edges:
                    arr = "◄─[BACK-EDGE]─" if e.is_back_edge else "────►"
                    lines.append(f"│   └─ ({e.edge_type.upper()}) {arr} {e.target}")
            else:
                lines.append("└── [TERMINAL RETURN / STOP]")
            lines.append("")

        return "\n".join(lines)


def build_cfg_from_blocks(
    blocks_data: list[dict[str, Any]],
    function_name: str,
    entry_addr: str,
    arch: str = "x86-64",
) -> CFGGraph:
    """Construct a full CFGGraph from serialized synthesizer block dictionaries."""
    nodes: dict[str, CFGNode] = {}
    edges: list[CFGDirectedEdge] = []

    for i, b in enumerate(blocks_data):
        bid = b.get("id", f"loc_{b.get('start_addr', hex(i))}")
        start_addr = str(b.get("start_addr", ""))
        end_addr = str(b.get("end_addr", start_addr))
        insns = b.get("instructions", [])
        succs = b.get("successors", [])

        # Determine terminator
        term = ""
        if insns:
            last_line = insns[-1].strip()
            parts = last_line.split()
            # If line has address prefix e.g. "0x1000: jmp 0x2000"
            if len(parts) >= 2 and parts[0].endswith(":"):
                term = parts[1].lower()
            elif parts:
                term = parts[0].lower()

        is_exit = any(term.startswith(ret) for ret in ["ret", "bx lr"]) or not succs
        is_entry = (i == 0) or (start_addr == entry_addr)

        nodes[bid] = CFGNode(
            id=bid,
            start_addr=start_addr,
            end_addr=end_addr,
            instructions=insns,
            successors=succs,
            predecessors=[],
            is_entry=is_entry,
            is_exit=is_exit,
            terminator_mnemonic=term,
        )

        for edge_info in b.get("edges", []):
            src = edge_info.get("source_block", bid)
            tgt = edge_info.get("target_block", "")
            etype = edge_info.get("edge_type", "unconditional")
            if tgt:
                edges.append(CFGDirectedEdge(source=src, target=tgt, edge_type=etype))

    # Build address-to-block-ID lookup table for cross-referencing targets
    addr_to_bid: dict[str, str] = {}
    for bid, node in nodes.items():
        addr_to_bid[bid] = bid
        clean_start = node.start_addr.rstrip(":")
        clean_end = node.end_addr.rstrip(":")
        if clean_start:
            addr_to_bid[clean_start] = bid
        if clean_end:
            addr_to_bid[clean_end] = bid
        for insn in node.instructions:
            parts = insn.strip().split()
            if parts and parts[0].endswith(":"):
                addr_to_bid[parts[0].rstrip(":")] = bid
            elif parts and parts[0].startswith("0x"):
                addr_to_bid[parts[0]] = bid

    # Fallback: if edges were not explicitly stored in blocks, infer from successors
    if not edges:
        for bid, node in nodes.items():
            succs = node.successors
            if len(succs) == 1:
                edges.append(CFGDirectedEdge(source=bid, target=succs[0], edge_type="unconditional"))
            elif len(succs) == 2:
                edges.append(CFGDirectedEdge(source=bid, target=succs[0], edge_type="conditional_true", label="T"))
                edges.append(CFGDirectedEdge(source=bid, target=succs[1], edge_type="conditional_false", label="F"))
            elif len(succs) > 2:
                for s in succs:
                    edges.append(CFGDirectedEdge(source=bid, target=s, edge_type="unconditional", label="branch"))

    # Normalize edge sources and targets using address-to-block lookup
    for edge in edges:
        edge.source = addr_to_bid.get(edge.source.rstrip(":"), edge.source)
        edge.target = addr_to_bid.get(edge.target.rstrip(":"), edge.target)

    # Normalize node successors
    for node in nodes.values():
        node.successors = [addr_to_bid.get(s.rstrip(":"), s) for s in node.successors]

    # Populate predecessors
    for e in edges:
        if e.target in nodes:
            if e.source not in nodes[e.target].predecessors:
                nodes[e.target].predecessors.append(e.source)

    # Detect loops and back-edges using DFS
    loop_count = 0
    entry_id = next((nid for nid, n in nodes.items() if n.is_entry), None)
    if not entry_id and nodes:
        entry_id = next(iter(nodes.keys()))

    visited: set[str] = set()
    rec_stack: set[str] = set()

    def dfs(curr: str, depth: int) -> int:
        nonlocal loop_count
        visited.add(curr)
        rec_stack.add(curr)
        max_d = depth

        for edge in edges:
            if edge.source == curr:
                nxt = edge.target
                if nxt in rec_stack:
                    # Found back-edge!
                    edge.is_back_edge = True
                    loop_count += 1
                    if nxt in nodes:
                        nodes[nxt].is_loop_head = True
                elif nxt not in visited and nxt in nodes:
                    d = dfs(nxt, depth + 1)
                    if d > max_d:
                        max_d = d

        rec_stack.remove(curr)
        return max_d

    max_depth = 1
    if entry_id:
        max_depth = dfs(entry_id, 1)

    # Cyclomatic complexity M = E - N + 2P (P=1 for single connected function)
    n_count = len(nodes)
    e_count = len(edges)
    complexity = max(1, e_count - n_count + 2) if n_count > 0 else 1

    return CFGGraph(
        function_name=function_name,
        entry_address=entry_addr,
        nodes=nodes,
        edges=edges,
        arch=arch,
        cyclomatic_complexity=complexity,
        loop_count=loop_count,
        max_depth=max_depth,
    )


def build_cfg_from_assembly(
    assembly_lines: list[str],
    function_name: str,
    arch: str = "x86-64",
    entry_addr: str = "",
) -> CFGGraph:
    """Decompose raw linear disassembly instructions into basic blocks and build a CFGGraph."""
    from .synthesizer import DecompilationSynthesizer

    synth = DecompilationSynthesizer()
    actual_entry = entry_addr or (assembly_lines[0].split(":")[0].strip() if assembly_lines else "0x0")
    _, blocks, _, _, _, _ = synth._synthesize_pseudocode(
        function_name, actual_entry, arch, assembly_lines, {}
    )
    blocks_dict = [b.to_dict() for b in blocks]
    return build_cfg_from_blocks(blocks_dict, function_name, actual_entry, arch=arch)
