"""Control Flow Graph (CFG) extraction, graph modeling, metrics, and visualization."""
from __future__ import annotations

import json
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class NaturalLoop:
    header: str
    latch: str
    blocks: list[str] = field(default_factory=list)
    is_reducible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CFGDirectedEdge:
    source: str
    target: str
    edge_type: str  # "conditional_true", "conditional_false", "unconditional", "call", "fallthrough", "indirect"
    label: str = ""
    is_back_edge: bool = False
    is_indirect: bool = False

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
    is_unreachable: bool = False
    has_indirect_branch: bool = False
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
    dominators: dict[str, list[str]] = field(default_factory=dict)
    immediate_dominators: dict[str, str | None] = field(default_factory=dict)
    dominance_frontiers: dict[str, list[str]] = field(default_factory=dict)
    natural_loops: list[NaturalLoop] = field(default_factory=list)
    unreachable_blocks: list[str] = field(default_factory=list)

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
            "dominators": self.dominators,
            "immediate_dominators": self.immediate_dominators,
            "dominance_frontiers": self.dominance_frontiers,
            "natural_loops": [loop_item.to_dict() for loop_item in self.natural_loops],
            "unreachable_blocks": self.unreachable_blocks,
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
            if node.is_unreachable:
                border_col = "#7f848e"
                fill_col = "#1e1e24"
                badge = "[UNREACHABLE] "
            elif node.is_entry:
                border_col = "#61afef"
                fill_col = "#21252b"
                badge = "[ENTRY] "
            elif node.is_exit:
                border_col = "#e5c07b"
                fill_col = "#282c34"
                badge = "[EXIT] "
            elif node.is_loop_head:
                border_col = "#c678dd"
                fill_col = "#282c34"
                badge = "[LOOP HEAD] "
            else:
                border_col = "#5c6370"
                fill_col = "#282c34"
                badge = ""

            if node.has_indirect_branch:
                badge += "[INDIRECT] "

            inst_text = "\\l".join(
                line.replace('"', '\\"').replace("<", "&lt;").replace(">", "&gt;")
                for line in node.instructions[:15]
            )
            if len(node.instructions) > 15:
                inst_text += f"\\l... (+{len(node.instructions) - 15} instructions)"
            if inst_text:
                inst_text += "\\l"

            label = f"{{{badge}{nid} [{node.start_addr}..{node.end_addr}]\\l|{inst_text}}}"
            lines.append(f'  "{nid}" [label="{label}", shape=record, fillcolor="{fill_col}", color="{border_col}"];')

        lines.append("")

        # Edges
        for edge in self.edges:
            if edge.is_indirect:
                color = "#d19a66"
                style = "dotted"
            elif edge.edge_type == "conditional_true":
                color = "#98c379"
                style = "solid"
            elif edge.edge_type == "conditional_false":
                color = "#e06c75"
                style = "solid"
            elif edge.edge_type == "unconditional":
                color = "#61afef"
                style = "solid"
            else:
                color = "#abb2bf"
                style = "solid"

            if edge.is_back_edge:
                style = "dashed"
                color = "#e5c07b"

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

        if self.natural_loops:
            lines.append(f"── Natural Loops Detected ({len(self.natural_loops)}):")
            for i, loop in enumerate(self.natural_loops):
                blocks_str = ", ".join(loop.blocks)
                lines.append(f"   [{i + 1}] Header: {loop.header} | Latch: {loop.latch} | Blocks: {{{blocks_str}}}")
            lines.append("")

        if self.unreachable_blocks:
            lines.append(f"── Unreachable Blocks ({len(self.unreachable_blocks)}): {', '.join(self.unreachable_blocks)}")
            lines.append("")

        for nid, node in self.nodes.items():
            tag = " [ENTRY]" if node.is_entry else (" [EXIT]" if node.is_exit else "")
            if node.is_loop_head:
                tag += " [LOOP-HEAD]"
            if node.is_unreachable:
                tag += " [UNREACHABLE]"
            if node.has_indirect_branch:
                tag += " [INDIRECT-BRANCH]"

            idom_str = f" idom={self.immediate_dominators.get(nid)}" if self.immediate_dominators.get(nid) else ""
            df_nodes = self.dominance_frontiers.get(nid, [])
            df_str = f" DF={{{', '.join(df_nodes)}}}" if df_nodes else ""

            lines.append(
                f"┌── Block {nid}{tag} [{node.start_addr}..{node.end_addr}] ({len(node.instructions)} insns){idom_str}{df_str}"
            )
            for insn in node.instructions[:12]:
                lines.append(f"│   {insn}")
            if len(node.instructions) > 12:
                lines.append(f"│   ... (+{len(node.instructions) - 12} more instructions)")

            out_edges = [e for e in self.edges if e.source == nid]
            if out_edges:
                lines.append("├── Branches:")
                for e in out_edges:
                    arr = "◄─[BACK-EDGE]─" if e.is_back_edge else ("···[INDIRECT]··►" if e.is_indirect else "────►")
                    lines.append(f"│   └─ ({e.edge_type.upper()}) {arr} {e.target}")
            else:
                lines.append("└── [TERMINAL RETURN / STOP]")
            lines.append("")

        return "\n".join(lines)


def is_indirect_instruction(insn: str) -> bool:
    """Detect if an instruction performs an indirect transfer of control."""
    text = insn.lower().strip()
    if ":" in text and text.split(":")[0].strip().startswith("0x"):
        text = text.split(":", 1)[1].strip()

    parts = text.split(None, 1)
    if not parts:
        return False
    mnemonic = parts[0]
    op = parts[1] if len(parts) > 1 else ""

    # x86 / x64 indirect jumps & calls
    if mnemonic in ("jmp", "call"):
        regs = {
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        }
        if op in regs or "[" in op or "*" in op or op.startswith("qword ptr") or op.startswith("dword ptr"):
            return True

    # ARM / ARM64 indirect branches: br x0, blr x1, bx r3, blx r3
    if mnemonic in ("br", "blr", "bx", "blx"):
        return True

    # MIPS: jr, jalr
    if mnemonic in ("jr", "jalr"):
        return True

    return False


def compute_cfg_dominance(
    nodes: dict[str, CFGNode],
    edges: list[CFGDirectedEdge],
    entry_id: str | None,
) -> tuple[
    dict[str, list[str]],          # dominators
    dict[str, str | None],         # immediate_dominators
    dict[str, list[str]],          # dominance_frontiers
    list[NaturalLoop],             # natural_loops
    list[str],                     # unreachable_blocks
]:
    """Compute formal dominator tree, immediate dominators, dominance frontiers, and natural loops."""
    if not nodes:
        return {}, {}, {}, [], []

    if not entry_id or entry_id not in nodes:
        entry_id = next(iter(nodes.keys()))

    # 1. Reachability from entry
    reachable: set[str] = set()
    queue = deque([entry_id])
    reachable.add(entry_id)

    # Edge lookup by source
    succ_map: dict[str, list[str]] = {nid: [] for nid in nodes}
    for e in edges:
        if e.source in succ_map and e.target in nodes:
            succ_map[e.source].append(e.target)

    while queue:
        curr = queue.popleft()
        for succ in succ_map.get(curr, []):
            if succ not in reachable:
                reachable.add(succ)
                queue.append(succ)

    unreachable_blocks = sorted([nid for nid in nodes if nid not in reachable])
    for uid in unreachable_blocks:
        nodes[uid].is_unreachable = True

    # 2. Iterative dominators algorithm: Dom(n) = {n} U (∩ Dom(p) for p in Pred(n))
    dom: dict[str, set[str]] = {entry_id: {entry_id}}
    for n in reachable:
        if n != entry_id:
            dom[n] = set(reachable)

    changed = True
    while changed:
        changed = False
        for n in reachable:
            if n == entry_id:
                continue
            preds = [p for p in nodes[n].predecessors if p in reachable]
            if preds:
                intersected = set.intersection(*(dom[p] for p in preds))
                new_dom = {n} | intersected
            else:
                new_dom = {n}

            if new_dom != dom[n]:
                dom[n] = new_dom
                changed = True

    # 3. Immediate Dominators: idom(n)
    idom: dict[str, str | None] = {entry_id: None}
    for n in reachable:
        if n == entry_id:
            continue
        strict = dom[n] - {n}
        candidate: str | None = None
        for d in strict:
            if all(d_prime in dom[d] for d_prime in strict if d_prime != d):
                candidate = d
                break
        if candidate is None and strict:
            candidate = max(strict, key=lambda d: len(dom[d]))
        idom[n] = candidate

    for uid in unreachable_blocks:
        dom[uid] = {uid}
        idom[uid] = None

    # 4. Dominance Frontiers (Cytron et al. standard algorithm)
    df: dict[str, set[str]] = {nid: set() for nid in nodes}
    for y in reachable:
        preds = [p for p in nodes[y].predecessors if p in reachable]
        if len(preds) >= 2:
            for p in preds:
                runner: str | None = p
                while runner is not None and runner != idom.get(y):
                    df[runner].add(y)
                    runner = idom.get(runner)

    # 5. Natural Loops from Back-Edges
    # A back-edge is an edge (latch -> header) where header dominates latch
    natural_loops: list[NaturalLoop] = []
    seen_loops: set[tuple[str, str]] = set()

    for e in edges:
        if e.source in reachable and e.target in reachable:
            if e.target in dom.get(e.source, set()):
                # Back-edge found!
                e.is_back_edge = True
                nodes[e.target].is_loop_head = True
                header = e.target
                latch = e.source

                if (header, latch) not in seen_loops:
                    seen_loops.add((header, latch))
                    # Reconstruct loop body: all nodes that can reach latch without passing through header
                    loop_body: set[str] = {header, latch}
                    body_stack = [latch] if latch != header else []
                    while body_stack:
                        curr_m = body_stack.pop()
                        for p in nodes[curr_m].predecessors:
                            if p in reachable and p not in loop_body:
                                loop_body.add(p)
                                body_stack.append(p)

                    natural_loops.append(
                        NaturalLoop(
                            header=header,
                            latch=latch,
                            blocks=sorted(loop_body),
                            is_reducible=True,
                        )
                    )

    dominators_dict = {k: sorted(v) for k, v in dom.items()}
    dominance_frontiers_dict = {k: sorted(v) for k, v in df.items()}

    return dominators_dict, idom, dominance_frontiers_dict, natural_loops, unreachable_blocks


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
        has_indirect = False
        if insns:
            last_line = insns[-1].strip()
            parts = last_line.split()
            if len(parts) >= 2 and parts[0].endswith(":"):
                term = parts[1].lower()
            elif parts:
                term = parts[0].lower()

            for insn in insns:
                if is_indirect_instruction(insn):
                    has_indirect = True

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
            has_indirect_branch=has_indirect,
            terminator_mnemonic=term,
        )

        for edge_info in b.get("edges", []):
            src = edge_info.get("source_block", bid)
            tgt = edge_info.get("target_block", "")
            etype = edge_info.get("edge_type", "unconditional")
            is_ind = edge_info.get("is_indirect", False)
            if tgt:
                edges.append(CFGDirectedEdge(source=src, target=tgt, edge_type=etype, is_indirect=is_ind))

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

    entry_id = next((nid for nid, n in nodes.items() if n.is_entry), None)
    if not entry_id and nodes:
        entry_id = next(iter(nodes.keys()))

    # Compute formal dominator tree, idom, dominance frontiers, and natural loops
    doms, idoms, dfs, natural_loops, unreachable = compute_cfg_dominance(nodes, edges, entry_id)

    # Mark indirect edges if source node has indirect branch and edge isn't standard fallthrough
    for edge in edges:
        if edge.source in nodes and nodes[edge.source].has_indirect_branch:
            if edge.edge_type not in ("conditional_true", "conditional_false"):
                edge.is_indirect = True

    # DFS for max depth calculation
    visited: set[str] = set()

    def calc_depth(curr: str, depth: int) -> int:
        visited.add(curr)
        max_d = depth
        for edge in edges:
            if edge.source == curr and not edge.is_back_edge:
                nxt = edge.target
                if nxt not in visited and nxt in nodes:
                    d = calc_depth(nxt, depth + 1)
                    if d > max_d:
                        max_d = d
        return max_d

    max_depth = 1
    if entry_id and entry_id in nodes:
        max_depth = calc_depth(entry_id, 1)

    # Cyclomatic complexity M = E - N + 2P (P=1 for single connected function)
    n_count = len(nodes) - len(unreachable)
    e_count = len([e for e in edges if not e.is_back_edge or e.source in nodes])
    complexity = max(1, e_count - n_count + 2) if n_count > 0 else 1

    return CFGGraph(
        function_name=function_name,
        entry_address=entry_addr,
        nodes=nodes,
        edges=edges,
        arch=arch,
        cyclomatic_complexity=complexity,
        loop_count=len(natural_loops),
        max_depth=max_depth,
        dominators=doms,
        immediate_dominators=idoms,
        dominance_frontiers=dfs,
        natural_loops=natural_loops,
        unreachable_blocks=unreachable,
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
