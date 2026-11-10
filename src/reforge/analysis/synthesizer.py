"""Advanced Decompilation Synthesizer: combines disassembly, symbols, CFGs, and decompiler findings."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.findings import Confidence, Finding, Provenance

PROVENANCE_BANNER = """/* ====================================================================
 * [RECONSTRUCTED ANALYSIS - NOT ORIGINAL SOURCE CODE]
 * Function:    {name}
 * Entrypoint:  {address} (Size: {size} bytes)
 * Architecture:{arch}
 * Provenance:  {provenance}
 * Confidence:  {confidence}
 * Notice: Synthesized clean-room reconstruction from binary analysis.
 *         Exact addresses and recovered symbols are preserved.
 * ==================================================================== */
"""

GENUINE_DECOMPILER_BANNER = """/* ====================================================================
 * [GENUINE DECOMPILER OUTPUT — EXTRACTED FROM ENGINE]
 * Function:    {name}
 * Entrypoint:  {address} (Size: {size} bytes)
 * Architecture:{arch}
 * Provenance:  {provenance}
 * Confidence:  CONFIRMED (Verified decompiler engine output)
 * Engine:      {engine}
 * Notice: Genuine decompiler AST/IR representation extracted from target.
 * ==================================================================== */
"""


@dataclass
class CFGEdge:
    source_block: str
    target_block: str
    edge_type: str  # "conditional_true", "conditional_false", "unconditional", "fallthrough"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class CFGBlock:
    id: str
    start_addr: str
    end_addr: str
    instructions: list[str] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)
    edges: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DecompiledFunction:
    name: str
    address: str
    size: int = 0
    arch: str = "x86-64"
    signature: str = ""
    confidence: str = Confidence.CONFIRMED.value
    confidence_score: float = 1.0
    provenance: str = Provenance.PARSED.value
    is_verified_decompiler: bool = False
    assembly_lines: list[str] = field(default_factory=list)
    pseudocode: str = ""
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    variables: list[dict[str, Any]] = field(default_factory=list)
    cfg_blocks: list[dict[str, Any]] = field(default_factory=list)
    cyclomatic_complexity: int = 1
    source_asm_map: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DecompilationSynthesizer:
    """Combines Capstone linear disassembly, Ghidra decompilation, Rizin, JADX, and ILSpy findings.

    Produces readable evidence-linked pseudocode with explicit confidence and provenance markers,
    preserving exact addresses and cross-references.
    """

    @classmethod
    def synthesize_from_findings(
        cls,
        findings: list[Finding | dict[str, Any]],
        target_subject: str = "",
    ) -> list[DecompiledFunction]:
        """Aggregate disassembly, function, and decompiler findings into unified DecompiledFunctions."""
        raw: list[dict[str, Any]] = []
        for f in findings:
            if isinstance(f, Finding):
                raw.append(f.to_dict())
            elif isinstance(f, dict):
                raw.append(f)

        # 1. Recover known symbols and exports
        symbols: dict[str, str] = {}  # address -> name
        symbol_to_addr: dict[str, str] = {}
        for r in raw:
            key = r.get("key", "")
            val = r.get("value")
            if "symbols" in key and isinstance(val, list):
                for s in val:
                    if isinstance(s, dict) and "name" in s and "address" in s:
                        addr = str(s["address"])
                        symbols[addr] = s["name"]
                        symbol_to_addr[s["name"]] = addr

        # 2. Recover call graph edges
        call_graph_edges: list[tuple[str, str]] = []  # (caller, callee)
        for r in raw:
            if r.get("key") == "call_graph" and isinstance(r.get("value"), dict):
                items = r["value"].get("items", [])
                for edge in items:
                    if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                        call_graph_edges.append((str(edge[0]), str(edge[1])))

        # 3. Collect decompiled & synthesized functions
        decompiled_code: dict[str, dict[str, Any]] = {}
        for r in raw:
            kind = r.get("kind", "")
            val = r.get("value")
            if kind in ("decompiled", "decompiled_synthesized") and isinstance(val, dict):
                fname = r.get("key", "")
                decompiled_code[fname] = val

        # 4. Collect disassembly findings (from Capstone or Rizin)
        disasm_entries: list[dict[str, Any]] = []
        for r in raw:
            if r.get("kind") == "disassembly" and isinstance(r.get("value"), dict):
                entry = dict(r["value"])
                entry["label"] = r.get("key", "")
                disasm_entries.append(entry)

        # 5. Collect Ghidra functions metadata
        ghidra_funcs: list[dict[str, Any]] = []
        for r in raw:
            if r.get("key") == "functions" and isinstance(r.get("value"), dict):
                ghidra_funcs.extend(r["value"].get("items", []))

        functions_map: dict[str, DecompiledFunction] = {}

        # Process any pre-synthesized findings first
        for r in raw:
            if r.get("kind") == "decompiled_synthesized" and isinstance(r.get("value"), dict):
                val = r["value"]
                fname = val.get("name") or r.get("key", "sub_unknown")
                faddr = val.get("address", "0x0")
                fn = DecompiledFunction(
                    name=fname,
                    address=faddr,
                    size=val.get("size", 0),
                    arch=val.get("arch", "x86-64"),
                    signature=val.get("signature", f"void {fname}()"),
                    confidence=str(r.get("confidence", Confidence.CONFIRMED.value)),
                    confidence_score=float(val.get("confidence_score", 0.90)),
                    provenance=str(r.get("provenance", Provenance.PARSED.value)),
                    is_verified_decompiler=bool(val.get("is_verified_decompiler", False)),
                    assembly_lines=val.get("assembly_lines", []),
                    pseudocode=val.get("code", ""),
                    callers=val.get("callers", []),
                    callees=val.get("callees", []),
                    variables=val.get("variables", []),
                    cfg_blocks=val.get("cfg_blocks", []),
                    cyclomatic_complexity=int(val.get("cyclomatic_complexity", 1)),
                    source_asm_map=val.get("source_asm_map", []),
                )
                functions_map[fname] = fn
                if faddr and faddr != "0x0":
                    functions_map[faddr] = fn

        # Process Ghidra / JADX / ILSpy functions if present
        for gf in ghidra_funcs:
            name = gf.get("name", "sub_unknown")
            addr = str(gf.get("entry", "0x0"))
            size = int(gf.get("size", 0))
            sig = gf.get("signature") or f"void {name}()"
            dec_info = decompiled_code.get(name, {})
            raw_code = dec_info.get("code", "")
            engine_name = dec_info.get("tool") or "ghidra"

            if raw_code:
                confidence = Confidence.CONFIRMED.value
                confidence_score = 1.0
                provenance = Provenance.DECOMPILED.value
                is_verified = True
                header = GENUINE_DECOMPILER_BANNER.format(
                    name=name,
                    address=addr,
                    size=size,
                    arch="native",
                    provenance=provenance,
                    engine=engine_name.capitalize(),
                )
                full_code = header + "\n" + raw_code
            else:
                confidence = Confidence.STRONG.value
                confidence_score = 0.85
                provenance = Provenance.PARSED.value
                is_verified = False
                header = PROVENANCE_BANNER.format(
                    name=name,
                    address=addr,
                    size=size,
                    arch="native",
                    provenance=provenance,
                    confidence=confidence,
                )
                full_code = header + "\n" + f"// [NO DECOMPILED CODE AVAILABLE - DISASSEMBLY ONLY]\n// Signature: {sig}"

            fn = DecompiledFunction(
                name=name,
                address=addr,
                size=size,
                signature=sig,
                confidence=confidence,
                confidence_score=confidence_score,
                provenance=provenance,
                is_verified_decompiler=is_verified,
                pseudocode=full_code,
            )
            functions_map[name] = fn
            if addr and addr != "0x0":
                functions_map[addr] = fn

        # Process Capstone / linear disassembly entries
        for de in disasm_entries:
            label = de.get("label", "")
            addr = de.get("address", "0x0")
            arch = de.get("arch", "x86-64")
            lines = de.get("lines", [])

            # Derive function name from label or symbols
            clean_name = label.replace("[slice0:X86_64] ", "").replace("[slice0:ARM64] ", "").replace("[slice1:X86_64] ", "")
            if clean_name.startswith("export:"):
                clean_name = clean_name[len("export:"):]
            elif clean_name.startswith("entrypoint"):
                clean_name = f"entrypoint_{addr}"
            elif not clean_name:
                clean_name = symbols.get(addr, f"func_{addr}")

            # Synthesize pseudocode and basic blocks from disassembly
            synth_pseudo, blocks, callees, vars_found, asm_map, complexity = cls._synthesize_pseudocode(
                name=clean_name,
                address=addr,
                arch=arch,
                asm_lines=lines,
                symbols=symbols,
            )

            existing = functions_map.get(clean_name) or functions_map.get(addr)
            if existing:
                existing.assembly_lines = lines
                existing.arch = arch
                if not existing.pseudocode or "[NO DECOMPILED CODE AVAILABLE" in existing.pseudocode:
                    existing.pseudocode = synth_pseudo
                existing.cfg_blocks = [b.to_dict() if isinstance(b, CFGBlock) else b for b in blocks]
                existing.callees = sorted(set(existing.callees + callees))
                existing.variables = vars_found
                existing.source_asm_map = asm_map
                existing.cyclomatic_complexity = complexity
            else:
                fn = DecompiledFunction(
                    name=clean_name,
                    address=addr,
                    size=len(lines) * 4,  # approximate byte size
                    arch=arch,
                    signature=f"int {clean_name}()",
                    confidence=Confidence.TENTATIVE.value,
                    confidence_score=0.75,
                    provenance=Provenance.INFERRED.value,
                    is_verified_decompiler=False,
                    assembly_lines=lines,
                    pseudocode=synth_pseudo,
                    callees=callees,
                    cfg_blocks=[b.to_dict() for b in blocks],
                    variables=vars_found,
                    cyclomatic_complexity=complexity,
                    source_asm_map=asm_map,
                )
                functions_map[clean_name] = fn
                functions_map[addr] = fn

        # Resolve callers and callees from call graph
        for caller, callee in call_graph_edges:
            if caller in functions_map and callee not in functions_map[caller].callees:
                functions_map[caller].callees.append(callee)
            if callee in functions_map and caller not in functions_map[callee].callers:
                functions_map[callee].callers.append(caller)

        # Deduplicate functions (by name / address)
        unique_funcs: list[DecompiledFunction] = []
        seen_keys: set[str] = set()
        for fn in functions_map.values():
            key = f"{fn.name}:{fn.address}"
            if key not in seen_keys:
                seen_keys.add(key)
                unique_funcs.append(fn)

        return sorted(unique_funcs, key=lambda f: f.address)

    @classmethod
    def _synthesize_pseudocode(
        cls,
        name: str,
        address: str,
        arch: str,
        asm_lines: list[str],
        symbols: dict[str, str],
    ) -> tuple[str, list[CFGBlock], list[str], list[dict[str, Any]], list[dict[str, Any]], int]:
        """Convert linear disassembly into evidence-linked pseudocode, CFG basic blocks, and source-to-asm map."""
        callees: list[str] = []
        variables: list[dict[str, Any]] = []
        blocks: list[CFGBlock] = []
        source_asm_map: list[dict[str, Any]] = []

        code_lines: list[str] = []
        curr_block_insns: list[str] = []
        block_start = address
        block_idx = 0

        header = PROVENANCE_BANNER.format(
            name=name,
            address=address,
            size=len(asm_lines) * 4,
            arch=arch,
            provenance="Synthesized from disassembly & CFG extraction",
            confidence="TENTATIVE (Clean-room heuristic)",
        )

        code_lines.append(header)
        code_lines.append(f"int {name}() {{")

        indent = "    "
        in_prologue = True

        for i, raw_line in enumerate(asm_lines):
            curr_block_insns.append(raw_line)
            # Parse address, bytes, mnemonic, operands
            parts = [p.strip() for p in re.split(r"\s{2,}", raw_line) if p.strip()]
            if len(parts) >= 3:
                addr_str = parts[0]
                ins_part = parts[2]
                mnemonic, _, operands = ins_part.partition(" ")
            elif len(parts) == 2:
                addr_str = parts[0]
                mnemonic, _, operands = parts[1].partition(" ")
            else:
                tokens = raw_line.split()
                addr_str = tokens[0] if tokens and tokens[0].startswith("0x") else ""
                start = 1 if addr_str else 0
                non_hex_idx = start
                for idx in range(start, len(tokens)):
                    t = tokens[idx]
                    if not all(c in "0123456789abcdefABCDEF" for c in t):
                        non_hex_idx = idx
                        break
                mnemonic = tokens[non_hex_idx] if non_hex_idx < len(tokens) else ""
                operands = " ".join(tokens[non_hex_idx + 1:])

            mnemonic = mnemonic.lower()
            operands = operands.strip()
            curr_line_no = len(code_lines) + 1

            # Check prologue
            if mnemonic in ("push", "mov") and any(r in operands for r in ("rbp", "ebp", "fp")):
                if in_prologue:
                    code_lines.append(f"{indent}/* {addr_str} */  // [Function Prologue: stack frame setup]")
                    source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})
                    continue
            else:
                in_prologue = False

            # Calls
            if mnemonic in ("call", "bl", "blx"):
                target = operands.strip()
                resolved = symbols.get(target, target)
                callees.append(resolved)
                code_lines.append(f"{indent}/* {addr_str} */  result = {resolved}();")
                source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})

            # Comparisons and jumps
            elif mnemonic in ("cmp", "test"):
                code_lines.append(f"{indent}/* {addr_str} */  flags = compare({operands});")
                source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})

            elif mnemonic.startswith("j") or mnemonic in ("b", "bx", "cbz", "cbnz"):
                target = operands.strip()
                resolved = symbols.get(target, target)
                is_uncond = mnemonic in ("jmp", "b", "bx")
                if is_uncond:
                    code_lines.append(f"{indent}/* {addr_str} */  goto {resolved};")
                else:
                    cond = mnemonic[1:] if mnemonic.startswith("j") else mnemonic
                    code_lines.append(f"{indent}/* {addr_str} */  if (condition_{cond}(flags)) goto {resolved};")
                source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})

                # End of a basic block: calculate edges and successors
                successors = [target]
                edges = [{"source_block": f"bb_{block_idx}", "target_block": target, "edge_type": "unconditional" if is_uncond else "conditional_true"}]

                # For conditional jumps, also add fallthrough to the next instruction
                if not is_uncond and i + 1 < len(asm_lines):
                    next_addr = asm_lines[i + 1].split()[0]
                    successors.append(next_addr)
                    edges.append({"source_block": f"bb_{block_idx}", "target_block": next_addr, "edge_type": "conditional_false"})

                blocks.append(
                    CFGBlock(
                        id=f"bb_{block_idx}",
                        start_addr=block_start,
                        end_addr=addr_str,
                        instructions=list(curr_block_insns),
                        successors=successors,
                        edges=edges,
                    )
                )
                block_idx += 1
                curr_block_insns = []
                block_start = asm_lines[i + 1].split()[0] if i + 1 < len(asm_lines) else addr_str

            # Returns
            elif mnemonic in ("ret", "retq"):
                code_lines.append(f"{indent}/* {addr_str} */  return result;  // [Function Epilogue]")
                source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})
                blocks.append(
                    CFGBlock(
                        id=f"bb_{block_idx}",
                        start_addr=block_start,
                        end_addr=addr_str,
                        instructions=list(curr_block_insns),
                        successors=[],
                        edges=[],
                    )
                )
                block_idx += 1
                curr_block_insns = []
                block_start = asm_lines[i + 1].split()[0] if i + 1 < len(asm_lines) else addr_str

            # Assignments and arithmetic
            elif mnemonic in ("mov", "movzx", "movsx", "ldr"):
                if "," in operands:
                    dst, src = (o.strip() for o in operands.split(",", 1))
                    code_lines.append(f"{indent}/* {addr_str} */  {dst} = {src};")
                else:
                    code_lines.append(f"{indent}/* {addr_str} */  // {mnemonic} {operands}")
                source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})

            elif mnemonic in ("add", "sub", "xor", "and", "or"):
                if "," in operands:
                    dst, src = (o.strip() for o in operands.split(",", 1))
                    op = {"add": "+=", "sub": "-=", "xor": "^=", "and": "&=", "or": "|="}.get(mnemonic, "=")
                    code_lines.append(f"{indent}/* {addr_str} */  {dst} {op} {src};")
                else:
                    code_lines.append(f"{indent}/* {addr_str} */  // {mnemonic} {operands}")
                source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})

            elif mnemonic == "lea":
                if "," in operands:
                    dst, src = (o.strip() for o in operands.split(",", 1))
                    code_lines.append(f"{indent}/* {addr_str} */  {dst} = &({src});")
                source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})

            else:
                code_lines.append(f"{indent}/* {addr_str} */  // [OP] {mnemonic} {operands}")
                source_asm_map.append({"line_no": curr_line_no, "address": addr_str, "instruction": f"{mnemonic} {operands}"})

        code_lines.append("}\n")

        # Flush final block if any
        if curr_block_insns:
            blocks.append(
                CFGBlock(
                    id=f"bb_{block_idx}",
                    start_addr=block_start,
                    end_addr=asm_lines[-1].split()[0] if asm_lines else address,
                    instructions=list(curr_block_insns),
                    successors=[],
                    edges=[],
                )
            )

        # Calculate Cyclomatic Complexity: M = E - N + 2P (P=1)
        num_nodes = len(blocks)
        num_edges = sum(len(b.successors) for b in blocks)
        cyclomatic_complexity = max(1, num_edges - num_nodes + 2) if num_nodes > 0 else 1

        return "\n".join(code_lines), blocks, sorted(set(callees)), variables, source_asm_map, cyclomatic_complexity

    @classmethod
    def to_findings(
        cls,
        functions: list[DecompiledFunction],
        rel_subject: str = "",
    ) -> list[Finding]:
        """Convert synthesized functions into findings for persistent storage in ReForge DB."""
        findings: list[Finding] = []
        for fn in functions:
            findings.append(
                Finding(
                    stage="synthesizer",
                    tool="reforge.synthesizer",
                    kind="decompiled_synthesized",
                    key=fn.name,
                    value={
                        "name": fn.name,
                        "address": fn.address,
                        "size": fn.size,
                        "signature": fn.signature,
                        "arch": fn.arch,
                        "code": fn.pseudocode,
                        "callers": fn.callers,
                        "callees": fn.callees,
                        "cfg_blocks": fn.cfg_blocks,
                        "cyclomatic_complexity": fn.cyclomatic_complexity,
                        "is_verified_decompiler": fn.is_verified_decompiler,
                        "confidence_score": fn.confidence_score,
                        "source_asm_map": fn.source_asm_map,
                    },
                    confidence=Confidence(fn.confidence) if fn.confidence in Confidence._value2member_map_ else Confidence.TENTATIVE,
                    provenance=Provenance(fn.provenance) if fn.provenance in Provenance._value2member_map_ else Provenance.INFERRED,
                    rationale="Synthesized readable clean-room pseudocode with preserved addresses and CFG",
                    subject=rel_subject,
                )
            )
        return findings
