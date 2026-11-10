"""Interactive Control Flow Graph (CFG) Visualizer Widget for Nexonic ReForge Studio."""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...analysis.cfg import CFGGraph, build_cfg_from_assembly, build_cfg_from_blocks


class BlockCardWidget(QFrame):
    """Visual card representing a single basic block in the Control Flow Graph."""

    clicked = Signal(str)  # emits block_id
    navigate_target = Signal(str)  # emits target_block_id

    def __init__(self, node_id: str, node_data: Any, is_entry: bool = False, is_exit: bool = False, is_loop: bool = False, parent: QWidget | None = None):
        super().__init__(parent)
        self.node_id = node_id
        self.setObjectName("Card")
        self.setFrameShape(QFrame.StyledPanel)

        # Style card
        border_color = "#61afef" if is_entry else ("#e5c07b" if is_exit else ("#c678dd" if is_loop else "#3e4451"))
        bg_color = "#21252b" if is_entry else "#282c34"
        self.setStyleSheet(f"""
            BlockCardWidget {{
                background-color: {bg_color};
                border: 2px solid {border_color};
                border-radius: 6px;
                padding: 4px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(4)

        # Header bar
        hdr = QHBoxLayout()
        hdr.setSpacing(6)
        lbl_id = QLabel(f"<b>{node_id}</b>")
        lbl_id.setStyleSheet("font-size: 11px; color: #abb2bf;")
        hdr.addWidget(lbl_id)

        start = getattr(node_data, "start_addr", "")
        end = getattr(node_data, "end_addr", "")
        if start:
            lbl_addr = QLabel(f"[{start}..{end}]")
            lbl_addr.setStyleSheet("font-size: 10px; color: #5c6370;")
            hdr.addWidget(lbl_addr)

        hdr.addStretch(1)

        if is_entry:
            lbl_badge = QLabel("ENTRY")
            lbl_badge.setStyleSheet("background-color: #61afef; color: #1e2227; font-weight: bold; font-size: 9px; padding: 2px 4px; border-radius: 3px;")
            hdr.addWidget(lbl_badge)
        if is_exit:
            lbl_badge = QLabel("EXIT")
            lbl_badge.setStyleSheet("background-color: #e5c07b; color: #1e2227; font-weight: bold; font-size: 9px; padding: 2px 4px; border-radius: 3px;")
            hdr.addWidget(lbl_badge)
        if is_loop:
            lbl_badge = QLabel("LOOP-HEAD")
            lbl_badge.setStyleSheet("background-color: #c678dd; color: #1e2227; font-weight: bold; font-size: 9px; padding: 2px 4px; border-radius: 3px;")
            hdr.addWidget(lbl_badge)

        layout.addLayout(hdr)

        # Instructions listing
        insns = getattr(node_data, "instructions", [])
        insn_text = "\n".join(insns[:20])
        if len(insns) > 20:
            insn_text += f"\n... (+{len(insns) - 20} more instructions)"

        ed = QPlainTextEdit()
        ed.setReadOnly(True)
        ed.setLineWrapMode(QPlainTextEdit.NoWrap)
        font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        font.setPointSize(9)
        ed.setFont(font)
        ed.setPlainText(insn_text)
        line_count = min(max(len(insns), 2), 12)
        ed.setFixedHeight(line_count * 18 + 10)
        ed.setStyleSheet("background-color: #1e2227; border: 1px solid #181a1f; color: #abb2bf;")
        layout.addWidget(ed)

        # Outgoing branches bar
        succs = getattr(node_data, "successors", [])
        if succs:
            branch_bar = QHBoxLayout()
            branch_bar.setSpacing(4)
            branch_bar.addWidget(QLabel("Branches:"))
            for s in succs:
                btn = QPushButton(f"➔ {s}")
                btn.setFixedHeight(22)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #3b4048;
                        color: #61afef;
                        border: 1px solid #4b5263;
                        border-radius: 3px;
                        font-size: 10px;
                        padding: 1px 6px;
                    }
                    QPushButton:hover {
                        background-color: #4b5263;
                        color: #ffffff;
                    }
                """)
                btn.clicked.connect(lambda _, target=s: self.navigate_target.emit(target))
                branch_bar.addWidget(btn)
            branch_bar.addStretch(1)
            layout.addLayout(branch_bar)
        else:
            lbl_term = QLabel("● End of execution path (Return)")
            lbl_term.setStyleSheet("color: #e5c07b; font-size: 10px; font-style: italic;")
            layout.addWidget(lbl_term)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.clicked.emit(self.node_id)


class CFGVisualizerWidget(QWidget):
    """Interactive Control Flow Graph viewer supporting visual block flow, DOT, and ASCII rendering."""

    block_selected = Signal(str)  # Emits start address or block ID

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.current_graph: CFGGraph | None = None
        self.cards: dict[str, BlockCardWidget] = {}

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(4)

        # Header Toolbar
        top = QHBoxLayout()
        top.setContentsMargins(4, 4, 4, 4)
        top.setSpacing(6)

        self.lbl_info = QLabel("CFG: No function loaded")
        self.lbl_info.setStyleSheet("font-weight: bold; font-size: 11px;")
        top.addWidget(self.lbl_info, 1)

        self.lbl_metrics = QLabel("")
        self.lbl_metrics.setStyleSheet("background-color: #2b3a4a; color: #61afef; padding: 2px 6px; border-radius: 3px; font-size: 10px;")
        top.addWidget(self.lbl_metrics)

        self.view_mode_sel = QComboBox()
        self.view_mode_sel.addItems(["Interactive Visual Flow", "ASCII / Unicode Flow", "Graphviz DOT"])
        self.view_mode_sel.currentIndexChanged.connect(self._on_mode_changed)
        top.addWidget(self.view_mode_sel)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter blocks…")
        self.filter_input.setFixedWidth(130)
        self.filter_input.textChanged.connect(self._apply_filter)
        top.addWidget(self.filter_input)

        btn_copy = QPushButton("Copy")
        btn_copy.setFixedWidth(50)
        btn_copy.clicked.connect(self._copy_content)
        top.addWidget(btn_copy)

        btn_export = QPushButton("Export…")
        btn_export.setFixedWidth(60)
        btn_export.clicked.connect(self._export_graph)
        top.addWidget(btn_export)

        vbox.addLayout(top)

        # Main Content Stack
        # 1. Interactive Visual Flow (Scroll Area with Block Cards)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(8, 8, 8, 8)
        self.scroll_layout.setSpacing(10)
        self.scroll_layout.addStretch(1)
        self.scroll_area.setWidget(self.scroll_content)
        vbox.addWidget(self.scroll_area, 1)

        # 2. Textual View (ASCII / DOT)
        self.text_view = QPlainTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.text_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.text_view.hide()
        vbox.addWidget(self.text_view, 1)

    # ---- Public API ----------------------------------------------------------
    def load_graph(self, graph: CFGGraph) -> None:
        """Load and display a CFGGraph."""
        self.current_graph = graph
        self.lbl_info.setText(f"CFG: <b>{graph.function_name}</b> ({graph.entry_address})")
        self.lbl_metrics.setText(
            f"M={graph.cyclomatic_complexity} · Blocks={len(graph.nodes)} · Edges={len(graph.edges)} · Loops={graph.loop_count}"
        )
        self._populate_visual_cards()
        self._on_mode_changed()

    def load_from_blocks(self, blocks: list[dict[str, Any]], function_name: str, entry_addr: str = "", arch: str = "x86-64") -> None:
        """Build and display CFG from synthesizer basic blocks."""
        graph = build_cfg_from_blocks(blocks, function_name, entry_addr, arch=arch)
        self.load_graph(graph)

    def load_from_assembly(self, assembly_lines: list[str], function_name: str, arch: str = "x86-64", entry_addr: str = "") -> None:
        """Decompose assembly instructions and build CFG."""
        graph = build_cfg_from_assembly(assembly_lines, function_name, arch=arch, entry_addr=entry_addr)
        self.load_graph(graph)

    def clear(self) -> None:
        self.current_graph = None
        self.lbl_info.setText("CFG: No function loaded")
        self.lbl_metrics.setText("")
        self._clear_visual_cards()
        self.text_view.clear()

    # ---- Internal Helpers ----------------------------------------------------
    def _clear_visual_cards(self) -> None:
        for c in self.cards.values():
            c.setParent(None)
            c.deleteLater()
        self.cards.clear()

    def _populate_visual_cards(self) -> None:
        self._clear_visual_cards()
        if not self.current_graph:
            return

        # Insert cards before trailing stretch
        for i, (nid, node) in enumerate(self.current_graph.nodes.items()):
            card = BlockCardWidget(
                node_id=nid,
                node_data=node,
                is_entry=node.is_entry,
                is_exit=node.is_exit,
                is_loop=node.is_loop_head,
                parent=self.scroll_content,
            )
            card.clicked.connect(self._on_card_clicked)
            card.navigate_target.connect(self._scroll_to_block)
            self.cards[nid] = card
            self.scroll_layout.insertWidget(i, card)

    def _on_mode_changed(self) -> None:
        if not self.current_graph:
            return
        mode = self.view_mode_sel.currentText()
        if "Visual" in mode:
            self.text_view.hide()
            self.scroll_area.show()
        elif "ASCII" in mode:
            self.scroll_area.hide()
            self.text_view.setPlainText(self.current_graph.to_ascii_diagram())
            self.text_view.show()
        elif "DOT" in mode:
            self.scroll_area.hide()
            self.text_view.setPlainText(self.current_graph.to_dot())
            self.text_view.show()

    def _apply_filter(self, text: str) -> None:
        term = text.lower().strip()
        for nid, card in self.cards.items():
            if not term:
                card.show()
            else:
                node = self.current_graph.nodes.get(nid) if self.current_graph else None
                matched = (term in nid.lower()) or (
                    any(term in insn.lower() for insn in node.instructions) if node else False
                )
                card.setVisible(matched)

    def _scroll_to_block(self, block_id: str) -> None:
        card = self.cards.get(block_id)
        if card:
            self.scroll_area.ensureWidgetVisible(card)
            # Visual highlight pulse
            self._on_card_clicked(block_id)

    def _on_card_clicked(self, block_id: str) -> None:
        node = self.current_graph.nodes.get(block_id) if self.current_graph else None
        target_addr = node.start_addr if node else block_id
        self.block_selected.emit(target_addr)

    def _copy_content(self) -> None:
        if not self.current_graph:
            return
        mode = self.view_mode_sel.currentText()
        if "DOT" in mode:
            txt = self.current_graph.to_dot()
        elif "ASCII" in mode:
            txt = self.current_graph.to_ascii_diagram()
        else:
            txt = self.current_graph.to_ascii_diagram()
        QApplication.clipboard().setText(txt)

    def _export_graph(self) -> None:
        if not self.current_graph:
            return
        mode = self.view_mode_sel.currentText()
        default_ext = ".dot" if "DOT" in mode else ".txt"
        file_filter = "Graphviz DOT (*.dot)" if "DOT" in mode else "Text File (*.txt)"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export CFG", f"cfg_{self.current_graph.function_name}{default_ext}", file_filter
        )
        if save_path:
            content = self.current_graph.to_dot() if "DOT" in mode else self.current_graph.to_ascii_diagram()
            from pathlib import Path

            Path(save_path).write_text(content, encoding="utf-8")
            QMessageBox.information(self, "Export Complete", f"Exported CFG to:\n{save_path}")
