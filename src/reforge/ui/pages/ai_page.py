"""AI Assistant page: project-aware chat with BYOK providers and local models."""
from __future__ import annotations

import threading

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
)

from ...ai import PROVIDERS, SYSTEM_PROMPT, build_project_context, delete_key, get_key, set_key, stream_chat
from .common import Page


class AIAssistantPage(Page):
    title = "AI Assistant"
    subtitle = "Project-aware assistance using Bring Your Own Key (BYOK) providers and local models."

    # Thread-safe signals for streaming tokens to the UI
    token_received = Signal(str)
    stream_finished = Signal(str)
    stream_error = Signal(str)

    def __init__(self, ctx):
        super().__init__(ctx)
        self.current_pid: int | None = None
        self.messages: list[dict] = []
        self._active_stream: threading.Event | None = None

        self.token_received.connect(self._on_token)
        self.stream_finished.connect(self._on_finished)
        self.stream_error.connect(self._on_error)

        # Splitter: Left is BYOK Settings + Context summary; Right is Chat interface
        split = QSplitter(Qt.Horizontal)

        # Left Config Panel
        left_w = QFrame()
        left_lay = QVBoxLayout(left_w)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(10)

        # BYOK Card
        byok_card = QFrame()
        byok_card.setObjectName("Card")
        byok_lay = QVBoxLayout(byok_card)
        byok_lay.setContentsMargins(14, 12, 14, 12)
        byok_lay.setSpacing(8)

        lbl_byok = QLabel("Provider & Credentials (BYOK)")
        lbl_byok.setStyleSheet("font-weight: 600; font-size: 13px;")
        byok_lay.addWidget(lbl_byok)

        # Provider
        byok_lay.addWidget(QLabel("Provider:"))
        self.prov_sel = QComboBox()
        for pid, pdata in PROVIDERS.items():
            self.prov_sel.addItem(pdata["name"], pid)
        self.prov_sel.currentIndexChanged.connect(self._on_provider_changed)
        byok_lay.addWidget(self.prov_sel)

        # Model
        byok_lay.addWidget(QLabel("Model:"))
        self.model_input = QLineEdit()
        byok_lay.addWidget(self.model_input)

        # API Key
        byok_lay.addWidget(QLabel("API Key (OS-protected storage):"))
        key_h = QHBoxLayout()
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)
        self.key_input.setPlaceholderText("Enter API key…")
        key_h.addWidget(self.key_input, 1)

        btn_save_key = QPushButton("Save")
        btn_save_key.clicked.connect(self._save_key)
        btn_clear_key = QPushButton("Clear")
        btn_clear_key.clicked.connect(self._clear_key)
        key_h.addWidget(btn_save_key)
        key_h.addWidget(btn_clear_key)
        byok_lay.addLayout(key_h)

        # Custom / Local Endpoint URL
        byok_lay.addWidget(QLabel("Endpoint URL (Local / Custom):"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Defaults to provider standard endpoint")
        byok_lay.addWidget(self.url_input)

        # Consent Opt-in Checkbox
        self.chk_optin = QCheckBox("Opt-in: Share project context with remote provider")
        self.chk_optin.setToolTip("Required before sending extracted findings, symbols, or decompiled snippets to remote APIs.")
        byok_lay.addWidget(self.chk_optin)

        left_lay.addWidget(byok_card)

        # Project Context Preview Card
        ctx_card = QFrame()
        ctx_card.setObjectName("Card")
        ctx_lay = QVBoxLayout(ctx_card)
        ctx_lay.setContentsMargins(14, 12, 14, 12)
        ctx_lay.setSpacing(6)

        lbl_ctx = QLabel("Active Project Context")
        lbl_ctx.setStyleSheet("font-weight: 600;")
        ctx_lay.addWidget(lbl_ctx)

        self.proj_sel = QComboBox()
        self.proj_sel.currentIndexChanged.connect(self._on_project_changed)
        ctx_lay.addWidget(self.proj_sel)

        self.ctx_preview = QPlainTextEdit()
        self.ctx_preview.setReadOnly(True)
        self.ctx_preview.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.ctx_preview.setPlaceholderText("No project findings loaded.")
        ctx_lay.addWidget(self.ctx_preview, 1)

        left_lay.addWidget(ctx_card, 1)
        split.addWidget(left_w)

        # Right Chat Panel
        right_w = QFrame()
        right_lay = QVBoxLayout(right_w)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(8)

        # Chat History Browser
        self.chat_history = QTextBrowser()
        self.chat_history.setOpenExternalLinks(True)
        right_lay.addWidget(self.chat_history, 1)

        # Action / Preset Prompt Chips
        chip_box = QHBoxLayout()
        chip_box.setSpacing(6)
        presets = [
            ("Explain Analysis", "Please explain the primary findings and security indicators discovered in this project."),
            ("Interpret Decompiled Code", "Help interpret the decompiled function logic and describe its functional purpose."),
            ("Summarize Architecture", "Summarize the discovered application architecture, components, and external services."),
            ("Clean-Room Spec", "Generate a clean-room functional requirements specification for reimplementing this application independently."),
            ("Generate Test Stubs", "Generate automated unit test stubs covering the discovered API contracts and data models."),
        ]
        for label, prompt in presets:
            btn = QPushButton(label)
            btn.setStyleSheet("font-size: 11px; padding: 3px 8px;")
            btn.clicked.connect(lambda _, p=prompt: self._insert_preset(p))
            chip_box.addWidget(btn)
        chip_box.addStretch(1)
        right_lay.addLayout(chip_box)

        # Prompt input + buttons
        bottom_h = QHBoxLayout()
        self.prompt_edit = QPlainTextEdit()
        self.prompt_edit.setFixedHeight(75)
        self.prompt_edit.setPlaceholderText("Ask the AI Assistant about findings, architecture, or clean-room implementation…")
        bottom_h.addWidget(self.prompt_edit, 1)

        btn_v = QVBoxLayout()
        self.btn_send = QPushButton("Send")
        self.btn_send.setObjectName("Primary")
        self.btn_send.clicked.connect(self._send_prompt)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_stream)
        btn_v.addWidget(self.btn_send)
        btn_v.addWidget(self.btn_cancel)
        bottom_h.addLayout(btn_v)

        right_lay.addLayout(bottom_h)
        split.addWidget(right_w)

        split.setSizes([380, 740])
        self.root.addWidget(split, 1)

        self._on_provider_changed(0)

    # ---- Lifecycle & Configuration -------------------------------------------
    def refresh(self, select: int | None = None) -> None:
        projs = self.ctx.db.projects()
        cur_data = self.proj_sel.currentData()
        self.proj_sel.blockSignals(True)
        self.proj_sel.clear()
        target_idx = 0
        for i, p in enumerate(projs):
            self.proj_sel.addItem(f"#{p['id']} · {p['name']} ({p['profile']})", p["id"])
            if select and p["id"] == select:
                target_idx = i
            elif not select and cur_data and p["id"] == cur_data:
                target_idx = i
        self.proj_sel.blockSignals(False)

        if projs:
            self.proj_sel.setCurrentIndex(target_idx)
            self._load_project(self.proj_sel.currentData())
        else:
            self.current_pid = None
            self.ctx_preview.setPlainText("")

    def _on_provider_changed(self, _idx: int):
        pid = self.prov_sel.currentData()
        prov = PROVIDERS.get(pid, PROVIDERS["openrouter"])
        self.model_input.setText(prov["default_model"])
        key = get_key(pid)
        self.key_input.setText(key or "")
        if pid == "local":
            self.url_input.setText("http://localhost:11434/v1/chat/completions")
        else:
            self.url_input.setText("")

    def _save_key(self):
        pid = self.prov_sel.currentData()
        k = self.key_input.text().strip()
        if k:
            set_key(pid, k)
            self.ctx.status(f"Saved API key for {pid} in protected storage.")
            QMessageBox.information(self, "API Key Saved", f"Key stored securely in OS credential storage for {pid}.")
        else:
            delete_key(pid)

    def _clear_key(self):
        pid = self.prov_sel.currentData()
        delete_key(pid)
        self.key_input.setText("")
        self.ctx.status(f"Cleared API key for {pid}.")

    def _on_project_changed(self, _idx: int):
        pid = self.proj_sel.currentData()
        if pid:
            self._load_project(pid)

    def _load_project(self, pid: int):
        self.current_pid = pid
        context = build_project_context(self.ctx.db, pid)
        self.ctx_preview.setPlainText(context)

    # ---- Chat & Interaction --------------------------------------------------
    def _insert_preset(self, text: str):
        self.prompt_edit.setPlainText(text)
        self.prompt_edit.setFocus()

    def _append_chat(self, sender: str, text: str):
        import html
        color = "#61afef" if sender == "User" else ("#98c379" if sender == "Assistant" else "#e5c07b")
        escaped = html.escape(text).replace("\n", "<br>")
        self.chat_history.append(f"<b style='color: {color};'>[{sender}]</b><br>{escaped}<br>")

    def _send_prompt(self):
        prompt = self.prompt_edit.toPlainText().strip()
        if not prompt:
            return

        pid = self.prov_sel.currentData()
        prov = PROVIDERS.get(pid, PROVIDERS["openrouter"])
        key = self.key_input.text().strip() or get_key(pid) or ""

        if pid != "local" and not key:
            QMessageBox.warning(self, "API Key Missing", f"Please provide an API key for {prov['name']} to continue.")
            return

        # Explicit consent check before sending project context
        include_context = self.chk_optin.isChecked()
        if not include_context and self.current_pid and pid != "local":
            ans = QMessageBox.question(
                self, "Opt-in Consent Required",
                "Would you like to include the project analysis context in this request?\n\n"
                "If No, the request will be processed without transmitting local project findings.",
                QMessageBox.Yes | QMessageBox.No
            )
            if ans == QMessageBox.Yes:
                self.chk_optin.setChecked(True)
                include_context = True

        self._append_chat("User", prompt)
        self.prompt_edit.clear()

        # Build message history
        built_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        if include_context and self.current_pid:
            ctx_text = build_project_context(self.ctx.db, self.current_pid)
            built_messages.append({"role": "system", "content": ctx_text})

        for m in self.messages[-10:]:
            built_messages.append(m)

        built_messages.append({"role": "user", "content": prompt})
        self.messages.append({"role": "user", "content": prompt})

        # Start streaming thread
        self.btn_send.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self._active_stream = threading.Event()
        self.chat_history.append("<b style='color: #98c379;'>[Assistant]</b><br>")

        model = self.model_input.text().strip() or prov["default_model"]
        custom_url = self.url_input.text().strip() or None
        stop_evt = self._active_stream

        def worker():
            collected = []
            try:
                for token in stream_chat(pid, key, model, built_messages, custom_url, stop_evt):
                    collected.append(token)
                    self.token_received.emit(token)
                full = "".join(collected)
                self.stream_finished.emit(full)
            except Exception as e:
                self.stream_error.emit(str(e))

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _cancel_stream(self):
        if self._active_stream:
            self._active_stream.set()
            self.ctx.status("AI request cancelled.")
            self._on_finished("[Response cancelled by user]")

    def _on_token(self, token: str):
        import html
        escaped = html.escape(token).replace("\n", "<br>")
        cursor = self.chat_history.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertHtml(escaped)
        self.chat_history.setTextCursor(cursor)

    def _on_finished(self, full_text: str):
        self.chat_history.append("<br>")
        self.messages.append({"role": "assistant", "content": full_text})
        self.btn_send.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self._active_stream = None

    def _on_error(self, err: str):
        self.chat_history.append(f"<br><span style='color: #e06c75;'>[Error: {err}]</span><br><br>")
        self.btn_send.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self._active_stream = None
