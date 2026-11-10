"""Syntax highlighter for code and markup in ReForge Studio viewers."""
from __future__ import annotations

import re

from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextDocument


class CodeHighlighter(QSyntaxHighlighter):
    """Multi-language regex-based syntax highlighter supporting dark and light themes."""

    def __init__(self, parent=None, lang: str = "generic", theme: str = "dark"):
        if hasattr(parent, "document"):
            super().__init__(parent)
            self.setDocument(parent.document())
        elif isinstance(parent, QTextDocument) and parent.parent():
            super().__init__(parent.parent())
            self.setDocument(parent)
        else:
            super().__init__(parent)
        self.lang = lang.lower()
        self.theme = theme
        self.rules: list[tuple[re.Pattern, QTextCharFormat]] = []
        self._init_styles()
        self._build_rules()

    def _init_styles(self):
        is_dark = self.theme == "dark"
        self.fmt_kw = QTextCharFormat()
        self.fmt_kw.setForeground(QColor("#c678dd" if is_dark else "#a626a4"))
        self.fmt_kw.setFontWeight(QFont.Bold)

        self.fmt_type = QTextCharFormat()
        self.fmt_type.setForeground(QColor("#e5c07b" if is_dark else "#b76b01"))

        self.fmt_str = QTextCharFormat()
        self.fmt_str.setForeground(QColor("#98c379" if is_dark else "#50a14f"))

        self.fmt_comment = QTextCharFormat()
        self.fmt_comment.setForeground(QColor("#5c6370" if is_dark else "#a0a1a7"))
        self.fmt_comment.setFontItalic(True)

        self.fmt_num = QTextCharFormat()
        self.fmt_num.setForeground(QColor("#d19a66" if is_dark else "#986801"))

        self.fmt_tag = QTextCharFormat()
        self.fmt_tag.setForeground(QColor("#e06c75" if is_dark else "#e45649"))
        self.fmt_tag.setFontWeight(QFont.Bold)

        self.fmt_attr = QTextCharFormat()
        self.fmt_attr.setForeground(QColor("#d19a66" if is_dark else "#986801"))

        self.fmt_reg = QTextCharFormat()
        self.fmt_reg.setForeground(QColor("#61afef" if is_dark else "#0184bc"))

        self.fmt_inst = QTextCharFormat()
        self.fmt_inst.setForeground(QColor("#e06c75" if is_dark else "#e45649"))
        self.fmt_inst.setFontWeight(QFont.Bold)

        self.fmt_addr = QTextCharFormat()
        self.fmt_addr.setForeground(QColor("#c678dd" if is_dark else "#a626a4"))

    def _build_rules(self):
        self.rules.clear()
        if self.lang in ("xml", "html", "xaml", "axml"):
            # Tags: <tag, </tag, >
            self.rules.append((re.compile(r"</?[a-zA-Z0-9_\-:]+"), self.fmt_tag))
            self.rules.append((re.compile(r"/?>"), self.fmt_tag))
            # Attributes: attr=
            self.rules.append((re.compile(r'\b[a-zA-Z0-9_\-:]+(?=\=)'), self.fmt_attr))
            # Strings in attributes
            self.rules.append((re.compile(r'"[^"\\]*(\\.[^"\\]*)*"'), self.fmt_str))
            self.rules.append((re.compile(r"'[^'\\]*(\\.[^'\\]*)*'"), self.fmt_str))
            # Comments: <!-- ... -->
            self.rules.append((re.compile(r"<!--[^\n]*?-->"), self.fmt_comment))
            return

        if self.lang in ("asm", "assembly", "disasm", "s"):
            # Comments (; or // or #)
            self.rules.append((re.compile(r";[^\n]*"), self.fmt_comment))
            self.rules.append((re.compile(r"//[^\n]*"), self.fmt_comment))
            self.rules.append((re.compile(r"#[^\n]*"), self.fmt_comment))

            # Addresses (0x... or 8+ hex digits at word boundary)
            self.rules.append((re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,16}\b"), self.fmt_addr))

            # Assembly Mnemonics (x86/x64 and ARM/ARM64)
            mnemonics = [
                "mov", "movzx", "movsx", "movsxd", "lea", "push", "pop", "call", "jmp",
                "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl",
                "jle", "js", "jns", "jo", "jno", "test", "cmp", "add", "sub", "imul",
                "idiv", "mul", "div", "inc", "dec", "xor", "and", "or", "not", "shl",
                "shr", "sar", "rol", "ror", "ret", "retq", "nop", "int", "syscall",
                "sysenter", "hlt", "leave", "enter", "cqo", "cdq", "cbw", "cwde",
                "clflush", "cpuid", "cmova", "cmovb", "cmove", "cmovne", "cmovg", "cmovl",
                "seta", "setb", "sete", "setne", "setg", "setl", "setz", "setnz",
                "ldr", "ldrb", "ldrh", "str", "strb", "strh", "ldp", "stp", "b", "bl",
                "bx", "blx", "cbz", "cbnz", "tbz", "tbnz", "adr", "adrp", "svc", "mrs",
                "msr", "ubfx", "sbfx", "lsl", "lsr", "asr",
            ]
            mnem_re = r"\b(" + "|".join(mnemonics) + r")\b"
            self.rules.append((re.compile(mnem_re, re.IGNORECASE), self.fmt_inst))

            # Registers (x86, x64, ARM, ARM64)
            regs = [
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
                "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "ip",
                "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
                "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
                "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
                "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
                "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
                "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9",
                "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19",
                "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30",
                "lr", "pc", "cpsr", "fpsr", "fpcr",
            ]
            reg_re = r"\b(" + "|".join(regs) + r")\b"
            self.rules.append((re.compile(reg_re, re.IGNORECASE), self.fmt_reg))

            # Numeric constants
            self.rules.append((re.compile(r"\b\d+\b"), self.fmt_num))
            return

        if self.lang == "json":
            # JSON Property keys
            self.rules.append((re.compile(r'"[^"\\]*(\\.[^"\\]*)*"\s*(?=:)'), self.fmt_tag))
            # JSON Strings
            self.rules.append((re.compile(r':\s*"[^"\\]*(\\.[^"\\]*)*"'), self.fmt_str))
            # JSON Numbers
            self.rules.append((re.compile(r"\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b"), self.fmt_num))
            # JSON Booleans and null
            self.rules.append((re.compile(r"\b(true|false|null)\b"), self.fmt_kw))
            return

        # General keywords
        kws = [
            "class", "def", "function", "return", "if", "else", "elif", "for", "while",
            "import", "from", "as", "try", "except", "catch", "finally", "public",
            "private", "protected", "static", "void", "int", "string", "bool", "float",
            "double", "new", "this", "super", "null", "true", "false", "None", "True",
            "False", "const", "let", "var", "interface", "namespace", "package", "struct",
            "async", "await", "yield", "switch", "case", "break", "continue", "default",
            "throw", "throws", "override", "virtual", "using", "extends", "implements",
        ]
        kw_re = r"\b(" + "|".join(kws) + r")\b"
        self.rules.append((re.compile(kw_re), self.fmt_kw))

        # Types / Classes (starts with capital)
        self.rules.append((re.compile(r"\b[A-Z][a-zA-Z0-9_]*\b"), self.fmt_type))

        # Numbers (hex and dec)
        self.rules.append((re.compile(r"\b0x[0-9a-fA-F]+\b|\b\d+(\.\d+)?\b"), self.fmt_num))

        # Strings
        self.rules.append((re.compile(r'"[^"\\]*(\\.[^"\\]*)*"'), self.fmt_str))
        self.rules.append((re.compile(r"'[^'\\]*(\\.[^'\\]*)*'"), self.fmt_str))

        # Single-line comments (// and #)
        self.rules.append((re.compile(r"//[^\n]*"), self.fmt_comment))
        self.rules.append((re.compile(r"#[^\n]*"), self.fmt_comment))

    def set_language(self, lang: str):
        self.lang = lang.lower()
        self._build_rules()
        self.rehighlight()

    def set_theme(self, theme: str):
        self.theme = theme
        self._init_styles()
        self._build_rules()
        self.rehighlight()

    def highlightBlock(self, text: str):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, fmt)
