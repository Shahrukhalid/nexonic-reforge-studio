"""Syntax highlighter for code and markup in ReForge Studio viewers."""
from __future__ import annotations

import re

from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat


class CodeHighlighter(QSyntaxHighlighter):
    """Multi-language regex-based syntax highlighter supporting dark and light themes."""

    def __init__(self, parent=None, lang: str = "generic", theme: str = "dark"):
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
