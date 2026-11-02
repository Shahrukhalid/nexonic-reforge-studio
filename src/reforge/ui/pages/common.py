from __future__ import annotations

from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


class Page(QWidget):
    title = ""
    subtitle = ""

    def __init__(self, app_ctx):
        super().__init__()
        self.ctx = app_ctx
        self.setObjectName("Page")
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(28, 22, 28, 22)
        self.root.setSpacing(14)
        h = QLabel(self.title)
        h.setObjectName("H1")
        self.root.addWidget(h)
        if self.subtitle:
            s = QLabel(self.subtitle)
            s.setObjectName("Muted")
            s.setWordWrap(True)
            self.root.addWidget(s)

    def refresh(self) -> None:  # called when page becomes visible
        pass


def card(title: str, value: str = "") -> tuple[QFrame, QLabel]:
    f = QFrame()
    f.setObjectName("Card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(16, 12, 16, 12)
    t = QLabel(title)
    t.setObjectName("Muted")
    v = QLabel(value)
    v.setObjectName("Stat")
    lay.addWidget(t)
    lay.addWidget(v)
    return f, v


class PlannedPage(Page):
    """Honest placeholder for modules not yet implemented."""

    def __init__(self, app_ctx, title: str, milestone: str, scope: str):
        self.title = title
        self.subtitle = f"Planned for {milestone}. Not implemented in this build."
        super().__init__(app_ctx)
        f = QFrame()
        f.setObjectName("Card")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(18, 16, 18, 16)
        lbl = QLabel(scope)
        lbl.setWordWrap(True)
        lay.addWidget(lbl)
        self.root.addWidget(f)
        self.root.addStretch(1)
