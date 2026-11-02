"""Light/Dark QSS themes."""

PALETTES = {
    "dark": dict(bg="#14161b", panel="#1b1e25", side="#101216", border="#2a2e38", text="#e6e8ee", muted="#8b93a7",
                 accent="#4f8cff", accent_text="#ffffff", sel="#243250", input="#0f1115", ok="#3fb27f",
                 warn="#e0a43b", err="#e5534b"),
    "light": dict(bg="#f5f6f8", panel="#ffffff", side="#eceef2", border="#d9dde5", text="#1b1f27", muted="#5d6577",
                  accent="#2f6fe4", accent_text="#ffffff", sel="#dce7fd", input="#ffffff", ok="#1f8a5b",
                  warn="#b7791f", err="#c93c37"),
}


def qss(name: str) -> str:
    p = PALETTES.get(name, PALETTES["dark"])
    return f"""
* {{ font-size: 13px; color: {p['text']}; }}
QMainWindow, QWidget#Page {{ background: {p['bg']}; }}
QWidget#Sidebar {{ background: {p['side']}; border-right: 1px solid {p['border']}; }}
QLabel#Brand {{ font-size: 15px; font-weight: 600; padding: 18px 16px 4px 16px; }}
QLabel#BrandSub {{ color: {p['muted']}; padding: 0 16px 14px 16px; font-size: 11px; }}
QListWidget#Nav {{ background: transparent; border: none; outline: 0; padding: 4px 8px; }}
QListWidget#Nav::item {{ padding: 8px 10px; border-radius: 6px; margin: 1px 0; }}
QListWidget#Nav::item:selected {{ background: {p['sel']}; color: {p['text']}; }}
QListWidget#Nav::item:hover:!selected {{ background: {p['border']}; }}
QLabel#H1 {{ font-size: 20px; font-weight: 600; }}
QLabel#Muted {{ color: {p['muted']}; }}
QFrame#Card {{ background: {p['panel']}; border: 1px solid {p['border']}; border-radius: 10px; }}
QLabel#Stat {{ font-size: 24px; font-weight: 600; }}
QFrame#Drop {{ background: {p['panel']}; border: 2px dashed {p['border']}; border-radius: 12px; }}
QFrame#Drop[hover="true"] {{ border-color: {p['accent']}; }}
QPushButton {{ background: {p['panel']}; border: 1px solid {p['border']}; border-radius: 6px; padding: 6px 14px; }}
QPushButton:hover {{ border-color: {p['accent']}; }}
QPushButton#Primary {{ background: {p['accent']}; color: {p['accent_text']}; border: none; font-weight: 600; }}
QPushButton:disabled {{ color: {p['muted']}; }}
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{ background: {p['input']}; border: 1px solid {p['border']};
  border-radius: 6px; padding: 4px 6px; selection-background-color: {p['sel']}; }}
QTableWidget, QTreeWidget {{ background: {p['panel']}; border: 1px solid {p['border']}; border-radius: 8px;
  gridline-color: {p['border']}; alternate-background-color: {p['bg']}; }}
QHeaderView::section {{ background: {p['side']}; border: none; border-bottom: 1px solid {p['border']}; padding: 6px; font-weight: 600; }}
QTableWidget::item:selected, QTreeWidget::item:selected {{ background: {p['sel']}; color: {p['text']}; }}
QProgressBar {{ background: {p['input']}; border: 1px solid {p['border']}; border-radius: 5px; height: 10px; text-align: center; }}
QProgressBar::chunk {{ background: {p['accent']}; border-radius: 4px; }}
QSplitter::handle {{ background: {p['border']}; }}
QStatusBar {{ background: {p['side']}; color: {p['muted']}; border-top: 1px solid {p['border']}; }}
QTabWidget::pane {{ border: 1px solid {p['border']}; border-radius: 6px; }}
QTabBar::tab {{ padding: 6px 12px; }}
QTabBar::tab:selected {{ color: {p['accent']}; }}
"""


def status_color(name: str, theme: str) -> str:
    p = PALETTES.get(theme, PALETTES["dark"])
    if name.startswith(("Bundled", "Installed")):
        return p["ok"]
    if name.startswith(("Unsupported", "Verification failed", "Deprecated")):
        return p["err"]
    if name.startswith(("External paid", "Installation pending")):
        return p["warn"]
    return p["muted"]
