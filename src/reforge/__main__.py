import logging
import sys
from logging.handlers import RotatingFileHandler


def main() -> int:
    from PySide6.QtWidgets import QApplication

    from . import APP_NAME, PUBLISHER, __version__
    from .core import paths
    from .ui.main_window import MainWindow
    from .ui.theme import qss

    logger = logging.getLogger("reforge")
    logger.setLevel(logging.INFO)
    fh = RotatingFileHandler(paths.log_path(), maxBytes=5 * 1024**2, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(fh)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(PUBLISHER)
    app.setApplicationVersion(__version__)
    win = MainWindow()
    app.setStyleSheet(qss(win.ctx.theme))
    win.show()
    logger.info("%s %s started", APP_NAME, __version__)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
