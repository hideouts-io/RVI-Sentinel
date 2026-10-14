"""An owned Qt worker loads validated report evidence outside the GUI thread."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QWidget

from gui_models import AnalysisReport, ReportLoadCancelled, ReportValidationError, load_report_cancellable


class ReportLoadWorker(QThread):
    """Deliver a generation-bound result; cancellation never emits partial evidence."""

    report_ready = Signal(int, AnalysisReport)
    report_failed = Signal(int, str)
    report_cancelled = Signal(int)

    def __init__(self, parent: QWidget, generation: int, path: Path) -> None:
        super().__init__(parent)
        self.generation = generation
        self.path = path
        self.cancellation = threading.Event()

    def cancel(self) -> None:
        self.cancellation.set()

    def run(self) -> None:
        try:
            report = load_report_cancellable(self.path, self.cancellation)
        except ReportLoadCancelled:
            self.report_cancelled.emit(self.generation)
        except ReportValidationError as error:
            self.report_failed.emit(self.generation, str(error))
        else:
            if self.cancellation.is_set():
                self.report_cancelled.emit(self.generation)
            else:
                self.report_ready.emit(self.generation, report)
