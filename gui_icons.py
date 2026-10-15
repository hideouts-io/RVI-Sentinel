"""Original, palette-aware Qt icons for the application's local workspaces.

Every glyph uses a 24-unit canvas and the same rounded stroke. The explicit
palette keeps rendering independent of installed fonts and platform icon
themes. Qt's native pixmap icon engine manages selection, scaling and copies.
"""

from __future__ import annotations

from math import ceil, isfinite
from typing import Literal

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import (
    QColor, QGuiApplication, QIcon, QPainter, QPainterPath, QPalette,
    QPen, QPixmap,
)

WorkspaceIconKey = Literal["overview", "setup", "capture", "analysis", "baselines", "exports", "diagnostics"]


def _overview_path() -> QPainterPath:
    path = QPainterPath()
    for x, y in ((3.5, 3.5), (14.0, 3.5), (3.5, 14.0), (14.0, 14.0)):
        path.addRoundedRect(QRectF(x, y, 6.5, 6.5), 1.3, 1.3)
    return path


def _setup_path() -> QPainterPath:
    path = QPainterPath()
    path.moveTo(9.0, 4.5)
    path.lineTo(6.5, 4.5)
    path.quadTo(5.0, 4.5, 5.0, 6.0)
    path.lineTo(5.0, 19.0)
    path.quadTo(5.0, 20.5, 6.5, 20.5)
    path.lineTo(18.0, 20.5)
    path.quadTo(19.5, 20.5, 19.5, 19.0)
    path.lineTo(19.5, 6.0)
    path.quadTo(19.5, 4.5, 18.0, 4.5)
    path.lineTo(15.5, 4.5)
    path.addRoundedRect(QRectF(9.0, 2.5, 6.5, 4.0), 1.0, 1.0)
    for y in (10.0, 16.0):
        path.moveTo(7.5, y)
        path.lineTo(8.5, y + 1.5)
        path.lineTo(11.0, y - 1.5)
        path.moveTo(13.5, y)
        path.lineTo(17.0, y)
    return path


def _capture_path() -> QPainterPath:
    path = QPainterPath()
    path.addRoundedRect(QRectF(3.5, 3.0, 11.0, 18.0), 2.0, 2.0)
    path.moveTo(7.0, 5.5)
    path.lineTo(11.0, 5.5)
    path.moveTo(8.0, 18.5)
    path.lineTo(10.0, 18.5)
    path.addEllipse(QRectF(15.5, 14.0, 6.0, 6.0))
    path.addEllipse(QRectF(17.5, 16.0, 2.0, 2.0))
    return path


def _analysis_path() -> QPainterPath:
    path = QPainterPath()
    path.addEllipse(QRectF(3.5, 3.5, 12.0, 12.0))
    path.moveTo(14.0, 14.0)
    path.lineTo(20.5, 20.5)
    path.moveTo(6.0, 10.0)
    path.lineTo(8.0, 10.0)
    path.lineTo(9.0, 7.5)
    path.lineTo(10.5, 12.0)
    path.lineTo(12.0, 9.5)
    path.lineTo(13.0, 9.5)
    return path


def _baselines_path() -> QPainterPath:
    path = QPainterPath()
    path.moveTo(12.0, 3.0)
    path.lineTo(20.5, 8.0)
    path.lineTo(12.0, 13.0)
    path.lineTo(3.5, 8.0)
    path.closeSubpath()
    for y in (12.5, 17.0):
        path.moveTo(3.5, y)
        path.lineTo(12.0, y + 4.5)
        path.lineTo(20.5, y)
    return path


def _exports_path() -> QPainterPath:
    path = QPainterPath()
    path.moveTo(11.0, 20.5)
    path.lineTo(5.0, 20.5)
    path.quadTo(3.5, 20.5, 3.5, 19.0)
    path.lineTo(3.5, 5.0)
    path.quadTo(3.5, 3.5, 5.0, 3.5)
    path.lineTo(12.5, 3.5)
    path.lineTo(17.0, 8.0)
    path.lineTo(17.0, 11.0)
    path.moveTo(12.5, 3.5)
    path.lineTo(12.5, 8.0)
    path.lineTo(17.0, 8.0)
    path.moveTo(10.0, 16.5)
    path.lineTo(21.0, 16.5)
    path.moveTo(17.5, 13.0)
    path.lineTo(21.0, 16.5)
    path.lineTo(17.5, 20.0)
    return path


def _diagnostics_path() -> QPainterPath:
    path = QPainterPath()
    path.moveTo(7.0, 20.5)
    path.lineTo(5.0, 20.5)
    path.quadTo(3.5, 20.5, 3.5, 19.0)
    path.lineTo(3.5, 5.0)
    path.quadTo(3.5, 3.5, 5.0, 3.5)
    path.lineTo(14.5, 3.5)
    path.quadTo(16.0, 3.5, 16.0, 5.0)
    path.lineTo(16.0, 7.0)
    path.moveTo(6.5, 7.5)
    path.lineTo(12.5, 7.5)
    path.moveTo(6.5, 11.5)
    path.lineTo(10.0, 11.5)
    path.moveTo(18.0, 8.5)
    path.lineTo(16.2, 10.3)
    path.lineTo(18.2, 12.3)
    path.lineTo(20.0, 10.5)
    path.cubicTo(21.0, 12.5, 19.0, 15.3, 16.8, 14.5)
    path.lineTo(11.0, 20.3)
    path.quadTo(10.4, 21.0, 9.7, 20.3)
    path.lineTo(9.0, 19.6)
    path.quadTo(8.4, 19.0, 9.0, 18.4)
    path.lineTo(14.8, 12.6)
    path.cubicTo(14.0, 10.2, 15.4, 8.0, 18.0, 8.5)
    path.closeSubpath()
    return path


def _workspace_path(key: WorkspaceIconKey) -> QPainterPath:
    match key:
        case "overview":
            return _overview_path()
        case "setup":
            return _setup_path()
        case "capture":
            return _capture_path()
        case "analysis":
            return _analysis_path()
        case "baselines":
            return _baselines_path()
        case "exports":
            return _exports_path()
        case "diagnostics":
            return _diagnostics_path()
    raise ValueError(f"Unknown workspace icon key: {key}")


def _workspace_pixmap(path: QPainterPath, color: QColor, size: QSize, scale: float) -> QPixmap:
    """Draw a fresh raster without mutating its original path or palette color."""
    if not 1 <= size.width() <= 1024 or not 1 <= size.height() <= 1024:
        raise ValueError("Workspace icon size must be between 1 and 1024 logical pixels per dimension")
    if not isfinite(scale) or not 0.0 < scale <= 8.0:
        raise ValueError("Workspace icon display scale must be finite, positive, and at most 8")
    pixmap = QPixmap(ceil(size.width() * scale), ceil(size.height() * scale))
    if pixmap.isNull():
        raise RuntimeError("Unable to allocate the workspace icon raster")
    pixmap.setDevicePixelRatio(scale)
    pixmap.fill(Qt.GlobalColor.transparent)
    with QPainter(pixmap) as painter:
        if not painter.isActive():
            raise RuntimeError("Unable to activate the workspace icon painter")
        extent = min(size.width(), size.height())
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.translate((size.width() - extent) / 2.0, (size.height() - extent) / 2.0)
        painter.scale(extent / 24.0, extent / 24.0)
        painter.setPen(QPen(color, 1.6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)
    return pixmap


def workspace_icon(key: WorkspaceIconKey, palette: QPalette) -> QIcon:
    """Provide sidebar/card glyphs and up to 4x rasters through Qt's native engine.

    Smaller fractional display scales are resampled by Qt from these original
    renders. Native engine ownership preserves safe QIcon copies and detachment.
    """
    if not isinstance(QGuiApplication.instance(), QGuiApplication):
        raise RuntimeError("Workspace icons require an initialized Qt GUI application")
    path = _workspace_path(key)
    group = palette.currentColorGroup()
    text = palette.color(group, QPalette.ColorRole.Text)
    modes: tuple[tuple[QIcon.Mode, QColor], ...] = (
        (QIcon.Mode.Normal, text),
        (QIcon.Mode.Active, text),
        (QIcon.Mode.Selected, palette.color(group, QPalette.ColorRole.HighlightedText)),
        (QIcon.Mode.Disabled, palette.color(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text)),
    )
    icon = QIcon()
    for mode, color in modes:
        for extent in (18, 24):
            for scale in (1.0, 2.0, 3.0, 4.0):
                pixmap = _workspace_pixmap(path, color, QSize(extent, extent), scale)
                icon.addPixmap(pixmap, mode, QIcon.State.Off)
                icon.addPixmap(pixmap, mode, QIcon.State.On)
    if icon.isNull():
        raise RuntimeError(f"Unable to create the workspace icon: {key}")
    return icon
