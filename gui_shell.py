"""Native Qt presentation for the existing local capture and analysis workflows.

These helpers create views only. Navigation never starts a capture, resolves a
name, writes a baseline, or reconstructs an evidence widget.
"""

from __future__ import annotations

from typing import NamedTuple

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication, QGridLayout, QLabel, QListWidget, QListWidgetItem, QPushButton,
    QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from gui_icons import WorkspaceIconKey, workspace_icon

Destination = WorkspaceIconKey


class WorkspaceDestination(NamedTuple):
    """Closed navigation metadata; indexes refer to the existing workspace tabs."""

    key: Destination
    title: str
    subtitle: str
    icon: WorkspaceIconKey
    workspace_index: int | None


DESTINATIONS: tuple[WorkspaceDestination, ...] = (
    WorkspaceDestination("overview", "Overview", "Local capture and evidence analysis", "overview", None),
    WorkspaceDestination("setup", "Check setup", "Verify this computer and the selected device", "setup", 2),
    WorkspaceDestination("capture", "Device & Capture", "Record an authorized iPhone or iPad capture", "capture", 0),
    WorkspaceDestination("analysis", "Analysis", "Inspect saved packets, scoped sessions, and DNS evidence", "analysis", 1),
    WorkspaceDestination("baselines", "Baselines", "Choose persistent history and review changes before applying them", "baselines", None),
    WorkspaceDestination("exports", "Exports", "Choose and open the local analysis output directory", "exports", None),
    WorkspaceDestination("diagnostics", "Diagnostics", "Review local status and copy redacted troubleshooting details", "diagnostics", None),
)


def destination_for_key(key: str) -> WorkspaceDestination:
    """Reject unknown routes rather than navigating to a guessed workspace."""
    for destination in DESTINATIONS:
        if destination.key == key:
            return destination
    raise ValueError(f"Unknown application destination: {key}")


def plain_label(text: str, name: str, parent: QWidget) -> QLabel:
    """Keep even path-like or captured text literal and within the page width."""
    label = QLabel(text, parent)
    label.setObjectName(name)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setMinimumWidth(0)
    label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
    return label


def scroll_page(content: QWidget, name: str, parent: QWidget) -> QScrollArea:
    """Allow long local details to scroll without increasing the window minimum."""
    scroll = QScrollArea(parent)
    scroll.setObjectName(name)
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QScrollArea.Shape.NoFrame)
    scroll.setWidget(content)
    return scroll


def populate_sidebar(sidebar: QListWidget) -> None:
    """Share the application palette used by shell stylesheet palette() colors."""
    sidebar.setObjectName("navigationSidebar")
    sidebar.setAccessibleName("Application workspaces")
    sidebar.setIconSize(QSize(18, 18))
    sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    sidebar.setFixedWidth(180)
    for destination in DESTINATIONS:
        item = QListWidgetItem(workspace_icon(destination.icon, QApplication.palette()), destination.title)
        item.setData(Qt.ItemDataRole.UserRole, destination.key)
        item.setSizeHint(QSize(170, 38))
        sidebar.addItem(item)


def workflow_card(destination: WorkspaceDestination, parent: QWidget) -> QPushButton:
    """Make the entire card a keyboard-focusable, accessible navigation button."""
    button = QPushButton(parent)
    button.setObjectName("overview" + destination.key.title() + "Button")
    button.setProperty("role", "workflowCard")
    button.setAccessibleName(destination.title)
    button.setAccessibleDescription(destination.subtitle)
    button.setMinimumHeight(116)
    button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    layout = QVBoxLayout(button)
    layout.setContentsMargins(16, 12, 16, 12)
    layout.setSpacing(5)
    icon = QLabel(button)
    icon.setObjectName("overview" + destination.key.title() + "Icon")
    icon.setPixmap(workspace_icon(destination.icon, QApplication.palette()).pixmap(
        QSize(24, 24), icon.devicePixelRatioF(), QIcon.Mode.Normal, QIcon.State.Off,
    ))
    title = plain_label(destination.title, "workflowTitle", button)
    description = plain_label(destination.subtitle, "workflowDescription", button)
    for label in (icon, title, description):
        label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        layout.addWidget(label)
    return button


def refresh_workspace_icons(sidebar: QListWidget, cards: tuple[tuple[Destination, QPushButton], ...]) -> None:
    """Refresh application palette and display scale while preserving widgets."""
    if sidebar.count() != len(DESTINATIONS):
        raise RuntimeError("Workspace sidebar has an unexpected number of destinations")
    for position, destination in enumerate(DESTINATIONS):
        item = sidebar.item(position)
        if item is None or item.data(Qt.ItemDataRole.UserRole) != destination.key:
            raise RuntimeError(f"Workspace sidebar destination is missing or out of order: {destination.key}")
        item.setIcon(workspace_icon(destination.icon, QApplication.palette()))
    for key, button in cards:
        destination = destination_for_key(key)
        icon = button.findChild(QLabel, "overview" + key.title() + "Icon")
        if icon is None:
            raise RuntimeError(f"Workspace overview card icon is missing: {key}")
        mode = QIcon.Mode.Normal if button.isEnabled() else QIcon.Mode.Disabled
        icon.setPixmap(workspace_icon(destination.icon, QApplication.palette()).pixmap(
            QSize(24, 24), icon.devicePixelRatioF(), mode, QIcon.State.Off,
        ))


def overview_page(parent: QWidget) -> tuple[QScrollArea, tuple[tuple[Destination, QPushButton], ...]]:
    content = QWidget(parent)
    layout = QVBoxLayout(content)
    layout.setContentsMargins(2, 4, 2, 4)
    layout.setSpacing(16)
    intro = plain_label(
        "Start with setup, record authorized traffic, or open a saved capture for passive analysis.",
        "overviewIntroduction", content,
    )
    layout.addWidget(intro)
    grid = QGridLayout()
    grid.setSpacing(12)
    grid.setColumnStretch(0, 1)
    grid.setColumnStretch(1, 1)
    actions: list[tuple[Destination, QPushButton]] = []
    for index, destination in enumerate(DESTINATIONS[1:]):
        button = workflow_card(destination, content)
        grid.addWidget(button, index // 2, index % 2)
        actions.append((destination.key, button))
    layout.addLayout(grid)
    scope = plain_label(
        "A new endpoint or hostname is a change to investigate, not proof of malicious activity. "
        "Encrypted payloads remain protected. Captures and identifiers stay local.",
        "overviewEvidenceNotice", content,
    )
    scope.setProperty("role", "notice")
    layout.addWidget(scope)
    layout.addStretch(1)
    return scroll_page(content, "overviewPage", parent), tuple(actions)


def shell_stylesheet() -> str:
    """Use Qt palette roles so the host's light or dark colors remain authoritative."""
    return """
        QWidget#sidebarPanel { background: palette(alternate-base); }
        QLabel#applicationTitle { font-size: 17px; font-weight: 700; }
        QLabel#pageTitle { font-size: 24px; font-weight: 700; }
        QLabel#pageSubtitle, QLabel#workflowDescription { font-size: 12px; }
        QLabel#workflowTitle { font-size: 16px; font-weight: 600; }
        QLabel#metricValue { font-size: 22px; font-weight: 600; }
        QListWidget#navigationSidebar { border: 0; background: transparent; outline: 0; }
        QListWidget#navigationSidebar::item { border-radius: 7px; padding-left: 6px; }
        QListWidget#navigationSidebar::item:selected {
            background: palette(highlight); color: palette(highlighted-text);
        }
        QTabWidget::pane { border: 0; }
        QGroupBox {
            border: 1px solid palette(mid); border-radius: 10px;
            margin-top: 16px; padding: 8px;
        }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
        QPushButton[role="workflowCard"] {
            background: palette(base); border: 1px solid palette(mid);
            border-radius: 12px; text-align: left;
        }
        QPushButton[role="workflowCard"]:hover { background: palette(alternate-base); }
        QPushButton[role="workflowCard"]:focus { border: 2px solid palette(highlight); }
        QWidget[role="metricCard"] {
            background: palette(base); border: 1px solid palette(mid); border-radius: 10px;
        }
        QLabel[role="notice"] {
            background: palette(alternate-base); border: 1px solid palette(mid);
            border-radius: 8px; padding: 10px;
        }
    """
