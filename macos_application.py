#!/usr/bin/env python3
"""Narrow macOS application integration for RVI-Sentinel."""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
from pathlib import Path


def set_macos_application_icon(path: Path) -> None:
    """Apply an image to the running macOS application's Dock tile."""
    if sys.platform != "darwin":
        return
    if not path.is_file():
        raise FileNotFoundError(f"RVI-Sentinel macOS application icon not found: {path}")

    objective_c_library = ctypes.util.find_library("objc")
    if objective_c_library is None:
        raise RuntimeError("RVI-Sentinel could not locate the macOS Objective-C runtime.")

    objective_c = ctypes.CDLL(objective_c_library)
    ctypes.CDLL("/System/Library/Frameworks/AppKit.framework/AppKit")
    objective_c.objc_getClass.argtypes = [ctypes.c_char_p]
    objective_c.objc_getClass.restype = ctypes.c_void_p
    objective_c.sel_registerName.argtypes = [ctypes.c_char_p]
    objective_c.sel_registerName.restype = ctypes.c_void_p

    message_address = ctypes.cast(objective_c.objc_msgSend, ctypes.c_void_p).value
    if message_address is None:
        raise RuntimeError("RVI-Sentinel could not access the macOS Objective-C message bridge.")
    send_message = ctypes.CFUNCTYPE(
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )(message_address)
    send_message_with_argument = ctypes.CFUNCTYPE(
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )(message_address)

    def objective_c_class(name: bytes) -> int:
        class_pointer = objective_c.objc_getClass(name)
        if class_pointer is None:
            raise RuntimeError(f"RVI-Sentinel could not load the macOS class {name.decode()}.")
        return class_pointer

    def selector(name: bytes) -> int:
        selector_pointer = objective_c.sel_registerName(name)
        if selector_pointer is None:
            raise RuntimeError(f"RVI-Sentinel could not load the macOS selector {name.decode()}.")
        return selector_pointer

    encoded_path = str(path.resolve()).encode("utf-8")
    path_pointer = ctypes.cast(ctypes.c_char_p(encoded_path), ctypes.c_void_p)
    native_path = send_message_with_argument(
        objective_c_class(b"NSString"),
        selector(b"stringWithUTF8String:"),
        path_pointer,
    )
    if native_path is None:
        raise RuntimeError(f"RVI-Sentinel could not represent the icon path on macOS: {path}")

    native_image = send_message(objective_c_class(b"NSImage"), selector(b"alloc"))
    native_image = send_message_with_argument(
        native_image,
        selector(b"initWithContentsOfFile:"),
        native_path,
    )
    if native_image is None:
        raise ValueError(f"RVI-Sentinel macOS application icon could not be decoded: {path}")

    native_application = send_message(
        objective_c_class(b"NSApplication"),
        selector(b"sharedApplication"),
    )
    if native_application is None:
        raise RuntimeError("RVI-Sentinel could not access the shared macOS application.")
    send_message_with_argument(
        native_application,
        selector(b"setApplicationIconImage:"),
        native_image,
    )
    applied_image = send_message(
        native_application,
        selector(b"applicationIconImage"),
    )
    if applied_image is None:
        raise RuntimeError("RVI-Sentinel could not apply its icon to the macOS application.")
