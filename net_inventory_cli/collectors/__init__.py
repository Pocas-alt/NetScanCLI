"""OS-specific inventory collectors."""

from . import linux, macos, windows

__all__ = ['linux', 'macos', 'windows']
