"""
Platform detection utilities for CyberCortexAssetBot.

This module provides cross-platform detection capabilities using Python 3.11 features
including pattern matching and self-documenting expressions.
"""

import platform
import sys
from enum import Enum
from typing import Literal, NamedTuple
from dataclasses import dataclass


class PlatformType(Enum):
    """Supported platform types."""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PlatformInfo:
    """Platform information container."""
    platform_type: PlatformType
    system_name: str
    release: str
    version: str
    machine: str
    processor: str
    python_version: str
    architecture: Literal["32bit", "64bit", "unknown"]


class PlatformDetector:
    """Cross-platform detection utility using Python 3.11 features."""
    
    def __init__(self) -> None:
        """Initialize platform detector."""
        self._cached_info: PlatformInfo | None = None
    
    def detect_platform(self) -> PlatformInfo:
        """
        Detect current platform information.
        
        Uses caching to avoid repeated system calls.
        
        Returns:
            PlatformInfo: Complete platform information
        """
        if self._cached_info is None:
            self._cached_info = self._detect_platform_info()
        
        return self._cached_info
    
    def _detect_platform_info(self) -> PlatformInfo:
        """Internal method to detect platform information."""
        system_name = platform.system().lower()
        
        # Use Python 3.11 pattern matching for platform detection
        platform_type = self._get_platform_type(system_name)
        
        # Get system information
        release = platform.release()
        version = platform.version()
        machine = platform.machine()
        processor = platform.processor()
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        
        # Detect architecture
        architecture = self._detect_architecture()
        
        return PlatformInfo(
            platform_type=platform_type,
            system_name=system_name,
            release=release,
            version=version,
            machine=machine,
            processor=processor,
            python_version=python_version,
            architecture=architecture
        )
    
    def _get_platform_type(self, system_name: str) -> PlatformType:
        """
        Determine platform type using pattern matching.
        
        Args:
            system_name: System name from platform.system()
            
        Returns:
            PlatformType: Detected platform type
        """
        # Use Python 3.11 pattern matching
        match system_name:
            case "linux":
                return PlatformType.LINUX
            case "windows":
                return PlatformType.WINDOWS
            case "darwin":
                return PlatformType.MACOS
            case _:
                return PlatformType.UNKNOWN
    
    def _detect_architecture(self) -> Literal["32bit", "64bit", "unknown"]:
        """
        Detect system architecture.
        
        Returns:
            Architecture type
        """
        # Check if we're running 64-bit Python
        if sys.maxsize > 2**32:
            return "64bit"
        else:
            return "32bit"
    
    def is_linux(self) -> bool:
        """Check if running on Linux."""
        return self.detect_platform().platform_type == PlatformType.LINUX
    
    def is_windows(self) -> bool:
        """Check if running on Windows."""
        return self.detect_platform().platform_type == PlatformType.WINDOWS
    
    def is_macos(self) -> bool:
        """Check if running on macOS."""
        return self.detect_platform().platform_type == PlatformType.MACOS
    
    def get_platform_string(self) -> str:
        """
        Get human-readable platform string.
        
        Returns:
            Formatted platform string
        """
        info = self.detect_platform()
        
        # Use self-documenting expressions (Python 3.11 feature)
        return (
            f"{info.platform_type.value.title()} "
            f"({info.system_name}) "
            f"{info.release} "
            f"{info.architecture}"
        )
    
    def get_collector_module_name(self) -> str:
        """
        Get the appropriate collector module name for current platform.
        
        Returns:
            Collector module name
        """
        platform_type = self.detect_platform().platform_type
        
        match platform_type:
            case PlatformType.LINUX:
                return "linux_collector"
            case PlatformType.WINDOWS:
                return "windows_collector"
            case PlatformType.MACOS:
                return "macos_collector"
            case _:
                raise RuntimeError(f"Unsupported platform: {platform_type.value}")
    
    def clear_cache(self) -> None:
        """Clear cached platform information."""
        self._cached_info = None


# Global platform detector instance
platform_detector = PlatformDetector()


def get_current_platform() -> PlatformInfo:
    """
    Get current platform information.
    
    Convenience function for accessing global platform detector.
    
    Returns:
        PlatformInfo: Current platform information
    """
    return platform_detector.detect_platform()


def is_supported_platform() -> bool:
    """
    Check if current platform is supported.
    
    Returns:
        True if platform is supported, False otherwise
    """
    platform_type = get_current_platform().platform_type
    return platform_type != PlatformType.UNKNOWN
