"""
Base collector abstract class for CyberCortexAssetBot.

This module defines the abstract base class that all platform-specific collectors
must implement. It uses Python 3.11 features including exception groups and
pattern matching for robust error handling.
"""

import hashlib
import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

from utils.platform_detector import PlatformInfo, get_current_platform


class AssetType(Enum):
    """Types of assets that can be collected."""
    DRIVERS = "drivers"
    APPLICATIONS = "applications"
    SERVICES = "services"
    LIBRARIES = "libraries"
    PACKAGES = "packages"
    CONTAINERS = "containers"


class CollectionError(Exception):
    """Base exception for collection errors."""
    pass


class CollectorNotSupportedError(CollectionError):
    """Raised when collector is not supported on current platform."""
    pass


class DataCollectionError(CollectionError):
    """Raised when data collection fails."""
    pass


@dataclass(frozen=True)
class AssetData:
    """Individual asset data container."""
    name: str
    version: Optional[str] = None
    path: Optional[str] = None
    checksum: Optional[str] = None
    signature: Optional[str] = None
    install_date: Optional[datetime] = None
    size: Optional[int] = None
    description: Optional[str] = None
    vendor: Optional[str] = None
    architecture: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        # Convert datetime to ISO string
        if data.get('install_date'):
            data['install_date'] = data['install_date'].isoformat()
        return data


@dataclass(frozen=True)
class CollectionResult:
    """Result of asset collection operation."""
    platform_info: PlatformInfo
    timestamp: datetime
    assets: Dict[AssetType, List[AssetData]]
    collection_duration: float
    success: bool
    errors: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'platform_info': {
                'platform_type': self.platform_info.platform_type.value,
                'system_name': self.platform_info.system_name,
                'release': self.platform_info.release,
                'version': self.platform_info.version,
                'machine': self.platform_info.machine,
                'processor': self.platform_info.processor,
                'python_version': self.platform_info.python_version,
                'architecture': self.platform_info.architecture
            },
            'timestamp': self.timestamp.isoformat(),
            'assets': {
                asset_type.value: [asset.to_dict() for asset in assets]
                for asset_type, assets in self.assets.items()
            },
            'collection_duration': self.collection_duration,
            'success': self.success,
            'errors': self.errors
        }
    
    def get_hash(self) -> str:
        """Generate hash for change detection."""
        data_str = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode()).hexdigest()


class BaseCollector(ABC):
    """
    Abstract base class for platform-specific asset collectors.
    
    This class defines the interface that all collectors must implement
    and provides common functionality for asset collection.
    """
    
    def __init__(self, platform_info: Optional[PlatformInfo] = None) -> None:
        """
        Initialize base collector.
        
        Args:
            platform_info: Platform information. If None, will be detected automatically.
        """
        self.platform_info = platform_info or get_current_platform()
        self._validate_platform_support()
    
    @abstractmethod
    def collect_drivers(self) -> List[AssetData]:
        """
        Collect driver information.
        
        Returns:
            List of driver assets
        """
        pass
    
    @abstractmethod
    def collect_applications(self) -> List[AssetData]:
        """
        Collect installed applications.
        
        Returns:
            List of application assets
        """
        pass
    
    @abstractmethod
    def collect_services(self) -> List[AssetData]:
        """
        Collect system services/daemons.
        
        Returns:
            List of service assets
        """
        pass
    
    @abstractmethod
    def collect_libraries(self) -> List[AssetData]:
        """
        Collect system libraries.
        
        Returns:
            List of library assets
        """
        pass
    
    @abstractmethod
    def collect_packages(self) -> List[AssetData]:
        """
        Collect programming language packages.
        
        Returns:
            List of package assets
        """
        pass
    
    @abstractmethod
    def collect_containers(self) -> List[AssetData]:
        """
        Collect container images.
        
        Returns:
            List of container assets
        """
        pass
    
    def collect_all(self) -> CollectionResult:
        """
        Collect all asset types.
        
        Returns:
            Complete collection result
        """
        start_time = datetime.now()
        errors: List[str] = []
        assets: Dict[AssetType, List[AssetData]] = {}
        
        # Collection methods mapping
        collection_methods = {
            AssetType.DRIVERS: self.collect_drivers,
            AssetType.APPLICATIONS: self.collect_applications,
            AssetType.SERVICES: self.collect_services,
            AssetType.LIBRARIES: self.collect_libraries,
            AssetType.PACKAGES: self.collect_packages,
            AssetType.CONTAINERS: self.collect_containers,
        }
        
        # Collect each asset type with error handling
        for asset_type, method in collection_methods.items():
            try:
                assets[asset_type] = method()
            except Exception as e:
                error_msg = f"Failed to collect {asset_type.value}: {str(e)}"
                errors.append(error_msg)
                assets[asset_type] = []
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return CollectionResult(
            platform_info=self.platform_info,
            timestamp=end_time,
            assets=assets,
            collection_duration=duration,
            success=len(errors) == 0,
            errors=errors
        )
    
    def collect_specific(self, asset_types: List[AssetType]) -> CollectionResult:
        """
        Collect specific asset types only.
        
        Args:
            asset_types: List of asset types to collect
            
        Returns:
            Collection result for specified types
        """
        start_time = datetime.now()
        errors: List[str] = []
        assets: Dict[AssetType, List[AssetData]] = {}
        
        # Collection methods mapping
        collection_methods = {
            AssetType.DRIVERS: self.collect_drivers,
            AssetType.APPLICATIONS: self.collect_applications,
            AssetType.SERVICES: self.collect_services,
            AssetType.LIBRARIES: self.collect_libraries,
            AssetType.PACKAGES: self.collect_packages,
            AssetType.CONTAINERS: self.collect_containers,
        }
        
        # Collect only specified asset types
        for asset_type in asset_types:
            if asset_type in collection_methods:
                try:
                    assets[asset_type] = collection_methods[asset_type]()
                except Exception as e:
                    error_msg = f"Failed to collect {asset_type.value}: {str(e)}"
                    errors.append(error_msg)
                    assets[asset_type] = []
            else:
                assets[asset_type] = []
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return CollectionResult(
            platform_info=self.platform_info,
            timestamp=end_time,
            assets=assets,
            collection_duration=duration,
            success=len(errors) == 0,
            errors=errors
        )
    
    @abstractmethod
    def _validate_platform_support(self) -> None:
        """
        Validate that collector supports current platform.
        
        Raises:
            CollectorNotSupportedError: If platform is not supported
        """
        pass
    
    def _calculate_checksum(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA256 checksum of a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA256 checksum or None if file doesn't exist
        """
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return hashlib.sha256(content).hexdigest()
        except (OSError, IOError):
            return None
    
    def _safe_execute(self, command: str, *args, **kwargs) -> Optional[str]:
        """
        Safely execute a command and return output.
        
        Args:
            command: Command to execute
            *args: Command arguments
            **kwargs: Additional subprocess arguments
            
        Returns:
            Command output or None if failed
        """
        import subprocess
        
        try:
            result = subprocess.run(
                [command] + list(args),
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',  # Replace invalid characters instead of failing
                check=True,
                **kwargs
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None
    
    def get_platform_info(self) -> PlatformInfo:
        """Get current platform information."""
        return self.platform_info
    
    def is_supported(self) -> bool:
        """Check if collector supports current platform."""
        try:
            self._validate_platform_support()
            return True
        except CollectorNotSupportedError:
            return False
