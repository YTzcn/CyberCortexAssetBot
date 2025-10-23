"""
macOS-specific asset collector for CyberCortexAssetBot.

This module implements macOS-specific asset collection using system commands,
property lists, and macOS-specific tools.
"""

import os
import subprocess
import plistlib
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import json

import psutil

from .base_collector import (
    BaseCollector, 
    AssetData, 
    CollectionResult, 
    AssetType,
    CollectorNotSupportedError,
    DataCollectionError
)
from utils.platform_detector import PlatformInfo, PlatformType


class MacOSCollector(BaseCollector):
    """macOS-specific asset collector implementation."""
    
    def __init__(self, platform_info: Optional[PlatformInfo] = None) -> None:
        """Initialize macOS collector."""
        super().__init__(platform_info)
    
    def _validate_platform_support(self) -> None:
        """Validate that collector supports current platform."""
        if self.platform_info.platform_type != PlatformType.MACOS:
            raise CollectorNotSupportedError(
                f"MacOSCollector only supports macOS, got {self.platform_info.platform_type.value}"
            )
    
    def collect_drivers(self) -> List[AssetData]:
        """
        Collect macOS kernel extensions and drivers.
        
        Returns:
            List of driver assets
        """
        drivers = []
        
        try:
            # Collect kernel extensions
            drivers.extend(self._collect_kernel_extensions())
            
            # Collect system extensions
            drivers.extend(self._collect_system_extensions())
            
            # Collect from /System/Library/Extensions
            drivers.extend(self._collect_system_extensions_dir())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect drivers: {str(e)}")
        
        return drivers
    
    def collect_applications(self) -> List[AssetData]:
        """
        Collect installed applications from various sources.
        
        Returns:
            List of application assets
        """
        applications = []
        
        try:
            # Collect from /Applications
            applications.extend(self._collect_applications_dir())
            
            # Collect from /System/Applications
            applications.extend(self._collect_system_applications())
            
            # Collect from Launchpad
            applications.extend(self._collect_launchpad_applications())
            
            # Collect from Homebrew
            applications.extend(self._collect_homebrew_applications())
            
            # Collect from Mac App Store
            applications.extend(self._collect_mas_applications())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect applications: {str(e)}")
        
        return applications
    
    def collect_services(self) -> List[AssetData]:
        """
        Collect macOS services and daemons.
        
        Returns:
            List of service assets
        """
        services = []
        
        try:
            # Collect launchd services
            services.extend(self._collect_launchd_services())
            
            # Collect running processes
            services.extend(self._collect_running_processes())
            
            # Collect background tasks
            services.extend(self._collect_background_tasks())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect services: {str(e)}")
        
        return services
    
    def collect_libraries(self) -> List[AssetData]:
        """
        Collect system libraries and frameworks.
        
        Returns:
            List of library assets
        """
        libraries = []
        
        try:
            # Collect frameworks from /System/Library/Frameworks
            libraries.extend(self._collect_system_frameworks())
            
            # Collect libraries from /usr/lib
            libraries.extend(self._collect_usr_libraries())
            
            # Collect Python packages
            libraries.extend(self._collect_python_packages())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect libraries: {str(e)}")
        
        return libraries
    
    def collect_packages(self) -> List[AssetData]:
        """
        Collect programming language packages.
        
        Returns:
            List of package assets
        """
        packages = []
        
        try:
            # Python packages
            packages.extend(self._collect_python_packages())
            
            # Node.js packages
            packages.extend(self._collect_npm_packages())
            
            # Ruby gems
            packages.extend(self._collect_ruby_gems())
            
            # Go modules
            packages.extend(self._collect_go_modules())
            
            # Rust crates
            packages.extend(self._collect_rust_crates())
            
            # Homebrew packages
            packages.extend(self._collect_homebrew_packages())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect packages: {str(e)}")
        
        return packages
    
    def collect_containers(self) -> List[AssetData]:
        """
        Collect container images and containers.
        
        Returns:
            List of container assets
        """
        containers = []
        
        try:
            # Docker Desktop
            containers.extend(self._collect_docker_containers())
            
            # Podman
            containers.extend(self._collect_podman_containers())
            
            # Lima (Docker alternative)
            containers.extend(self._collect_lima_containers())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect containers: {str(e)}")
        
        return containers
    
    def _collect_kernel_extensions(self) -> List[AssetData]:
        """Collect kernel extensions using kmutil (modern macOS)."""
        drivers = []
        
        try:
            # Try modern kmutil first
            kmutil_output = self._safe_execute("kmutil", "showloaded", "--list-only")
            if kmutil_output:
                for line in kmutil_output.split('\n'):
                    if line.strip() and not line.startswith('Executing:') and not line.startswith('No variant'):
                        parts = line.split()
                        if len(parts) >= 7:
                            # kmutil format: Index Refs Address Size Name (Version) UUID
                            name = parts[5]
                            version = parts[6]
                            
                            # Clean up version (remove parentheses)
                            if version.startswith('(') and version.endswith(')'):
                                version = version[1:-1]
                            
                            drivers.append(AssetData(
                                name=name,
                                version=version,
                                path=None,
                                description=f"Index: {parts[0]}, Refs: {parts[1]}"
                            ))
            else:
                # Fallback to old kextstat
                kextstat_output = self._safe_execute("kextstat", "-l")
                if kextstat_output:
                    for line in kextstat_output.split('\n')[1:]:  # Skip header
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 7:
                                name = parts[6]
                                version = parts[5] if len(parts) > 5 else None
                                
                                if version and version.startswith('(') and version.endswith(')'):
                                    version = version[1:-1]
                                
                                drivers.append(AssetData(
                                    name=name,
                                    version=version,
                                    path=None,
                                    description=f"Index: {parts[0]}, Refs: {parts[1]}"
                                ))
        except Exception:
            pass
        
        return drivers
    
    def _collect_system_extensions(self) -> List[AssetData]:
        """Collect system extensions using systemextensionsctl."""
        drivers = []
        
        try:
            se_output = self._safe_execute("systemextensionsctl", "list")
            if se_output:
                for line in se_output.split('\n'):
                    if line.strip() and not line.startswith('---'):
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1] if len(parts) > 1 else None
                            
                            # Clean up version if it's in parentheses
                            if version and version.startswith('(') and version.endswith(')'):
                                version = version[1:-1]
                            
                            drivers.append(AssetData(
                                name=name,
                                version=version,
                                path=None,
                                description="System Extension"
                            ))
        except Exception:
            pass
        
        return drivers
    
    def _collect_system_extensions_dir(self) -> List[AssetData]:
        """Collect from /System/Library/Extensions directory."""
        drivers = []
        
        try:
            ext_dir = Path("/System/Library/Extensions")
            if ext_dir.exists():
                for kext_file in ext_dir.rglob("*.kext"):
                    if kext_file.is_dir():
                        # Read Info.plist
                        info_plist = kext_file / "Contents" / "Info.plist"
                        if info_plist.exists():
                            try:
                                with open(info_plist, 'rb') as f:
                                    plist_data = plistlib.load(f)
                                
                                drivers.append(AssetData(
                                    name=plist_data.get('CFBundleName', kext_file.name),
                                    version=plist_data.get('CFBundleVersion'),
                                    path=str(kext_file),
                                    description=plist_data.get('CFBundleDescription'),
                                    vendor=plist_data.get('CFBundleIdentifier')
                                ))
                            except Exception:
                                drivers.append(AssetData(
                                    name=kext_file.name,
                                    path=str(kext_file)
                                ))
        except Exception:
            pass
        
        return drivers
    
    def _collect_applications_dir(self) -> List[AssetData]:
        """Collect applications from /Applications directory."""
        applications = []
        
        try:
            apps_dir = Path("/Applications")
            if apps_dir.exists():
                for app in apps_dir.iterdir():
                    if app.suffix == '.app' and app.is_dir():
                        # Read Info.plist
                        info_plist = app / "Contents" / "Info.plist"
                        if info_plist.exists():
                            try:
                                with open(info_plist, 'rb') as f:
                                    plist_data = plistlib.load(f)
                                
                                # Try multiple version fields
                                version = (plist_data.get('CFBundleShortVersionString') or 
                                         plist_data.get('CFBundleVersion') or 
                                         plist_data.get('CFBundleGetInfoString'))
                                
                                applications.append(AssetData(
                                    name=plist_data.get('CFBundleName', app.stem),
                                    version=version,
                                    path=str(app),
                                    description=plist_data.get('CFBundleDescription'),
                                    vendor=plist_data.get('CFBundleIdentifier')
                                ))
                            except Exception:
                                # Try to get version from app bundle directly
                                version = self._get_app_version_from_bundle(str(app))
                                applications.append(AssetData(
                                    name=app.stem,
                                    version=version or "Unknown",
                                    path=str(app)
                                ))
        except Exception:
            pass
        
        return applications
    
    def _collect_system_applications(self) -> List[AssetData]:
        """Collect system applications from /System/Applications."""
        applications = []
        
        try:
            sys_apps_dir = Path("/System/Applications")
            if sys_apps_dir.exists():
                for app in sys_apps_dir.iterdir():
                    if app.suffix == '.app' and app.is_dir():
                        info_plist = app / "Contents" / "Info.plist"
                        if info_plist.exists():
                            try:
                                with open(info_plist, 'rb') as f:
                                    plist_data = plistlib.load(f)
                                
                                # Try multiple version fields
                                version = (plist_data.get('CFBundleShortVersionString') or 
                                         plist_data.get('CFBundleVersion') or 
                                         plist_data.get('CFBundleGetInfoString'))
                                
                                applications.append(AssetData(
                                    name=plist_data.get('CFBundleName', app.stem),
                                    version=version,
                                    path=str(app),
                                    description=plist_data.get('CFBundleDescription'),
                                    vendor="Apple"
                                ))
                            except Exception:
                                # Try to get version from app bundle directly
                                version = self._get_app_version_from_bundle(str(app))
                                applications.append(AssetData(
                                    name=app.stem,
                                    version=version or "Unknown",
                                    path=str(app),
                                    vendor="Apple"
                                ))
        except Exception:
            pass
        
        return applications
    
    def _collect_launchpad_applications(self) -> List[AssetData]:
        """Collect applications from Launchpad database."""
        applications = []
        
        try:
            # Launchpad database location
            db_path = Path.home() / "Library" / "Application Support" / "Dock" / "launchpad.db"
            if db_path.exists():
                # Use sqlite3 to query the database
                sql_cmd = "SELECT item_id, title FROM apps WHERE title IS NOT NULL"
                output = self._safe_execute("sqlite3", str(db_path), sql_cmd)
                if output:
                    for line in output.split('\n'):
                        if line.strip():
                            parts = line.split('|')
                            if len(parts) >= 2:
                                applications.append(AssetData(
                                    name=parts[1],
                                    description=f"Launchpad ID: {parts[0]}"
                                ))
        except Exception:
            pass
        
        return applications
    
    def _collect_homebrew_applications(self) -> List[AssetData]:
        """Collect Homebrew applications."""
        applications = []
        
        try:
            brew_output = self._safe_execute("brew", "list", "--formula")
            if brew_output:
                for line in brew_output.split('\n'):
                    if line.strip():
                        name = line.strip()
                        # Use the same version detection method as packages
                        version = self._get_homebrew_package_version(name)
                        
                        # Get description
                        info_output = self._safe_execute("brew", "info", name)
                        description = None
                        if info_output:
                            lines = info_output.split('\n')
                            for info_line in lines:
                                if info_line.strip() and not info_line.startswith('==>') and not info_line.startswith(f"{name}:"):
                                    description = info_line.strip()
                                    break
                        
                        applications.append(AssetData(
                            name=name,
                            version=version,
                            description=description,
                            vendor="Homebrew"
                        ))
        except Exception:
            pass
        
        return applications
    
    def _collect_mas_applications(self) -> List[AssetData]:
        """Collect Mac App Store applications."""
        applications = []
        
        try:
            mas_output = self._safe_execute("mas", "list")
            if mas_output:
                for line in mas_output.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            app_id = parts[0]
                            app_name = ' '.join(parts[1:])
                            applications.append(AssetData(
                                name=app_name,
                                description=f"App Store ID: {app_id}",
                                vendor="Mac App Store"
                            ))
        except Exception:
            pass
        
        return applications
    
    def _collect_launchd_services(self) -> List[AssetData]:
        """Collect launchd services."""
        services = []
        
        try:
            # User services
            user_services_dir = Path.home() / "Library" / "LaunchAgents"
            if user_services_dir.exists():
                for plist_file in user_services_dir.glob("*.plist"):
                    try:
                        with open(plist_file, 'rb') as f:
                            plist_data = plistlib.load(f)
                        
                        # Try to get version information
                        version = (plist_data.get('CFBundleShortVersionString') or 
                                 plist_data.get('CFBundleVersion') or 
                                 plist_data.get('Version'))
                        
                        services.append(AssetData(
                            name=plist_file.stem,
                            version=version,
                            path=str(plist_file),
                            description=plist_data.get('Label'),
                            vendor="User LaunchAgent"
                        ))
                    except Exception:
                        # Try to get version from plist file directly
                        version = self._get_plist_version(str(plist_file))
                        services.append(AssetData(
                            name=plist_file.stem,
                            version=version,
                            path=str(plist_file),
                            vendor="User LaunchAgent"
                        ))
            
            # System services
            system_services_dir = Path("/Library/LaunchDaemons")
            if system_services_dir.exists():
                for plist_file in system_services_dir.glob("*.plist"):
                    try:
                        with open(plist_file, 'rb') as f:
                            plist_data = plistlib.load(f)
                        
                        # Try to get version information
                        version = (plist_data.get('CFBundleShortVersionString') or 
                                 plist_data.get('CFBundleVersion') or 
                                 plist_data.get('Version'))
                        
                        services.append(AssetData(
                            name=plist_file.stem,
                            version=version,
                            path=str(plist_file),
                            description=plist_data.get('Label'),
                            vendor="System LaunchDaemon"
                        ))
                    except Exception:
                        # Try to get version from plist file directly
                        version = self._get_plist_version(str(plist_file))
                        services.append(AssetData(
                            name=plist_file.stem,
                            version=version,
                            path=str(plist_file),
                            vendor="System LaunchDaemon"
                        ))
        except Exception:
            pass
        
        return services
    
    def _collect_running_processes(self) -> List[AssetData]:
        """Collect running processes."""
        services = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                try:
                    proc_info = proc.info
                    # Try to get version information from executable
                    version = self._get_process_version(proc_info.get('exe', ''))
                    
                    services.append(AssetData(
                        name=proc_info['name'],
                        version=version,
                        path=proc_info.get('exe', ''),
                        install_date=datetime.fromtimestamp(proc_info['create_time'])
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        
        return services
    
    def _collect_background_tasks(self) -> List[AssetData]:
        """Collect background tasks."""
        services = []
        
        try:
            # Background tasks directory
            bg_tasks_dir = Path.home() / "Library" / "Application Support" / "com.apple.backgroundtaskmanagementagent"
            if bg_tasks_dir.exists():
                for task_file in bg_tasks_dir.glob("*.plist"):
                    try:
                        with open(task_file, 'rb') as f:
                            plist_data = plistlib.load(f)
                        
                        services.append(AssetData(
                            name=task_file.stem,
                            path=str(task_file),
                            description="Background Task",
                            vendor="macOS"
                        ))
                    except Exception:
                        services.append(AssetData(
                            name=task_file.stem,
                            path=str(task_file),
                            vendor="macOS"
                        ))
        except Exception:
            pass
        
        return services
    
    def _collect_system_frameworks(self) -> List[AssetData]:
        """Collect system frameworks."""
        libraries = []
        
        try:
            frameworks_dir = Path("/System/Library/Frameworks")
            if frameworks_dir.exists():
                for framework in frameworks_dir.iterdir():
                    if framework.suffix == '.framework' and framework.is_dir():
                        info_plist = framework / "Resources" / "Info.plist"
                        if info_plist.exists():
                            try:
                                with open(info_plist, 'rb') as f:
                                    plist_data = plistlib.load(f)
                                
                                libraries.append(AssetData(
                                    name=plist_data.get('CFBundleName', framework.stem),
                                    version=plist_data.get('CFBundleShortVersionString'),
                                    path=str(framework),
                                    description=plist_data.get('CFBundleDescription'),
                                    vendor="Apple"
                                ))
                            except Exception:
                                libraries.append(AssetData(
                                    name=framework.stem,
                                    path=str(framework),
                                    vendor="Apple"
                                ))
        except Exception:
            pass
        
        return libraries
    
    def _collect_usr_libraries(self) -> List[AssetData]:
        """Collect libraries from /usr/lib."""
        libraries = []
        
        try:
            usr_lib_dir = Path("/usr/lib")
            if usr_lib_dir.exists():
                for lib_file in usr_lib_dir.rglob("*.dylib"):
                    if lib_file.is_file():
                        libraries.append(AssetData(
                            name=lib_file.name,
                            path=str(lib_file),
                            size=lib_file.stat().st_size,
                            install_date=datetime.fromtimestamp(lib_file.stat().st_mtime)
                        ))
        except Exception:
            pass
        
        return libraries
    
    def _collect_python_packages(self) -> List[AssetData]:
        """Collect Python packages."""
        packages = []
        
        try:
            pip_output = self._safe_execute("pip", "list", "--format=json")
            if pip_output:
                pip_packages = json.loads(pip_output)
                for pkg in pip_packages:
                    packages.append(AssetData(
                        name=pkg['name'],
                        version=pkg['version'],
                        description=pkg.get('description') or None,
                        vendor="Python"
                    ))
        except Exception:
            pass
        
        return packages
    
    def _collect_npm_packages(self) -> List[AssetData]:
        """Collect NPM packages."""
        packages = []
        
        try:
            npm_output = self._safe_execute("npm", "list", "-g", "--json")
            if npm_output:
                npm_data = json.loads(npm_output)
                if 'dependencies' in npm_data:
                    for name, info in npm_data['dependencies'].items():
                        packages.append(AssetData(
                            name=name,
                            version=info.get('version') or None,
                            description=info.get('description') or None,
                            vendor="NPM"
                        ))
        except Exception:
            pass
        
        return packages
    
    def _collect_ruby_gems(self) -> List[AssetData]:
        """Collect Ruby gems."""
        packages = []
        
        try:
            gem_output = self._safe_execute("gem", "list")
            if gem_output:
                for line in gem_output.split('\n'):
                    if '(' in line and ')' in line:
                        name = line.split('(')[0].strip()
                        version = line.split('(')[1].split(')')[0].strip()
                        packages.append(AssetData(
                            name=name,
                            version=version,
                            vendor="Ruby"
                        ))
        except Exception:
            pass
        
        return packages
    
    def _collect_go_modules(self) -> List[AssetData]:
        """Collect Go modules."""
        packages = []
        
        try:
            go_output = self._safe_execute("go", "list", "-m", "all")
            if go_output:
                for line in go_output.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append(AssetData(
                                name=parts[0],
                                version=parts[1]
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_rust_crates(self) -> List[AssetData]:
        """Collect Rust crates."""
        packages = []
        
        try:
            cargo_output = self._safe_execute("cargo", "list")
            if cargo_output:
                for line in cargo_output.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append(AssetData(
                                name=parts[0],
                                version=parts[1]
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_homebrew_packages(self) -> List[AssetData]:
        """Collect Homebrew packages with version information."""
        packages = []
        
        try:
            # Get installed packages with versions
            brew_output = self._safe_execute("brew", "list", "--formula", "--versions")
            if brew_output:
                for line in brew_output.split('\n'):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            packages.append(AssetData(
                                name=name,
                                version=version,
                                vendor="Homebrew"
                            ))
                        else:
                            # Try to get version info individually
                            name = parts[0]
                            version = self._get_homebrew_package_version(name)
                            
                            packages.append(AssetData(
                                name=name,
                                version=version,
                                vendor="Homebrew"
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_docker_containers(self) -> List[AssetData]:
        """Collect Docker containers and images."""
        containers = []
        
        try:
            # Docker images - extract version from image name
            docker_images = self._safe_execute("docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.Size}}")
            if docker_images:
                for line in docker_images.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            image_name = parts[0]
                            size = parts[1]
                            
                            # Extract version from image name (e.g., redis:7-alpine -> redis, 7-alpine)
                            if ':' in image_name:
                                name, version = image_name.split(':', 1)
                            else:
                                name = image_name
                                version = "latest"
                            
                            containers.append(AssetData(
                                name=name,
                                version=version,
                                description=f"Size: {size}",
                                vendor="Docker Image"
                            ))
            
            # Docker containers - separate from images
            docker_containers = self._safe_execute("docker", "ps", "-a", "--format", "{{.Names}} {{.Image}} {{.Status}}")
            if docker_containers:
                for line in docker_containers.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            container_name = parts[0]
                            image_name = parts[1]
                            status = parts[2]
                            
                            # Extract version from image name
                            if ':' in image_name:
                                image_base, image_version = image_name.split(':', 1)
                            else:
                                image_base = image_name
                                image_version = "latest"
                            
                            containers.append(AssetData(
                                name=container_name,
                                version=image_version,
                                description=f"Status: {status}, Image: {image_base}",
                                vendor="Docker Container"
                            ))
        except Exception:
            pass
        
        return containers
    
    def _collect_podman_containers(self) -> List[AssetData]:
        """Collect Podman containers and images."""
        containers = []
        
        try:
            podman_images = self._safe_execute("podman", "images", "--format", "{{.Repository}}:{{.Tag}} {{.Size}}")
            if podman_images:
                for line in podman_images.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            containers.append(AssetData(
                                name=parts[0],
                                description=f"Size: {parts[1]}",
                                vendor="Podman"
                            ))
        except Exception:
            pass
        
        return containers
    
    def _collect_lima_containers(self) -> List[AssetData]:
        """Collect Lima containers."""
        containers = []
        
        try:
            lima_output = self._safe_execute("limactl", "list")
            if lima_output:
                for line in lima_output.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            containers.append(AssetData(
                                name=parts[0],
                                description=parts[1],
                                vendor="Lima"
                            ))
        except Exception:
            pass
        
        return containers
    
    def collect_hardware(self) -> List[AssetData]:
        """
        Collect hardware information.
        
        Returns:
            List of hardware assets
        """
        hardware = []
        
        try:
            # System Information
            hardware.extend(self._collect_system_info())
            
            # CPU Information
            hardware.extend(self._collect_cpu_info())
            
            # Memory Information
            hardware.extend(self._collect_memory_info())
            
            # Disk Information
            hardware.extend(self._collect_disk_info())
            
            # Network Information
            hardware.extend(self._collect_network_info())
            
            # Graphics Information
            hardware.extend(self._collect_graphics_info())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect hardware: {str(e)}")
        
        return hardware
    
    def _collect_system_info(self) -> List[AssetData]:
        """Collect system information."""
        hardware = []
        
        try:
            # System model and serial
            model = self._safe_execute("sysctl", "-n", "hw.model")
            serial = self._safe_execute("system_profiler", "SPHardwareDataType", "-json")
            
            if model:
                # Get more detailed model information
                model_version = self._safe_execute("system_profiler", "SPHardwareDataType", "-json")
                version_info = None
                if model_version:
                    try:
                        import json
                        data = json.loads(model_version)
                        if 'SPHardwareDataType' in data and len(data['SPHardwareDataType']) > 0:
                            info = data['SPHardwareDataType'][0]
                            version_info = info.get('os_version', 'Unknown')
                    except:
                        pass
                
                hardware.append(AssetData(
                    name=f"Mac Model: {model}",
                    version=version_info,
                    vendor="Apple"
                ))
            
            if serial:
                try:
                    import json
                    data = json.loads(serial)
                    if 'SPHardwareDataType' in data and len(data['SPHardwareDataType']) > 0:
                        info = data['SPHardwareDataType'][0]
                        hardware.append(AssetData(
                            name=f"Serial: {info.get('serial_number', 'Unknown')}",
                            version=info.get('os_version', 'Unknown'),
                            description=f"Model: {info.get('machine_model', 'Unknown')}, Boot ROM: {info.get('boot_rom_version', 'Unknown')}",
                            vendor="Apple"
                        ))
                except:
                    pass
                    
        except Exception:
            pass
        
        return hardware
    
    def _collect_cpu_info(self) -> List[AssetData]:
        """Collect CPU information."""
        hardware = []
        
        try:
            # CPU brand string
            brand = self._safe_execute("sysctl", "-n", "machdep.cpu.brand_string")
            cores = self._safe_execute("sysctl", "-n", "hw.ncpu")
            cores_per_package = self._safe_execute("sysctl", "-n", "hw.packages")
            
            # Get CPU version information (Apple Silicon specific)
            cpu_type = self._safe_execute("sysctl", "-n", "hw.cputype")
            cpu_subtype = self._safe_execute("sysctl", "-n", "hw.cpusubtype")
            cpu_arm64 = self._safe_execute("sysctl", "-n", "hw.optional.arm64")
            cpu_64bit = self._safe_execute("sysctl", "-n", "hw.cpu64bit_capable")
            logical_cpu = self._safe_execute("sysctl", "-n", "hw.logicalcpu")
            physical_cpu = self._safe_execute("sysctl", "-n", "hw.physicalcpu")
            
            if brand:
                # Create version string from available info
                version_parts = []
                if cpu_type:
                    version_parts.append(f"Type: {cpu_type}")
                if cpu_subtype:
                    version_parts.append(f"Subtype: {cpu_subtype}")
                if cpu_arm64:
                    version_parts.append(f"ARM64: {cpu_arm64}")
                if cpu_64bit:
                    version_parts.append(f"64-bit: {cpu_64bit}")
                if logical_cpu:
                    version_parts.append(f"Logical CPUs: {logical_cpu}")
                if physical_cpu:
                    version_parts.append(f"Physical CPUs: {physical_cpu}")
                
                version_string = ", ".join(version_parts) if version_parts else None
                
                hardware.append(AssetData(
                    name=f"CPU: {brand}",
                    version=version_string,
                    description=f"Cores: {cores}, Packages: {cores_per_package}",
                    vendor="Intel" if "Intel" in brand else "Apple" if "Apple" in brand else "Unknown"
                ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_memory_info(self) -> List[AssetData]:
        """Collect memory information."""
        hardware = []
        
        try:
            # Total memory
            total_memory = self._safe_execute("sysctl", "-n", "hw.memsize")
            if total_memory:
                memory_gb = int(total_memory) // (1024**3)
                
                # Get memory type and speed information
                memory_info = self._safe_execute("system_profiler", "SPMemoryDataType", "-json")
                memory_version = None
                if memory_info:
                    try:
                        import json
                        data = json.loads(memory_info)
                        if 'SPMemoryDataType' in data and len(data['SPMemoryDataType']) > 0:
                            mem_data = data['SPMemoryDataType'][0]
                            if 'SPMemoryDataType' in mem_data:
                                memory_modules = mem_data['SPMemoryDataType']
                                if memory_modules:
                                    # Get info from first memory module
                                    first_module = memory_modules[0]
                                    version_parts = []
                                    if first_module.get('dimm_type'):
                                        version_parts.append(f"Type: {first_module['dimm_type']}")
                                    if first_module.get('dimm_speed'):
                                        version_parts.append(f"Speed: {first_module['dimm_speed']}")
                                    if first_module.get('dimm_size'):
                                        version_parts.append(f"Module Size: {first_module['dimm_size']}")
                                    memory_version = ", ".join(version_parts) if version_parts else None
                    except:
                        pass
                
                hardware.append(AssetData(
                    name=f"RAM: {memory_gb}GB",
                    version=memory_version,
                    size=int(total_memory),
                    vendor="Apple"
                ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_disk_info(self) -> List[AssetData]:
        """Collect disk information."""
        hardware = []
        
        try:
            # Disk information
            disk_info = self._safe_execute("system_profiler", "SPStorageDataType", "-json")
            if disk_info:
                import json
                data = json.loads(disk_info)
                if 'SPStorageDataType' in data:
                    for disk in data['SPStorageDataType']:
                        if 'mount_point' in disk:
                            # Get disk version information
                            version_parts = []
                            if disk.get('spserial_ata', {}).get('_name'):
                                version_parts.append(f"Interface: {disk['spserial_ata']['_name']}")
                            if disk.get('spserial_ata', {}).get('_name'):
                                version_parts.append(f"Protocol: {disk['spserial_ata'].get('spsata_protocol', 'Unknown')}")
                            if disk.get('spserial_ata', {}).get('spsata_physical_interconnect'):
                                version_parts.append(f"Physical: {disk['spserial_ata']['spsata_physical_interconnect']}")
                            
                            version_string = ", ".join(version_parts) if version_parts else None
                            
                            hardware.append(AssetData(
                                name=f"Disk: {disk.get('_name', 'Unknown')}",
                                version=version_string,
                                description=f"Mount: {disk.get('mount_point', 'Unknown')}, Size: {disk.get('size_in_bytes', 0) // (1024**3)}GB",
                                vendor=disk.get('spserial_ata', {}).get('_name', 'Unknown'),
                                size=disk.get('size_in_bytes', 0)
                            ))
                            
        except Exception:
            pass
        
        return hardware
    
    def _collect_network_info(self) -> List[AssetData]:
        """Collect network information."""
        hardware = []
        
        try:
            # Network interfaces with detailed information
            network_info = self._safe_execute("system_profiler", "SPNetworkDataType", "-json")
            if network_info:
                import json
                data = json.loads(network_info)
                if 'SPNetworkDataType' in data:
                    for interface in data['SPNetworkDataType']:
                        interface_name = interface.get('_name', 'Unknown')
                        if interface_name != "lo0":  # Skip loopback
                            # Get interface version information
                            version_parts = []
                            if interface.get('spnetwork_hardware'):
                                version_parts.append(f"Hardware: {interface['spnetwork_hardware']}")
                            if interface.get('spnetwork_type'):
                                version_parts.append(f"Type: {interface['spnetwork_type']}")
                            if interface.get('spnetwork_interface'):
                                version_parts.append(f"Interface: {interface['spnetwork_interface']}")
                            
                            version_string = ", ".join(version_parts) if version_parts else None
                            
                            hardware.append(AssetData(
                                name=f"Network: {interface_name}",
                                version=version_string,
                                vendor="Apple"
                            ))
            else:
                # Fallback to basic interface listing
                interfaces = self._safe_execute("ifconfig", "-l")
                if interfaces:
                    for interface in interfaces.split():
                        if interface != "lo0":  # Skip loopback
                            hardware.append(AssetData(
                                name=f"Network: {interface}",
                                vendor="Apple"
                            ))
                        
        except Exception:
            pass
        
        return hardware
    
    def _collect_graphics_info(self) -> List[AssetData]:
        """Collect graphics information."""
        hardware = []
        
        try:
            # Graphics information
            gpu_info = self._safe_execute("system_profiler", "SPDisplaysDataType", "-json")
            if gpu_info:
                import json
                data = json.loads(gpu_info)
                if 'SPDisplaysDataType' in data:
                    for display in data['SPDisplaysDataType']:
                        # Get GPU version information
                        version_parts = []
                        if display.get('sppci_model'):
                            version_parts.append(f"PCI Model: {display['sppci_model']}")
                        if display.get('spdisplays_vram'):
                            version_parts.append(f"VRAM: {display['spdisplays_vram']}")
                        if display.get('spdisplays_resolution'):
                            version_parts.append(f"Resolution: {display['spdisplays_resolution']}")
                        if display.get('spdisplays_main_display'):
                            version_parts.append(f"Main Display: {display['spdisplays_main_display']}")
                        
                        version_string = ", ".join(version_parts) if version_parts else None
                        
                        hardware.append(AssetData(
                            name=f"GPU: {display.get('_name', 'Unknown')}",
                            version=version_string,
                            description=f"Resolution: {display.get('spdisplays_resolution', 'Unknown')}, VRAM: {display.get('spdisplays_vram', 'Unknown')}",
                            vendor=display.get('sppci_model', 'Unknown')
                        ))
                        
        except Exception:
            pass
        
        return hardware
    
    def _get_app_version_from_bundle(self, app_path: str) -> Optional[str]:
        """Get version information from app bundle using various methods."""
        try:
            # Method 1: Try mdls command
            mdls_output = self._safe_execute("mdls", "-name", "kMDItemVersion", app_path)
            if mdls_output and mdls_output != "(null)":
                return mdls_output.strip('"')
            
            # Method 2: Try plutil command
            info_plist = Path(app_path) / "Contents" / "Info.plist"
            if info_plist.exists():
                plutil_output = self._safe_execute("plutil", "-p", str(info_plist))
                if plutil_output:
                    for line in plutil_output.split('\n'):
                        if 'CFBundleShortVersionString' in line or 'CFBundleVersion' in line:
                            # Extract version from plutil output
                            if '=>' in line:
                                version = line.split('=>')[1].strip().strip('"')
                                if version and version != 'null':
                                    return version
            
            # Method 3: Try defaults command
            bundle_id = self._safe_execute("defaults", "read", app_path + "/Contents/Info", "CFBundleIdentifier")
            if bundle_id:
                version = self._safe_execute("defaults", "read", app_path + "/Contents/Info", "CFBundleShortVersionString")
                if version:
                    return version.strip('"')
            
            return None
        except Exception:
            return None
    
    def _get_plist_version(self, plist_path: str) -> Optional[str]:
        """Get version information from plist file using various methods."""
        try:
            # Method 1: Try plutil command
            plutil_output = self._safe_execute("plutil", "-p", plist_path)
            if plutil_output:
                for line in plutil_output.split('\n'):
                    if 'CFBundleShortVersionString' in line or 'CFBundleVersion' in line or 'Version' in line:
                        if '=>' in line:
                            version = line.split('=>')[1].strip().strip('"')
                            if version and version != 'null':
                                return version
            
            # Method 2: Try defaults command
            version = self._safe_execute("defaults", "read", plist_path, "CFBundleShortVersionString")
            if version:
                return version.strip('"')
            
            version = self._safe_execute("defaults", "read", plist_path, "CFBundleVersion")
            if version:
                return version.strip('"')
            
            version = self._safe_execute("defaults", "read", plist_path, "Version")
            if version:
                return version.strip('"')
            
            # Method 3: Try to get version from executable path in plist
            if plutil_output:
                for line in plutil_output.split('\n'):
                    if 'ProgramArguments' in line or 'Program' in line:
                        # Find the executable path
                        next_lines = plutil_output.split('\n')[plutil_output.split('\n').index(line):]
                        for next_line in next_lines:
                            if '=>' in next_line and ('/' in next_line or 'Program' in next_line):
                                exe_path = next_line.split('=>')[1].strip().strip('"')
                                if exe_path and Path(exe_path).exists():
                                    return self._get_process_version(exe_path)
            
            return None
        except Exception:
            return None
    
    def _get_homebrew_package_version(self, package_name: str) -> Optional[str]:
        """Get version information for a specific Homebrew package."""
        try:
            # Method 1: Try brew info --json
            version_info = self._safe_execute("brew", "info", package_name, "--json")
            if version_info:
                try:
                    import json
                    info = json.loads(version_info)
                    if info and len(info) > 0:
                        installed = info[0].get('installed', [])
                        if installed and len(installed) > 0:
                            return installed[0].get('version')
                except:
                    pass
            
            # Method 2: Try brew list --versions
            versions_output = self._safe_execute("brew", "list", "--versions", package_name)
            if versions_output:
                parts = versions_output.split()
                if len(parts) >= 2:
                    return parts[1]
            
            # Method 3: Try brew info (text output)
            info_output = self._safe_execute("brew", "info", package_name)
            if info_output:
                for line in info_output.split('\n'):
                    if line.startswith(f"{package_name}:"):
                        version = line.split(':')[1].strip().split()[0]
                        if version and version != 'Not':
                            return version
            
            return None
        except Exception:
            return None
    
    def _get_process_version(self, exe_path: str) -> Optional[str]:
        """Get version information from executable path."""
        try:
            if not exe_path or not Path(exe_path).exists():
                return None
            
            # Method 1: Try mdls command
            mdls_output = self._safe_execute("mdls", "-name", "kMDItemVersion", exe_path)
            if mdls_output and "(null)" not in mdls_output and mdls_output.strip() != "(null)":
                return mdls_output.strip('"')
            
            # Method 2: Try otool command for Mach-O binaries
            otool_output = self._safe_execute("otool", "-l", exe_path)
            if otool_output:
                for line in otool_output.split('\n'):
                    if 'version' in line.lower() and any(char.isdigit() for char in line):
                        # Extract version from otool output
                        import re
                        version_match = re.search(r'version\s+(\d+\.\d+(?:\.\d+)?)', line)
                        if version_match:
                            return version_match.group(1)
            
            # Method 3: Try strings command
            strings_output = self._safe_execute("strings", exe_path)
            if strings_output:
                for line in strings_output.split('\n'):
                    if 'version' in line.lower() and any(char.isdigit() for char in line):
                        # Extract version from strings output
                        import re
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', line)
                        if version_match:
                            return version_match.group(1)
            
            # Method 4: Try to run executable with --version flag
            version_output = self._safe_execute(exe_path, "--version")
            if version_output:
                import re
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_output)
                if version_match:
                    return version_match.group(1)
            
            # Method 5: Try to run executable with -v flag
            version_output = self._safe_execute(exe_path, "-v")
            if version_output:
                import re
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_output)
                if version_match:
                    return version_match.group(1)
            
            # Method 6: Try to run executable with -V flag
            version_output = self._safe_execute(exe_path, "-V")
            if version_output:
                import re
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_output)
                if version_match:
                    return version_match.group(1)
            
            # Method 7: Try to run executable with version flag
            version_output = self._safe_execute(exe_path, "version")
            if version_output:
                import re
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_output)
                if version_match:
                    return version_match.group(1)
            
            return None
        except Exception:
            return None
