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
                                
                                applications.append(AssetData(
                                    name=plist_data.get('CFBundleName', app.stem),
                                    version=plist_data.get('CFBundleShortVersionString'),
                                    path=str(app),
                                    description=plist_data.get('CFBundleDescription'),
                                    vendor=plist_data.get('CFBundleIdentifier')
                                ))
                            except Exception:
                                applications.append(AssetData(
                                    name=app.stem,
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
                                
                                applications.append(AssetData(
                                    name=plist_data.get('CFBundleName', app.stem),
                                    version=plist_data.get('CFBundleShortVersionString'),
                                    path=str(app),
                                    description=plist_data.get('CFBundleDescription'),
                                    vendor="Apple"
                                ))
                            except Exception:
                                applications.append(AssetData(
                                    name=app.stem,
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
                        # Get more info about each package
                        info_output = self._safe_execute("brew", "info", line.strip())
                        if info_output:
                            lines = info_output.split('\n')
                            name = line.strip()
                            version = None
                            description = None
                            
                            for info_line in lines:
                                if info_line.startswith(f"{name}:"):
                                    version = info_line.split(':')[1].strip().split()[0]
                                elif info_line.strip() and not info_line.startswith('==>'):
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
                        
                        services.append(AssetData(
                            name=plist_file.stem,
                            path=str(plist_file),
                            description=plist_data.get('Label'),
                            vendor="User LaunchAgent"
                        ))
                    except Exception:
                        services.append(AssetData(
                            name=plist_file.stem,
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
                        
                        services.append(AssetData(
                            name=plist_file.stem,
                            path=str(plist_file),
                            description=plist_data.get('Label'),
                            vendor="System LaunchDaemon"
                        ))
                    except Exception:
                        services.append(AssetData(
                            name=plist_file.stem,
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
                    services.append(AssetData(
                        name=proc_info['name'],
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
                            # Fallback for packages without version info
                            packages.append(AssetData(
                                name=parts[0],
                                version=None,
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
