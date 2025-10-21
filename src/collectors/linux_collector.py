"""
Linux-specific asset collector for CyberCortexAssetBot.

This module implements Linux-specific asset collection using various
system commands and Python libraries like psutil.
"""

import os
import re
import subprocess
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


class LinuxCollector(BaseCollector):
    """Linux-specific asset collector implementation."""
    
    def __init__(self, platform_info: Optional[PlatformInfo] = None) -> None:
        """Initialize Linux collector."""
        super().__init__(platform_info)
    
    def _validate_platform_support(self) -> None:
        """Validate that collector supports current platform."""
        if self.platform_info.platform_type != PlatformType.LINUX:
            raise CollectorNotSupportedError(
                f"LinuxCollector only supports Linux, got {self.platform_info.platform_type.value}"
            )
    
    def collect_drivers(self) -> List[AssetData]:
        """
        Collect Linux kernel modules and drivers.
        
        Returns:
            List of driver assets
        """
        drivers = []
        
        try:
            # Get loaded kernel modules
            modules_output = self._safe_execute("lsmod")
            if modules_output:
                for line in modules_output.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[0]
                            size = int(parts[1]) if parts[1].isdigit() else None
                            
                            # Get module information
                            modinfo = self._get_module_info(name)
                            
                            drivers.append(AssetData(
                                name=name,
                                version=modinfo.get('version'),
                                path=modinfo.get('filename'),
                                size=size,
                                description=modinfo.get('description'),
                                vendor=modinfo.get('author')
                            ))
            
            # Get available modules from /lib/modules
            modules_dir = Path("/lib/modules")
            if modules_dir.exists():
                for kernel_version in modules_dir.iterdir():
                    if kernel_version.is_dir():
                        modules_path = kernel_version / "modules.dep"
                        if modules_path.exists():
                            with open(modules_path, 'r') as f:
                                for line in f:
                                    if line.strip():
                                        module_path = line.split(':')[0]
                                        module_name = Path(module_path).stem
                                        
                                        # Check if not already collected
                                        if not any(d.name == module_name for d in drivers):
                                            drivers.append(AssetData(
                                                name=module_name,
                                                path=f"/lib/modules/{kernel_version.name}/{module_path}"
                                            ))
        
        except Exception as e:
            raise DataCollectionError(f"Failed to collect drivers: {str(e)}")
        
        return drivers
    
    def collect_applications(self) -> List[AssetData]:
        """
        Collect installed applications using package managers.
        
        Returns:
            List of application assets
        """
        applications = []
        
        try:
            # Collect from different package managers
            applications.extend(self._collect_apt_packages())
            applications.extend(self._collect_yum_packages())
            applications.extend(self._collect_dnf_packages())
            applications.extend(self._collect_pacman_packages())
            applications.extend(self._collect_flatpak_packages())
            applications.extend(self._collect_snap_packages())
            
            # Collect from /usr/bin, /usr/local/bin
            applications.extend(self._collect_binary_applications())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect applications: {str(e)}")
        
        return applications
    
    def collect_services(self) -> List[AssetData]:
        """
        Collect system services and daemons.
        
        Returns:
            List of service assets
        """
        services = []
        
        try:
            # Collect systemd services
            services.extend(self._collect_systemd_services())
            
            # Collect init.d services
            services.extend(self._collect_initd_services())
            
            # Collect running processes
            services.extend(self._collect_running_processes())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect services: {str(e)}")
        
        return services
    
    def collect_libraries(self) -> List[AssetData]:
        """
        Collect system libraries.
        
        Returns:
            List of library assets
        """
        libraries = []
        
        try:
            # Collect shared libraries from /lib, /usr/lib, /usr/local/lib
            lib_dirs = ["/lib", "/usr/lib", "/usr/local/lib", "/lib64", "/usr/lib64"]
            
            for lib_dir in lib_dirs:
                lib_path = Path(lib_dir)
                if lib_path.exists():
                    for so_file in lib_path.rglob("*.so*"):
                        if so_file.is_file():
                            libraries.append(AssetData(
                                name=so_file.name,
                                path=str(so_file),
                                size=so_file.stat().st_size,
                                install_date=datetime.fromtimestamp(so_file.stat().st_mtime)
                            ))
            
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
            # Docker containers and images
            containers.extend(self._collect_docker_containers())
            
            # Podman containers and images
            containers.extend(self._collect_podman_containers())
            
            # LXC containers
            containers.extend(self._collect_lxc_containers())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect containers: {str(e)}")
        
        return containers
    
    def _get_module_info(self, module_name: str) -> Dict[str, str]:
        """Get detailed information about a kernel module."""
        info = {}
        
        try:
            modinfo_output = self._safe_execute("modinfo", module_name)
            if modinfo_output:
                for line in modinfo_output.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        info[key.strip().lower()] = value.strip()
        except Exception:
            pass
        
        return info
    
    def _collect_apt_packages(self) -> List[AssetData]:
        """Collect packages from APT (Debian/Ubuntu)."""
        packages = []
        
        try:
            dpkg_output = self._safe_execute("dpkg", "-l")
            if dpkg_output:
                for line in dpkg_output.split('\n')[5:]:  # Skip headers
                    if line.startswith('ii'):  # Installed packages
                        parts = line.split()
                        if len(parts) >= 3:
                            packages.append(AssetData(
                                name=parts[1],
                                version=parts[2],
                                description=' '.join(parts[4:]) if len(parts) > 4 else None
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_yum_packages(self) -> List[AssetData]:
        """Collect packages from YUM (RHEL/CentOS)."""
        packages = []
        
        try:
            yum_output = self._safe_execute("yum", "list", "installed")
            if yum_output:
                for line in yum_output.split('\n'):
                    if not line.startswith('Loaded') and not line.startswith('Installed'):
                        parts = line.split()
                        if len(parts) >= 3:
                            packages.append(AssetData(
                                name=parts[0],
                                version=parts[1],
                                architecture=parts[2] if len(parts) > 2 else None
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_dnf_packages(self) -> List[AssetData]:
        """Collect packages from DNF (Fedora)."""
        packages = []
        
        try:
            dnf_output = self._safe_execute("dnf", "list", "installed")
            if dnf_output:
                for line in dnf_output.split('\n'):
                    if not line.startswith('Last') and not line.startswith('Installed'):
                        parts = line.split()
                        if len(parts) >= 3:
                            packages.append(AssetData(
                                name=parts[0],
                                version=parts[1],
                                architecture=parts[2] if len(parts) > 2 else None
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_pacman_packages(self) -> List[AssetData]:
        """Collect packages from Pacman (Arch Linux)."""
        packages = []
        
        try:
            pacman_output = self._safe_execute("pacman", "-Q")
            if pacman_output:
                for line in pacman_output.split('\n'):
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
    
    def _collect_flatpak_packages(self) -> List[AssetData]:
        """Collect Flatpak packages."""
        packages = []
        
        try:
            flatpak_output = self._safe_execute("flatpak", "list")
            if flatpak_output:
                for line in flatpak_output.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            packages.append(AssetData(
                                name=parts[0],
                                version=parts[1],
                                description=parts[2] if len(parts) > 2 else None
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_snap_packages(self) -> List[AssetData]:
        """Collect Snap packages."""
        packages = []
        
        try:
            snap_output = self._safe_execute("snap", "list")
            if snap_output:
                for line in snap_output.split('\n')[1:]:  # Skip header
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
    
    def _collect_binary_applications(self) -> List[AssetData]:
        """Collect applications from binary directories."""
        applications = []
        
        bin_dirs = ["/usr/bin", "/usr/local/bin", "/opt"]
        
        for bin_dir in bin_dirs:
            bin_path = Path(bin_dir)
            if bin_path.exists():
                for binary in bin_path.iterdir():
                    if binary.is_file() and binary.stat().st_mode & 0o111:  # Executable
                        applications.append(AssetData(
                            name=binary.name,
                            path=str(binary),
                            size=binary.stat().st_size,
                            install_date=datetime.fromtimestamp(binary.stat().st_mtime)
                        ))
        
        return applications
    
    def _collect_systemd_services(self) -> List[AssetData]:
        """Collect systemd services."""
        services = []
        
        try:
            systemctl_output = self._safe_execute("systemctl", "list-units", "--type=service", "--all")
            if systemctl_output:
                for line in systemctl_output.split('\n')[1:]:  # Skip header
                    if '.service' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            service_name = parts[0]
                            load_state = parts[1]
                            active_state = parts[2]
                            
                            services.append(AssetData(
                                name=service_name,
                                description=f"Load: {load_state}, Active: {active_state}"
                            ))
        except Exception:
            pass
        
        return services
    
    def _collect_initd_services(self) -> List[AssetData]:
        """Collect init.d services."""
        services = []
        
        initd_path = Path("/etc/init.d")
        if initd_path.exists():
            for service_file in initd_path.iterdir():
                if service_file.is_file() and service_file.stat().st_mode & 0o111:
                    services.append(AssetData(
                        name=service_file.name,
                        path=str(service_file)
                    ))
        
        return services
    
    def _collect_running_processes(self) -> List[AssetData]:
        """Collect running processes as services."""
        services = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    services.append(AssetData(
                        name=proc_info['name'],
                        description=f"PID: {proc_info['pid']}, CMD: {' '.join(proc_info['cmdline'])}",
                        install_date=datetime.fromtimestamp(proc_info['create_time'])
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        
        return services
    
    def _collect_python_packages(self) -> List[AssetData]:
        """Collect Python packages."""
        packages = []
        
        try:
            # Global packages
            pip_output = self._safe_execute("pip", "list", "--format=json")
            if pip_output:
                pip_packages = json.loads(pip_output)
                for pkg in pip_packages:
                    packages.append(AssetData(
                        name=pkg['name'],
                        version=pkg['version'],
                        description=pkg.get('description', '')
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
                            version=info.get('version', ''),
                            description=info.get('description', '')
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
                            version=version
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
    
    def _collect_docker_containers(self) -> List[AssetData]:
        """Collect Docker containers and images."""
        containers = []
        
        try:
            # Docker images
            docker_images = self._safe_execute("docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.Size}}")
            if docker_images:
                for line in docker_images.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            containers.append(AssetData(
                                name=parts[0],
                                description=f"Size: {parts[1]}",
                                vendor="Docker"
                            ))
            
            # Docker containers
            docker_containers = self._safe_execute("docker", "ps", "-a", "--format", "{{.Names}} {{.Image}} {{.Status}}")
            if docker_containers:
                for line in docker_containers.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            containers.append(AssetData(
                                name=parts[0],
                                version=parts[1],
                                description=parts[2],
                                vendor="Docker"
                            ))
        except Exception:
            pass
        
        return containers
    
    def _collect_podman_containers(self) -> List[AssetData]:
        """Collect Podman containers and images."""
        containers = []
        
        try:
            # Podman images
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
    
    def _collect_lxc_containers(self) -> List[AssetData]:
        """Collect LXC containers."""
        containers = []
        
        try:
            lxc_output = self._safe_execute("lxc", "list", "--format", "csv")
            if lxc_output:
                for line in lxc_output.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 3:
                            containers.append(AssetData(
                                name=parts[0],
                                version=parts[1],
                                description=parts[2],
                                vendor="LXC"
                            ))
        except Exception:
            pass
        
        return containers
