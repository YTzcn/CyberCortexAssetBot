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
            
            # USB Devices
            hardware.extend(self._collect_usb_devices())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect hardware: {str(e)}")
        
        return hardware
    
    def _collect_system_info(self) -> List[AssetData]:
        """Collect system information."""
        hardware = []
        
        try:
            # System information from /proc/cpuinfo
            cpuinfo = self._safe_execute("cat", "/proc/cpuinfo")
            if cpuinfo:
                lines = cpuinfo.split('\n')
                vendor_id = None
                model_name = None
                cpu_version = None
                cpu_family = None
                cpu_model = None
                
                for line in lines:
                    if line.startswith('vendor_id'):
                        vendor_id = line.split(':')[1].strip()
                    elif line.startswith('model name'):
                        model_name = line.split(':')[1].strip()
                    elif line.startswith('cpu family'):
                        cpu_family = line.split(':')[1].strip()
                    elif line.startswith('model'):
                        cpu_model = line.split(':')[1].strip()
                    elif line.startswith('cpu MHz'):
                        cpu_version = line.split(':')[1].strip() + " MHz"
                        break
                
                if model_name:
                    version_parts = []
                    if cpu_family:
                        version_parts.append(f"Family: {cpu_family}")
                    if cpu_model:
                        version_parts.append(f"Model: {cpu_model}")
                    if cpu_version:
                        version_parts.append(f"Speed: {cpu_version}")
                    
                    version_string = ", ".join(version_parts) if version_parts else None
                    
                    hardware.append(AssetData(
                        name=f"System: {model_name}",
                        version=version_string,
                        vendor=vendor_id or "Unknown"
                    ))
            
            # System information from /proc/version
            version = self._safe_execute("cat", "/proc/version")
            if version:
                hardware.append(AssetData(
                    name="Kernel",
                    version=version.split()[2],  # Kernel version
                    description=version,
                    vendor="Linux"
                ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_cpu_info(self) -> List[AssetData]:
        """Collect CPU information."""
        hardware = []
        
        try:
            # CPU information from lscpu
            lscpu_output = self._safe_execute("lscpu")
            if lscpu_output:
                cpu_info = {}
                for line in lscpu_output.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        cpu_info[key.strip()] = value.strip()
                
                if 'Model name' in cpu_info:
                    # Create version string from available info
                    version_parts = []
                    if cpu_info.get('CPU(s)'):
                        version_parts.append(f"Cores: {cpu_info['CPU(s)']}")
                    if cpu_info.get('Thread(s) per core'):
                        version_parts.append(f"Threads per core: {cpu_info['Thread(s) per core']}")
                    if cpu_info.get('Architecture'):
                        version_parts.append(f"Architecture: {cpu_info['Architecture']}")
                    if cpu_info.get('CPU MHz'):
                        version_parts.append(f"Speed: {cpu_info['CPU MHz']} MHz")
                    if cpu_info.get('CPU family'):
                        version_parts.append(f"Family: {cpu_info['CPU family']}")
                    if cpu_info.get('Model'):
                        version_parts.append(f"Model: {cpu_info['Model']}")
                    
                    version_string = ", ".join(version_parts) if version_parts else None
                    
                    hardware.append(AssetData(
                        name=f"CPU: {cpu_info['Model name']}",
                        version=version_string,
                        description=f"Cores: {cpu_info.get('CPU(s)', 'Unknown')}, Threads: {cpu_info.get('Thread(s) per core', 'Unknown')}, Architecture: {cpu_info.get('Architecture', 'Unknown')}",
                        vendor=cpu_info.get('Vendor ID', 'Unknown')
                    ))
            
            # Alternative: /proc/cpuinfo
            cpuinfo = self._safe_execute("cat", "/proc/cpuinfo")
            if cpuinfo and not hardware:  # Only if lscpu didn't work
                lines = cpuinfo.split('\n')
                model_name = None
                vendor_id = None
                cpu_cores = 0
                cpu_family = None
                cpu_model = None
                cpu_mhz = None
                
                for line in lines:
                    if line.startswith('model name'):
                        model_name = line.split(':')[1].strip()
                    elif line.startswith('vendor_id'):
                        vendor_id = line.split(':')[1].strip()
                    elif line.startswith('processor'):
                        cpu_cores += 1
                    elif line.startswith('cpu family'):
                        cpu_family = line.split(':')[1].strip()
                    elif line.startswith('model'):
                        cpu_model = line.split(':')[1].strip()
                    elif line.startswith('cpu MHz'):
                        cpu_mhz = line.split(':')[1].strip() + " MHz"
                
                if model_name:
                    version_parts = []
                    if cpu_family:
                        version_parts.append(f"Family: {cpu_family}")
                    if cpu_model:
                        version_parts.append(f"Model: {cpu_model}")
                    if cpu_mhz:
                        version_parts.append(f"Speed: {cpu_mhz}")
                    
                    version_string = ", ".join(version_parts) if version_parts else None
                    
                    hardware.append(AssetData(
                        name=f"CPU: {model_name}",
                        version=version_string,
                        description=f"Cores: {cpu_cores}",
                        vendor=vendor_id or "Unknown"
                    ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_memory_info(self) -> List[AssetData]:
        """Collect memory information."""
        hardware = []
        
        try:
            # Memory information from /proc/meminfo
            meminfo = self._safe_execute("cat", "/proc/meminfo")
            if meminfo:
                mem_total = None
                mem_available = None
                mem_free = None
                mem_cached = None
                
                for line in meminfo.split('\n'):
                    if line.startswith('MemTotal'):
                        mem_total = int(line.split(':')[1].strip().split()[0]) // 1024  # Convert to MB
                    elif line.startswith('MemAvailable'):
                        mem_available = int(line.split(':')[1].strip().split()[0]) // 1024
                    elif line.startswith('MemFree'):
                        mem_free = int(line.split(':')[1].strip().split()[0]) // 1024
                    elif line.startswith('Cached'):
                        mem_cached = int(line.split(':')[1].strip().split()[0]) // 1024
                
                if mem_total:
                    # Create version string with memory details
                    version_parts = []
                    if mem_available:
                        version_parts.append(f"Available: {mem_available // 1024}GB")
                    if mem_free:
                        version_parts.append(f"Free: {mem_free // 1024}GB")
                    if mem_cached:
                        version_parts.append(f"Cached: {mem_cached // 1024}GB")
                    
                    version_string = ", ".join(version_parts) if version_parts else None
                    
                    hardware.append(AssetData(
                        name=f"RAM: {mem_total // 1024}GB",
                        version=version_string,
                        size=mem_total * 1024 * 1024,  # Convert to bytes
                        vendor="Unknown"
                    ))
            
            # Alternative: free command
            free_output = self._safe_execute("free", "-h")
            if free_output and not hardware:
                lines = free_output.split('\n')
                if len(lines) > 1:
                    mem_line = lines[1].split()
                    if len(mem_line) > 1:
                        hardware.append(AssetData(
                            name=f"RAM: {mem_line[1]}",
                            vendor="Unknown"
                        ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_disk_info(self) -> List[AssetData]:
        """Collect disk information."""
        hardware = []
        
        try:
            # Disk information from lsblk
            lsblk_output = self._safe_execute("lsblk", "-J")
            if lsblk_output:
                import json
                data = json.loads(lsblk_output)
                if 'blockdevices' in data:
                    for device in data['blockdevices']:
                        if device.get('type') == 'disk':
                            # Create version string with disk details
                            version_parts = []
                            if device.get('model'):
                                version_parts.append(f"Model: {device['model']}")
                            if device.get('vendor'):
                                version_parts.append(f"Vendor: {device['vendor']}")
                            if device.get('tran'):
                                version_parts.append(f"Transport: {device['tran']}")
                            if device.get('rota'):
                                version_parts.append(f"Rotational: {device['rota']}")
                            if device.get('serial'):
                                version_parts.append(f"Serial: {device['serial']}")
                            
                            version_string = ", ".join(version_parts) if version_parts else None
                            
                            hardware.append(AssetData(
                                name=f"Disk: {device.get('name', 'Unknown')}",
                                version=version_string,
                                description=f"Size: {device.get('size', 'Unknown')}, Model: {device.get('model', 'Unknown')}",
                                vendor=device.get('vendor', 'Unknown'),
                                size=self._parse_size(device.get('size', '0'))
                            ))
            
            # Alternative: df command
            df_output = self._safe_execute("df", "-h")
            if df_output and not hardware:
                lines = df_output.split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 6:
                            hardware.append(AssetData(
                                name=f"Disk: {parts[0]}",
                                description=f"Size: {parts[1]}, Used: {parts[2]}, Available: {parts[3]}",
                                vendor="Unknown"
                            ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_network_info(self) -> List[AssetData]:
        """Collect network information."""
        hardware = []
        
        try:
            # Network interfaces from ip command with detailed info
            ip_output = self._safe_execute("ip", "link", "show")
            if ip_output:
                for line in ip_output.split('\n'):
                    if ':' in line and 'state' in line:
                        interface = line.split(':')[1].strip()
                        if not interface.startswith('lo'):  # Skip loopback
                            # Get additional interface details
                            version_parts = []
                            
                            # Get interface type and state
                            if 'state' in line:
                                state_part = line.split('state')[1].strip()
                                if ' ' in state_part:
                                    state = state_part.split()[0]
                                    version_parts.append(f"State: {state}")
                            
                            # Get interface type from /sys/class/net
                            try:
                                interface_type = self._safe_execute("cat", f"/sys/class/net/{interface}/type")
                                if interface_type:
                                    version_parts.append(f"Type: {interface_type}")
                            except:
                                pass
                            
                            # Get driver information
                            try:
                                driver = self._safe_execute("cat", f"/sys/class/net/{interface}/device/driver/module/drivers")
                                if driver:
                                    version_parts.append(f"Driver: {driver}")
                            except:
                                pass
                            
                            version_string = ", ".join(version_parts) if version_parts else None
                            
                            hardware.append(AssetData(
                                name=f"Network: {interface}",
                                version=version_string,
                                vendor="Unknown"
                            ))
            
            # Alternative: ifconfig
            ifconfig_output = self._safe_execute("ifconfig")
            if ifconfig_output and not hardware:
                for line in ifconfig_output.split('\n'):
                    if line and not line.startswith(' ') and not line.startswith('\t'):
                        interface = line.split(':')[0]
                        if not interface.startswith('lo'):  # Skip loopback
                            hardware.append(AssetData(
                                name=f"Network: {interface}",
                                vendor="Unknown"
                            ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_graphics_info(self) -> List[AssetData]:
        """Collect graphics information."""
        hardware = []
        
        try:
            # Graphics information from lspci with detailed info
            lspci_output = self._safe_execute("lspci", "-v")
            if lspci_output:
                current_gpu = None
                gpu_info = {}
                
                for line in lspci_output.split('\n'):
                    if 'VGA' in line or 'Display' in line or '3D' in line:
                        if current_gpu:
                            # Process previous GPU
                            version_parts = []
                            if gpu_info.get('subsystem'):
                                version_parts.append(f"Subsystem: {gpu_info['subsystem']}")
                            if gpu_info.get('driver'):
                                version_parts.append(f"Driver: {gpu_info['driver']}")
                            if gpu_info.get('memory'):
                                version_parts.append(f"Memory: {gpu_info['memory']}")
                            
                            version_string = ", ".join(version_parts) if version_parts else None
                            
                            hardware.append(AssetData(
                                name=f"GPU: {current_gpu}",
                                version=version_string,
                                vendor="Unknown"
                            ))
                        
                        # Start new GPU
                        current_gpu = line
                        gpu_info = {}
                    elif current_gpu and line.strip():
                        if line.startswith('\t'):
                            # This is a detail line
                            if 'Subsystem:' in line:
                                gpu_info['subsystem'] = line.split('Subsystem:')[1].strip()
                            elif 'Kernel driver in use:' in line:
                                gpu_info['driver'] = line.split('Kernel driver in use:')[1].strip()
                            elif 'Memory at' in line:
                                gpu_info['memory'] = line.split('Memory at')[1].strip().split()[0]
                
                # Process last GPU if exists
                if current_gpu:
                    version_parts = []
                    if gpu_info.get('subsystem'):
                        version_parts.append(f"Subsystem: {gpu_info['subsystem']}")
                    if gpu_info.get('driver'):
                        version_parts.append(f"Driver: {gpu_info['driver']}")
                    if gpu_info.get('memory'):
                        version_parts.append(f"Memory: {gpu_info['memory']}")
                    
                    version_string = ", ".join(version_parts) if version_parts else None
                    
                    hardware.append(AssetData(
                        name=f"GPU: {current_gpu}",
                        version=version_string,
                        vendor="Unknown"
                    ))
            
            # Fallback: simple lspci
            if not hardware:
                lspci_simple = self._safe_execute("lspci")
                if lspci_simple:
                    for line in lspci_simple.split('\n'):
                        if 'VGA' in line or 'Display' in line or '3D' in line:
                            hardware.append(AssetData(
                                name=f"GPU: {line}",
                                vendor="Unknown"
                            ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_usb_devices(self) -> List[AssetData]:
        """Collect USB device information."""
        hardware = []
        
        try:
            # USB devices from lsusb
            lsusb_output = self._safe_execute("lsusb")
            if lsusb_output:
                for line in lsusb_output.split('\n'):
                    if line.strip():
                        hardware.append(AssetData(
                            name=f"USB: {line}",
                            vendor="Unknown"
                        ))
            
            # Alternative: /proc/bus/usb/devices
            usb_output = self._safe_execute("cat", "/proc/bus/usb/devices")
            if usb_output and not hardware:
                # This is more complex, just add a basic entry
                hardware.append(AssetData(
                    name="USB: Unknown",
                    vendor="Unknown"
                ))
                
        except Exception:
            pass
        
        return hardware
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes."""
        if not size_str or size_str == 'Unknown':
            return 0
        
        size_str = size_str.upper()
        multipliers = {
            'K': 1024,
            'M': 1024**2,
            'G': 1024**3,
            'T': 1024**4
        }
        
        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[:-1]) * multiplier)
                except ValueError:
                    return 0
        
        try:
            return int(size_str)
        except ValueError:
            return 0
