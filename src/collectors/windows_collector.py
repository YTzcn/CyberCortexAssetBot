"""
Windows-specific asset collector for CyberCortexAssetBot.

This module implements Windows-specific asset collection using WMI,
Windows Registry, and PowerShell commands.
"""

import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import json

import psutil

# Windows-specific imports
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

from .base_collector import (
    BaseCollector, 
    AssetData, 
    CollectionResult, 
    AssetType,
    CollectorNotSupportedError,
    DataCollectionError
)
from utils.platform_detector import PlatformInfo, PlatformType


class WindowsCollector(BaseCollector):
    """Windows-specific asset collector implementation."""
    
    def __init__(self, platform_info: Optional[PlatformInfo] = None) -> None:
        """Initialize Windows collector."""
        super().__init__(platform_info)
        self.wmi_conn = None
        if WMI_AVAILABLE:
            try:
                self.wmi_conn = wmi.WMI()
            except Exception:
                self.wmi_conn = None
    
    def _validate_platform_support(self) -> None:
        """Validate that collector supports current platform."""
        if self.platform_info.platform_type != PlatformType.WINDOWS:
            raise CollectorNotSupportedError(
                f"WindowsCollector only supports Windows, got {self.platform_info.platform_type.value}"
            )
    
    def collect_drivers(self) -> List[AssetData]:
        """
        Collect Windows drivers and kernel modules.
        
        Returns:
            List of driver assets
        """
        drivers = []
        
        try:
            # Collect using WMI if available
            if self.wmi_conn:
                drivers.extend(self._collect_wmi_drivers())
            
            # Collect using PowerShell as fallback
            drivers.extend(self._collect_powershell_drivers())
            
            # Collect from registry
            drivers.extend(self._collect_registry_drivers())
            
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
            # Collect from WMI Win32_Product
            if self.wmi_conn:
                applications.extend(self._collect_wmi_applications())
            
            # Collect from registry (Add/Remove Programs)
            applications.extend(self._collect_registry_applications())
            
            # Collect from PowerShell Get-WmiObject
            applications.extend(self._collect_powershell_applications())
            
            # Collect from Windows Store apps
            applications.extend(self._collect_store_applications())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect applications: {str(e)}")
        
        return applications
    
    def collect_services(self) -> List[AssetData]:
        """
        Collect Windows services and processes.
        
        Returns:
            List of service assets
        """
        services = []
        
        try:
            # Collect using WMI
            if self.wmi_conn:
                services.extend(self._collect_wmi_services())
            
            # Collect using PowerShell
            services.extend(self._collect_powershell_services())
            
            # Collect from Registry
            services.extend(self._collect_registry_services())
            
            # Collect running processes
            services.extend(self._collect_running_processes())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect services: {str(e)}")
        
        return services
    
    def collect_libraries(self) -> List[AssetData]:
        """
        Collect system libraries and DLLs.
        
        Returns:
            List of library assets
        """
        libraries = []
        
        try:
            # Collect DLLs from system directories
            lib_dirs = [
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64",
                "C:\\Program Files\\Common Files",
                "C:\\Program Files (x86)\\Common Files"
            ]
            
            for lib_dir in lib_dirs:
                lib_path = Path(lib_dir)
                if lib_path.exists():
                    for dll_file in lib_path.rglob("*.dll"):
                        if dll_file.is_file():
                            # Try to get version information
                            version = None
                            try:
                                import win32api
                                version_info = win32api.GetFileVersionInfo(str(dll_file), "\\")
                                version = f"{version_info['FileVersionMS'] >> 16}.{version_info['FileVersionMS'] & 0xFFFF}.{version_info['FileVersionLS'] >> 16}.{version_info['FileVersionLS'] & 0xFFFF}"
                            except:
                                pass
                            
                            libraries.append(AssetData(
                                name=dll_file.name,
                                version=version,
                                path=str(dll_file),
                                size=dll_file.stat().st_size,
                                install_date=datetime.fromtimestamp(dll_file.stat().st_mtime),
                                vendor="Microsoft" if "Windows" in str(dll_file) else None
                            ))
            
            # Collect .NET assemblies
            libraries.extend(self._collect_dotnet_assemblies())
            
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
            
            # .NET packages
            packages.extend(self._collect_nuget_packages())
            
            # Chocolatey packages
            packages.extend(self._collect_chocolatey_packages())
            
            # Scoop packages
            packages.extend(self._collect_scoop_packages())
            
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
            
            # Hyper-V containers
            containers.extend(self._collect_hyperv_containers())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect containers: {str(e)}")
        
        return containers
    
    def collect_hardware(self) -> List[AssetData]:
        """
        Collect hardware information.
        
        Returns:
            List of hardware assets
        """
        hardware = []
        
        try:
            # Collect using WMI if available
            if self.wmi_conn:
                hardware.extend(self._collect_wmi_hardware())
            
            # Collect using PowerShell as fallback
            hardware.extend(self._collect_powershell_hardware())
            
        except Exception as e:
            raise DataCollectionError(f"Failed to collect hardware: {str(e)}")
        
        return hardware
    
    def _collect_wmi_drivers(self) -> List[AssetData]:
        """Collect drivers using WMI."""
        drivers = []
        
        try:
            for driver in self.wmi_conn.Win32_SystemDriver():
                # Initialize variables
                version = None
                checksum = None
                signature = None
                install_date = None
                size = None
                architecture = None
                
                if driver.PathName:
                    try:
                        import win32api
                        clean_path = driver.PathName.strip('"')
                        clean_path = os.path.expandvars(clean_path)
                        
                        # Get version information
                        try:
                            version_info = win32api.GetFileVersionInfo(clean_path, "\\")
                            version = f"{version_info['FileVersionMS'] >> 16}.{version_info['FileVersionMS'] & 0xFFFF}.{version_info['FileVersionLS'] >> 16}.{version_info['FileVersionLS'] & 0xFFFF}"
                        except:
                            pass
                        
                        # Get file stats if file exists
                        file_path = Path(clean_path)
                        if file_path.exists() and file_path.is_file():
                            # Get file size
                            size = file_path.stat().st_size
                            
                            # Get install/creation date
                            install_date = datetime.fromtimestamp(file_path.stat().st_ctime)
                            
                            # Calculate checksum
                            checksum = self._calculate_checksum(str(file_path))
                            
                            # Detect architecture from path
                            path_lower = str(file_path).lower()
                            if 'system32' in path_lower and 'syswow64' not in path_lower:
                                architecture = "x64"
                            elif 'syswow64' in path_lower:
                                architecture = "x86"
                            
                            # Check digital signature
                            signature = self._check_digital_signature(str(file_path))
                    except:
                        pass
                
                drivers.append(AssetData(
                    name=driver.Name,
                    version=version,
                    description=driver.Description,
                    path=driver.PathName,
                    checksum=checksum,
                    signature=signature,
                    install_date=install_date,
                    size=size,
                    vendor=driver.ServiceType,
                    architecture=architecture
                ))
        except Exception:
            pass
        
        return drivers
    
    def _collect_powershell_drivers(self) -> List[AssetData]:
        """Collect drivers using PowerShell."""
        drivers = []
        
        try:
            ps_cmd = """
            Get-WmiObject -Class Win32_SystemDriver | ForEach-Object {
                $version = $null
                $size = $null
                $installDate = $null
                $checksum = $null
                $signature = $null
                $architecture = $null
                
                if ($_.PathName) {
                    try {
                        $filePath = $_.PathName.Trim('"')
                        $filePath = [System.Environment]::ExpandEnvironmentVariables($filePath)
                        
                        if (Test-Path $filePath) {
                            # Get version
                            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath)
                            $version = $versionInfo.FileVersion
                            
                            # Get file info
                            $fileInfo = Get-Item $filePath
                            $size = $fileInfo.Length
                            $installDate = $fileInfo.CreationTime.ToString("o")
                            
                            # Get checksum (SHA256)
                            $hash = Get-FileHash -Path $filePath -Algorithm SHA256
                            $checksum = $hash.Hash
                            
                            # Get signature
                            $sig = Get-AuthenticodeSignature -FilePath $filePath
                            $signature = $sig.Status
                            
                            # Detect architecture
                            if ($filePath -like "*System32*" -and $filePath -notlike "*SysWOW64*") {
                                $architecture = "x64"
                            } elseif ($filePath -like "*SysWOW64*") {
                                $architecture = "x86"
                            }
                        }
                    } catch {
                        # Ignore errors
                    }
                }
                [PSCustomObject]@{
                    Name = $_.Name
                    Description = $_.Description
                    PathName = $_.PathName
                    ServiceType = $_.ServiceType
                    Version = $version
                    Size = $size
                    InstallDate = $installDate
                    Checksum = $checksum
                    Signature = $signature
                    Architecture = $architecture
                }
            } | ConvertTo-Json
            """
            output = self._safe_execute("powershell", "-Command", ps_cmd, encoding='utf-8')
            if output:
                driver_data = json.loads(output)
                if isinstance(driver_data, list):
                    for driver in driver_data:
                        # Parse install date
                        install_date = None
                        if driver.get('InstallDate'):
                            try:
                                install_date = datetime.fromisoformat(driver['InstallDate'])
                            except:
                                pass
                        
                        drivers.append(AssetData(
                            name=driver.get('Name', ''),
                            version=driver.get('Version'),
                            description=driver.get('Description', ''),
                            path=driver.get('PathName', ''),
                            checksum=driver.get('Checksum'),
                            signature=driver.get('Signature'),
                            install_date=install_date,
                            size=driver.get('Size'),
                            vendor=driver.get('ServiceType', ''),
                            architecture=driver.get('Architecture')
                        ))
        except Exception:
            pass
        
        return drivers
    
    def _collect_registry_drivers(self) -> List[AssetData]:
        """Collect drivers from Windows Registry."""
        drivers = []
        
        if not WINREG_AVAILABLE:
            return drivers
        
        try:
            # Registry key for drivers
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   "SYSTEM\\CurrentControlSet\\Services")
            
            for i in range(winreg.QueryInfoKey(reg_key)[0]):
                try:
                    subkey_name = winreg.EnumKey(reg_key, i)
                    subkey = winreg.OpenKey(reg_key, subkey_name)
                    
                    try:
                        service_type = winreg.QueryValueEx(subkey, "Type")[0]
                        if service_type == 1:  # Kernel driver
                            image_path = winreg.QueryValueEx(subkey, "ImagePath")[0]
                            
                            # Initialize variables
                            version = None
                            checksum = None
                            signature = None
                            install_date = None
                            size = None
                            architecture = None
                            
                            if image_path:
                                try:
                                    import win32api
                                    clean_path = image_path.strip('"')
                                    
                                    # Expand environment variables
                                    clean_path = os.path.expandvars(clean_path)
                                    
                                    # Get version information
                                    try:
                                        version_info = win32api.GetFileVersionInfo(clean_path, "\\")
                                        version = f"{version_info['FileVersionMS'] >> 16}.{version_info['FileVersionMS'] & 0xFFFF}.{version_info['FileVersionLS'] >> 16}.{version_info['FileVersionLS'] & 0xFFFF}"
                                    except:
                                        pass
                                    
                                    # Get file stats if file exists
                                    file_path = Path(clean_path)
                                    if file_path.exists() and file_path.is_file():
                                        # Get file size
                                        size = file_path.stat().st_size
                                        
                                        # Get install/creation date
                                        install_date = datetime.fromtimestamp(file_path.stat().st_ctime)
                                        
                                        # Calculate checksum
                                        checksum = self._calculate_checksum(str(file_path))
                                        
                                        # Detect architecture from path
                                        path_lower = str(file_path).lower()
                                        if 'system32' in path_lower and 'syswow64' not in path_lower:
                                            architecture = "x64"
                                        elif 'syswow64' in path_lower:
                                            architecture = "x86"
                                        
                                        # Check digital signature
                                        signature = self._check_digital_signature(str(file_path))
                                        
                                except:
                                    pass
                            
                            drivers.append(AssetData(
                                name=subkey_name,
                                version=version,
                                path=image_path,
                                checksum=checksum,
                                signature=signature,
                                install_date=install_date,
                                size=size,
                                vendor="Kernel Driver",
                                architecture=architecture
                            ))
                    except FileNotFoundError:
                        pass
                    finally:
                        winreg.CloseKey(subkey)
                        
                except OSError:
                    continue
            
            winreg.CloseKey(reg_key)
        except Exception:
            pass
        
        return drivers
    
    def _collect_wmi_applications(self) -> List[AssetData]:
        """Collect applications using WMI Win32_Product."""
        applications = []
        
        try:
            for product in self.wmi_conn.Win32_Product():
                applications.append(AssetData(
                    name=product.Name,
                    version=product.Version,
                    vendor=product.Vendor,
                    description=product.Description,
                    install_date=datetime.strptime(product.InstallDate, "%Y%m%d") if product.InstallDate else None
                ))
        except Exception:
            pass
        
        return applications
    
    def _collect_registry_applications(self) -> List[AssetData]:
        """Collect applications from registry."""
        applications = []
        
        if not WINREG_AVAILABLE:
            return applications
        
        registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        ]
        
        for hkey, subkey_path in registry_keys:
            try:
                with winreg.OpenKey(hkey, subkey_path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                    publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                                    
                                    applications.append(AssetData(
                                        name=display_name,
                                        version=version,
                                        vendor=publisher
                                    ))
                                except FileNotFoundError:
                                    pass
                        except OSError:
                            continue
            except FileNotFoundError:
                continue
        
        return applications
    
    def _collect_powershell_applications(self) -> List[AssetData]:
        """Collect applications using PowerShell."""
        applications = []
        
        try:
            ps_cmd = """
            Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | 
            Where-Object {$_.DisplayName} | 
            Select-Object DisplayName, DisplayVersion, Publisher | 
            ConvertTo-Json
            """
            output = self._safe_execute("powershell", "-Command", ps_cmd, encoding='utf-8')
            if output:
                app_data = json.loads(output)
                if isinstance(app_data, list):
                    for app in app_data:
                        applications.append(AssetData(
                            name=app.get('DisplayName', ''),
                            version=app.get('DisplayVersion', ''),
                            vendor=app.get('Publisher', '')
                        ))
        except Exception:
            pass
        
        return applications
    
    def _collect_store_applications(self) -> List[AssetData]:
        """Collect Windows Store applications."""
        applications = []
        
        try:
            ps_cmd = "Get-AppxPackage | Select-Object Name, Version, Publisher | ConvertTo-Json"
            output = self._safe_execute("powershell", "-Command", ps_cmd, encoding='utf-8')
            if output:
                store_data = json.loads(output)
                if isinstance(store_data, list):
                    for app in store_data:
                        applications.append(AssetData(
                            name=app.get('Name', ''),
                            version=app.get('Version', ''),
                            vendor=app.get('Publisher', '')
                        ))
        except Exception:
            pass
        
        return applications
    
    def _collect_wmi_services(self) -> List[AssetData]:
        """Collect services using WMI."""
        services = []
        
        try:
            for service in self.wmi_conn.Win32_Service():
                # Try to get version from executable path
                version = None
                if service.PathName:
                    try:
                        # Get file version from executable
                        import win32api
                        version_info = win32api.GetFileVersionInfo(service.PathName.strip('"'), "\\")
                        version = f"{version_info['FileVersionMS'] >> 16}.{version_info['FileVersionMS'] & 0xFFFF}.{version_info['FileVersionLS'] >> 16}.{version_info['FileVersionLS'] & 0xFFFF}"
                    except:
                        pass
                
                services.append(AssetData(
                    name=service.Name,
                    version=version,
                    description=service.Description,
                    path=service.PathName,
                    vendor=service.StartMode
                ))
        except Exception:
            pass
        
        return services
    
    def _collect_powershell_services(self) -> List[AssetData]:
        """Collect services using PowerShell with version info."""
        services = []
        
        try:
            # PowerShell command to get services with executable path and version
            ps_cmd = """
            Get-WmiObject -Class Win32_Service | ForEach-Object {
                $version = $null
                if ($_.PathName) {
                    try {
                        $filePath = $_.PathName.Trim('"')
                        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath)
                        $version = $versionInfo.FileVersion
                    } catch {
                        $version = $null
                    }
                }
                [PSCustomObject]@{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    Status = $_.State
                    PathName = $_.PathName
                    Version = $version
                    StartMode = $_.StartMode
                }
            } | ConvertTo-Json
            """
            output = self._safe_execute("powershell", "-Command", ps_cmd, encoding='utf-8')
            if output:
                service_data = json.loads(output)
                if isinstance(service_data, list):
                    for service in service_data:
                        services.append(AssetData(
                            name=service.get('Name', ''),
                            version=service.get('Version'),
                            description=service.get('DisplayName', ''),
                            path=service.get('PathName', ''),
                            vendor=service.get('StartMode', '')
                        ))
        except Exception:
            pass
        
        return services
    
    def _collect_registry_services(self) -> List[AssetData]:
        """Collect services from Windows Registry."""
        services = []
        
        if not WINREG_AVAILABLE:
            return services
        
        try:
            # Registry key for services
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   "SYSTEM\\CurrentControlSet\\Services")
            
            for i in range(winreg.QueryInfoKey(reg_key)[0]):
                try:
                    service_name = winreg.EnumKey(reg_key, i)
                    service_key = winreg.OpenKey(reg_key, service_name)
                    
                    # Get service information
                    display_name = None
                    image_path = None
                    start_type = None
                    
                    try:
                        display_name = winreg.QueryValueEx(service_key, "DisplayName")[0]
                    except FileNotFoundError:
                        pass
                    
                    try:
                        image_path = winreg.QueryValueEx(service_key, "ImagePath")[0]
                    except FileNotFoundError:
                        pass
                    
                    try:
                        start_type = winreg.QueryValueEx(service_key, "Start")[0]
                    except FileNotFoundError:
                        pass
                    
                    # Try to get version from executable
                    version = None
                    if image_path:
                        try:
                            import win32api
                            clean_path = image_path.strip('"')
                            version_info = win32api.GetFileVersionInfo(clean_path, "\\")
                            version = f"{version_info['FileVersionMS'] >> 16}.{version_info['FileVersionMS'] & 0xFFFF}.{version_info['FileVersionLS'] >> 16}.{version_info['FileVersionLS'] & 0xFFFF}"
                        except:
                            pass
                    
                    services.append(AssetData(
                        name=service_name,
                        version=version,
                        description=display_name,
                        path=image_path,
                        vendor=f"StartType: {start_type}" if start_type is not None else None
                    ))
                    
                    winreg.CloseKey(service_key)
                    
                except OSError:
                    continue
            
            winreg.CloseKey(reg_key)
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
    
    def _collect_dotnet_assemblies(self) -> List[AssetData]:
        """Collect .NET assemblies."""
        libraries = []
        
        try:
            # Global Assembly Cache
            gac_paths = [
                "C:\\Windows\\Microsoft.NET\\assembly",
                "C:\\Windows\\assembly"
            ]
            
            for gac_path in gac_paths:
                gac_dir = Path(gac_path)
                if gac_dir.exists():
                    for dll_file in gac_dir.rglob("*.dll"):
                        if dll_file.is_file():
                            # Try to get version information
                            version = None
                            try:
                                import win32api
                                version_info = win32api.GetFileVersionInfo(str(dll_file), "\\")
                                version = f"{version_info['FileVersionMS'] >> 16}.{version_info['FileVersionMS'] & 0xFFFF}.{version_info['FileVersionLS'] >> 16}.{version_info['FileVersionLS'] & 0xFFFF}"
                            except:
                                pass
                            
                            libraries.append(AssetData(
                                name=dll_file.name,
                                version=version,
                                path=str(dll_file),
                                size=dll_file.stat().st_size,
                                vendor=".NET Framework"
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
    
    def _collect_nuget_packages(self) -> List[AssetData]:
        """Collect NuGet packages."""
        packages = []
        
        try:
            nuget_output = self._safe_execute("nuget", "list", "-Source", "All")
            if nuget_output:
                for line in nuget_output.split('\n'):
                    if ' ' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append(AssetData(
                                name=parts[0],
                                version=parts[1]
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_chocolatey_packages(self) -> List[AssetData]:
        """Collect Chocolatey packages."""
        packages = []
        
        try:
            choco_output = self._safe_execute("choco", "list", "--local-only")
            if choco_output:
                for line in choco_output.split('\n'):
                    if '|' in line and not line.startswith('Chocolatey'):
                        parts = line.split('|')
                        if len(parts) >= 2:
                            packages.append(AssetData(
                                name=parts[0].strip(),
                                version=parts[1].strip(),
                                vendor="Chocolatey"
                            ))
        except Exception:
            pass
        
        return packages
    
    def _collect_scoop_packages(self) -> List[AssetData]:
        """Collect Scoop packages."""
        packages = []
        
        try:
            scoop_output = self._safe_execute("scoop", "list")
            if scoop_output:
                for line in scoop_output.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append(AssetData(
                                name=parts[0],
                                version=parts[1],
                                vendor="Scoop"
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
    
    def _collect_hyperv_containers(self) -> List[AssetData]:
        """Collect Hyper-V containers."""
        containers = []
        
        try:
            ps_cmd = "Get-VM | Select-Object Name, State, Generation | ConvertTo-Json"
            output = self._safe_execute("powershell", "-Command", ps_cmd, encoding='utf-8')
            if output:
                vm_data = json.loads(output)
                if isinstance(vm_data, list):
                    for vm in vm_data:
                        containers.append(AssetData(
                            name=vm.get('Name', ''),
                            description=vm.get('State', ''),
                            vendor="Hyper-V"
                        ))
        except Exception:
            pass
        
        return containers
    
    def _check_digital_signature(self, file_path: str) -> Optional[str]:
        """
        Check digital signature of a file using PowerShell.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            Signature status or None if check fails
        """
        try:
            ps_cmd = f'(Get-AuthenticodeSignature "{file_path}").Status'
            output = self._safe_execute("powershell", "-Command", ps_cmd, encoding='utf-8')
            if output:
                return output.strip()
        except Exception:
            pass
        return None
    
    def _collect_wmi_hardware(self) -> List[AssetData]:
        """Collect hardware using WMI."""
        hardware = []
        
        try:
            # CPU Information
            for cpu in self.wmi_conn.Win32_Processor():
                hardware.append(AssetData(
                    name=f"CPU: {cpu.Name}",
                    version=cpu.Version,
                    description=f"Manufacturer: {cpu.Manufacturer}, Cores: {cpu.NumberOfCores}, Threads: {cpu.NumberOfLogicalProcessors}",
                    vendor=cpu.Manufacturer,
                    size=cpu.MaxClockSpeed
                ))
            
            # Memory Information
            for memory in self.wmi_conn.Win32_PhysicalMemory():
                hardware.append(AssetData(
                    name=f"RAM: {memory.Capacity // (1024**3)}GB",
                    version=memory.Version,
                    description=f"Manufacturer: {memory.Manufacturer}, Speed: {memory.Speed}MHz, Form Factor: {memory.FormFactor}",
                    vendor=memory.Manufacturer,
                    size=memory.Capacity
                ))
            
            # Disk Drives
            for disk in self.wmi_conn.Win32_DiskDrive():
                hardware.append(AssetData(
                    name=f"Disk: {disk.Model}",
                    version=disk.FirmwareRevision,
                    description=f"Manufacturer: {disk.Manufacturer}, Interface: {disk.InterfaceType}, Size: {disk.Size // (1024**3)}GB",
                    vendor=disk.Manufacturer,
                    size=disk.Size
                ))
            
            # Network Adapters
            for adapter in self.wmi_conn.Win32_NetworkAdapter():
                if adapter.NetConnectionStatus == 2:  # Connected
                    hardware.append(AssetData(
                        name=f"Network: {adapter.Name}",
                        version=adapter.DriverVersion,
                        description=f"Manufacturer: {adapter.Manufacturer}, MAC: {adapter.MACAddress}",
                        vendor=adapter.Manufacturer
                    ))
            
            # Graphics Cards
            for gpu in self.wmi_conn.Win32_VideoController():
                if gpu.Name and "Microsoft" not in gpu.Name:
                    hardware.append(AssetData(
                        name=f"GPU: {gpu.Name}",
                        version=gpu.DriverVersion,
                        description=f"Manufacturer: {gpu.Manufacturer}, Memory: {gpu.AdapterRAM // (1024**2)}MB",
                        vendor=gpu.Manufacturer,
                        size=gpu.AdapterRAM
                    ))
            
            # Motherboard
            for board in self.wmi_conn.Win32_BaseBoard():
                hardware.append(AssetData(
                    name=f"Motherboard: {board.Product}",
                    version=board.Version,
                    description=f"Manufacturer: {board.Manufacturer}, Serial: {board.SerialNumber}",
                    vendor=board.Manufacturer
                ))
            
            # BIOS
            for bios in self.wmi_conn.Win32_BIOS():
                hardware.append(AssetData(
                    name=f"BIOS: {bios.Name}",
                    version=bios.SMBIOSBIOSVersion,
                    description=f"Manufacturer: {bios.Manufacturer}, Release Date: {bios.ReleaseDate}",
                    vendor=bios.Manufacturer
                ))
                
        except Exception:
            pass
        
        return hardware
    
    def _collect_powershell_hardware(self) -> List[AssetData]:
        """Collect hardware using PowerShell."""
        hardware = []
        
        try:
            ps_cmd = """
            $hardware = @()
            
            # CPU
            Get-WmiObject -Class Win32_Processor | ForEach-Object {
                $hardware += [PSCustomObject]@{
                    Type = "CPU"
                    Name = $_.Name
                    Version = $_.Version
                    Manufacturer = $_.Manufacturer
                    Cores = $_.NumberOfCores
                    Threads = $_.NumberOfLogicalProcessors
                    MaxClockSpeed = $_.MaxClockSpeed
                }
            }
            
            # Memory
            Get-WmiObject -Class Win32_PhysicalMemory | ForEach-Object {
                $hardware += [PSCustomObject]@{
                    Type = "RAM"
                    Name = "RAM: $([math]::Round($_.Capacity / 1GB, 2))GB"
                    Version = $_.Version
                    Manufacturer = $_.Manufacturer
                    Speed = $_.Speed
                    FormFactor = $_.FormFactor
                    Capacity = $_.Capacity
                }
            }
            
            # Disk Drives
            Get-WmiObject -Class Win32_DiskDrive | ForEach-Object {
                $hardware += [PSCustomObject]@{
                    Type = "Disk"
                    Name = "Disk: $($_.Model)"
                    Version = $_.FirmwareRevision
                    Manufacturer = $_.Manufacturer
                    Interface = $_.InterfaceType
                    Size = $_.Size
                }
            }
            
            # Network Adapters
            Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | ForEach-Object {
                $hardware += [PSCustomObject]@{
                    Type = "Network"
                    Name = "Network: $($_.Name)"
                    Version = $_.DriverVersion
                    Manufacturer = $_.Manufacturer
                    MACAddress = $_.MACAddress
                }
            }
            
            # Graphics Cards
            Get-WmiObject -Class Win32_VideoController | Where-Object { $_.Name -and $_.Name -notlike "*Microsoft*" } | ForEach-Object {
                $hardware += [PSCustomObject]@{
                    Type = "GPU"
                    Name = "GPU: $($_.Name)"
                    Version = $_.DriverVersion
                    Manufacturer = $_.Manufacturer
                    AdapterRAM = $_.AdapterRAM
                }
            }
            
            # Motherboard
            Get-WmiObject -Class Win32_BaseBoard | ForEach-Object {
                $hardware += [PSCustomObject]@{
                    Type = "Motherboard"
                    Name = "Motherboard: $($_.Product)"
                    Version = $_.Version
                    Manufacturer = $_.Manufacturer
                    SerialNumber = $_.SerialNumber
                }
            }
            
            # BIOS
            Get-WmiObject -Class Win32_BIOS | ForEach-Object {
                $hardware += [PSCustomObject]@{
                    Type = "BIOS"
                    Name = "BIOS: $($_.Name)"
                    Version = $_.SMBIOSBIOSVersion
                    Manufacturer = $_.Manufacturer
                    ReleaseDate = $_.ReleaseDate
                }
            }
            
            $hardware | ConvertTo-Json
            """
            
            output = self._safe_execute("powershell", "-Command", ps_cmd, encoding='utf-8')
            if output:
                hardware_data = json.loads(output)
                if isinstance(hardware_data, list):
                    for item in hardware_data:
                        description_parts = []
                        if item.get('Manufacturer'):
                            description_parts.append(f"Manufacturer: {item['Manufacturer']}")
                        if item.get('Cores'):
                            description_parts.append(f"Cores: {item['Cores']}")
                        if item.get('Threads'):
                            description_parts.append(f"Threads: {item['Threads']}")
                        if item.get('Speed'):
                            description_parts.append(f"Speed: {item['Speed']}MHz")
                        if item.get('Interface'):
                            description_parts.append(f"Interface: {item['Interface']}")
                        if item.get('MACAddress'):
                            description_parts.append(f"MAC: {item['MACAddress']}")
                        if item.get('SerialNumber'):
                            description_parts.append(f"Serial: {item['SerialNumber']}")
                        if item.get('ReleaseDate'):
                            description_parts.append(f"Release: {item['ReleaseDate']}")
                        
                        hardware.append(AssetData(
                            name=item.get('Name', ''),
                            version=item.get('Version'),
                            description=', '.join(description_parts) if description_parts else None,
                            vendor=item.get('Manufacturer'),
                            size=item.get('Capacity') or item.get('AdapterRAM') or item.get('Size') or item.get('MaxClockSpeed')
                        ))
                        
        except Exception:
            pass
        
        return hardware
