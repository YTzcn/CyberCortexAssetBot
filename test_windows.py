#!/usr/bin/env python3
"""
Windows Test Script for CyberCortexAssetBot
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from utils.platform_detector import get_current_platform, is_supported_platform
from collectors.windows_collector import WindowsCollector

def test_windows_collector():
    """Test Windows collector with encoding fixes."""
    print("🔍 Windows Collector Test")
    print("=" * 50)
    
    # Check platform
    if not is_supported_platform():
        print("❌ Unsupported platform!")
        return
    
    platform_info = get_current_platform()
    print(f"🖥️  Platform: {platform_info.platform_type.value}")
    print()
    
    try:
        # Create collector
        collector = WindowsCollector(platform_info)
        print(f"✅ {collector.__class__.__name__} loaded")
        
        # Test packages collection
        print("\n📦 Testing packages collection...")
        packages = collector.collect_packages()
        print(f"✅ Collected {len(packages)} packages")
        
        # Show first few packages
        for i, pkg in enumerate(packages[:5]):
            print(f"   {i+1}. {pkg.name} v{pkg.version} ({pkg.vendor})")
        
        if len(packages) > 5:
            print(f"   ... and {len(packages) - 5} more")
        
        print(f"\n✅ Test completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_windows_collector()
