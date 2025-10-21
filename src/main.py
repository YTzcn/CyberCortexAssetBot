#!/usr/bin/env python3
"""
CyberCortexAssetBot - Main Agent

Test için basit bir main agent implementasyonu.
Platform tespiti yapar ve uygun collector'ı kullanarak asset toplama işlemi gerçekleştirir.
"""

import json
import sys
from pathlib import Path
from typing import Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from utils.platform_detector import get_current_platform, is_supported_platform
from collectors.linux_collector import LinuxCollector
from collectors.windows_collector import WindowsCollector
from collectors.macos_collector import MacOSCollector
from collectors.base_collector import AssetType


def get_collector():
    """
    Platform'a göre uygun collector'ı döndürür.
    
    Returns:
        Uygun collector instance
    """
    platform_info = get_current_platform()
    
    match platform_info.platform_type.value:
        case "linux":
            return LinuxCollector(platform_info)
        case "windows":
            return WindowsCollector(platform_info)
        case "macos":
            return MacOSCollector(platform_info)
        case _:
            raise RuntimeError(f"Desteklenmeyen platform: {platform_info.platform_type.value}")


def collect_assets(asset_types: Optional[list[str]] = None) -> dict:
    """
    Asset toplama işlemini gerçekleştirir.
    
    Args:
        asset_types: Toplanacak asset türleri. None ise tüm türler toplanır.
        
    Returns:
        Toplanan asset verileri
    """
    print("🔍 CyberCortexAssetBot - Asset Collection Agent")
    print("=" * 50)
    
    # Platform kontrolü
    if not is_supported_platform():
        print("❌ Hata: Desteklenmeyen platform!")
        return {}
    
    platform_info = get_current_platform()
    print(f"🖥️  Platform: {platform_info.get_platform_string()}")
    print(f"🐍 Python: {platform_info.python_version}")
    print()
    
    try:
        # Collector'ı al
        collector = get_collector()
        print(f"✅ {collector.__class__.__name__} yüklendi")
        
        # Asset türlerini belirle
        if asset_types:
            # String'leri AssetType enum'una çevir
            asset_type_enums = []
            for asset_type_str in asset_types:
                try:
                    asset_type_enums.append(AssetType(asset_type_str))
                except ValueError:
                    print(f"⚠️  Geçersiz asset türü: {asset_type_str}")
            result = collector.collect_specific(asset_type_enums)
        else:
            # Tüm asset türlerini topla
            result = collector.collect_all()
        
        print(f"⏱️  Toplama süresi: {result.collection_duration:.2f} saniye")
        print(f"✅ Başarılı: {result.success}")
        
        if result.errors:
            print(f"⚠️  Hatalar ({len(result.errors)}):")
            for error in result.errors:
                print(f"   - {error}")
        
        print()
        
        # Sonuçları göster
        total_assets = sum(len(assets) for assets in result.assets.values())
        print(f"📊 Toplam {total_assets} asset toplandı:")
        
        for asset_type, assets in result.assets.items():
            if assets:
                print(f"   {asset_type.value}: {len(assets)} adet")
        
        return result.to_dict()
        
    except Exception as e:
        print(f"❌ Hata: {str(e)}")
        return {}


def main():
    """Ana fonksiyon."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberCortexAssetBot - Asset Collection Agent")
    parser.add_argument(
        "--types", 
        nargs="+", 
        choices=[t.value for t in AssetType],
        help="Toplanacak asset türleri (varsayılan: tümü)"
    )
    parser.add_argument(
        "--output", 
        type=str, 
        help="Sonuçları JSON dosyasına kaydet"
    )
    parser.add_argument(
        "--pretty", 
        action="store_true", 
        help="JSON çıktısını güzel formatla"
    )
    
    args = parser.parse_args()
    
    # Asset toplama
    result = collect_assets(args.types)
    
    if not result:
        sys.exit(1)
    
    # JSON çıktısı
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w', encoding='utf-8') as f:
            if args.pretty:
                json.dump(result, f, indent=2, ensure_ascii=False)
            else:
                json.dump(result, f, ensure_ascii=False)
        print(f"💾 Sonuçlar kaydedildi: {output_path}")
    else:
        # Konsola JSON yazdır
        print("\n📄 JSON Çıktısı:")
        print("-" * 30)
        if args.pretty:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
