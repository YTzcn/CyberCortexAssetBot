#!/usr/bin/env python3
"""
CyberCortexAssetBot Test Script

Bu script agent'ı test etmek için kullanılır.
"""

import subprocess
import sys
from pathlib import Path

def run_test():
    """Test'i çalıştır."""
    print("🧪 CyberCortexAssetBot Test Başlatılıyor...")
    print("=" * 50)
    
    # Python path'i ayarla
    src_path = Path(__file__).parent / "src"
    
    # Test komutları
    test_commands = [
        # Temel test - tüm asset türleri
        [sys.executable, "main.py"],
        
        # Sadece applications test
        [sys.executable, "main.py", "--types", "applications"],
        
        # Sadece packages test
        [sys.executable, "main.py", "--types", "packages"],
        
        # JSON dosyasına kaydet
        [sys.executable, "main.py", "--output", "test_results.json", "--pretty"],
    ]
    
    for i, cmd in enumerate(test_commands, 1):
        print(f"\n🔍 Test {i}: {' '.join(cmd[2:]) if len(cmd) > 2 else 'Tüm asset türleri'}")
        print("-" * 40)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ Test başarılı!")
                if result.stdout:
                    print("📄 Çıktı:")
                    print(result.stdout)
            else:
                print("❌ Test başarısız!")
                print("Hata:")
                print(result.stderr)
                
        except subprocess.TimeoutExpired:
            print("⏰ Test zaman aşımına uğradı (60 saniye)")
        except Exception as e:
            print(f"❌ Test hatası: {e}")
    
    print("\n🎉 Test tamamlandı!")

if __name__ == "__main__":
    run_test()
