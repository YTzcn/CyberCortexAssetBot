# CyberCortexAssetBot

Platform bağımsız, modüler ve güvenilir asset toplama ajanı. Windows, Linux ve macOS üzerinde çalışabilir.

## 🚀 Özellikler

- **Platform Bağımsızlık**: Windows, Linux, macOS desteği
- **Modüler Yapı**: Her platform için ayrı collector modülleri
- **Kapsamlı Veri Toplama**: 
  - Sürücüler (Drivers)
  - Uygulamalar (Applications)
  - Servisler (Services)
  - Kütüphaneler (Libraries)
  - Paketler (Packages)
  - Konteynerler (Containers)
- **Python 3.11**: Modern Python özellikleri
- **JSON Çıktısı**: Standart veri formatı

## 📋 Gereksinimler

- Python 3.11+
- Platform-specific bağımlılıklar (opsiyonel)

## 🛠️ Kurulum

1. Repository'yi klonlayın:
```bash
git clone <repository-url>
cd CyberCortexAssetBot
```

2. Virtual environment oluşturun:
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# veya
venv\Scripts\activate  # Windows
```

3. Bağımlılıkları yükleyin:
```bash
pip install -r requirements.txt
```

## 🎯 Kullanım

### Temel Kullanım

Tüm asset türlerini topla:
```bash
python src/main.py
```

### Belirli Asset Türlerini Topla

Sadece uygulamaları topla:
```bash
python src/main.py --types applications
```

Birden fazla tür:
```bash
python src/main.py --types applications packages services
```

### JSON Dosyasına Kaydet

```bash
python src/main.py --output results.json --pretty
```

### Test Et

```bash
python test_agent.py
```

## 📊 Desteklenen Asset Türleri

| Tür | Açıklama |
|-----|----------|
| `drivers` | Sürücüler ve kernel modülleri |
| `applications` | Yüklü uygulamalar |
| `services` | Sistem servisleri |
| `libraries` | Sistem kütüphaneleri |
| `packages` | Programlama dili paketleri |
| `containers` | Konteyner görüntüleri |

## 🖥️ Platform Desteği

### Linux
- Package managers: APT, YUM, DNF, Pacman, Flatpak, Snap
- Services: systemd, init.d
- Containers: Docker, Podman, LXC

### Windows
- WMI integration
- Registry access
- PowerShell commands
- Package managers: Chocolatey, Scoop, NuGet

### macOS
- Kernel extensions
- Launchd services
- Package managers: Homebrew, MAS
- Containers: Docker, Podman, Lima

## 📁 Proje Yapısı

```
CyberCortexAssetBot/
├── src/
│   ├── main.py                 # Ana agent
│   ├── collectors/             # Platform-specific collectors
│   ├── utils/                  # Yardımcı araçlar
│   └── ...
├── config/                     # Konfigürasyon dosyaları
├── tests/                      # Test dosyaları
├── requirements.txt            # Python bağımlılıkları
└── README.md
```

## 🔧 Geliştirme

### Test Çalıştırma

```bash
python test_agent.py
```

### Linting

```bash
mypy src/
```

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push yapın (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun
