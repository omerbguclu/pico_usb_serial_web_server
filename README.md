# Raspberry Pi Pico - POS USB Serial Web Server

MicroPython 1.26.1 ile Raspberry Pi Pico için POS USB Serial Web Server projesi.

## Özellikler

- ✅ USB Serial üzerinden POS mesajları alır/gönderir
- ✅ AES şifreleme/çözme (ECB modu)
- ✅ WiFi Access Point modu
- ✅ Web sunucusu ile log görüntüleme
- ✅ Otomatik POS protokol akışı (GUI olmadan)

## Gereksinimler

- Raspberry Pi Pico **W** (WiFi dahili) veya Pico + harici WiFi modülü
- MicroPython 1.26.1
- USB kablosu (USB serial iletişim için)

**Not:** Bu proje Pico W için optimize edilmiştir. Standart Pico için harici WiFi modülü gerekir.

## Kurulum

1. MicroPython 1.26.1'i Pico'ya yükleyin:
   - [MicroPython İndirme Sayfası](https://micropython.org/download/rp2-pico-w/)
   - Pico W için özel firmware indirin
   - Pico'yu BOOTSEL moduna alın (BOOT butonuna basılı tutup USB'ye bağlayın)
   - İndirdiğiniz `.uf2` dosyasını Pico'ya kopyalayın

2. Tüm `.py` dosyalarını Pico'ya kopyalayın:
   - `main.py` (zorunlu - ana program)
   - `pos_protocol.py` (zorunlu)
   - `pos_handler.py` (zorunlu)
   - `wifi_setup.py` (zorunlu)
   - `web_server.py` (zorunlu)
   - `config.py` (opsiyonel - yoksa varsayılan değerler kullanılır)

   **Kopyalama yöntemi:**
   - Thonny IDE kullanarak dosyaları yükleyebilirsiniz
   - Veya `mpremote` komut satırı aracını kullanabilirsiniz:
     ```bash
     mpremote cp main.py :main.py
     mpremote cp pos_protocol.py :pos_protocol.py
     # ... diğer dosyalar için de aynı şekilde
     ```

3. Pico'yu yeniden başlatın (RST butonuna basın veya USB'yi çıkarıp takın)

## Kullanım

1. Pico başladığında WiFi Access Point oluşturulur:
   - SSID: `POS-AP`
   - Şifre: `12345678`
   - IP: `192.168.4.1`

2. Tarayıcınızdan `http://192.168.4.1` adresine bağlanın

3. Web arayüzünden tüm logları görüntüleyebilirsiniz

4. USB Serial üzerinden POS mesajları otomatik olarak işlenir

## Dosya Yapısı

- `main.py` - Ana program giriş noktası
- `pos_protocol.py` - POS protokol sınıfları (AES, CRC8, framing)
- `pos_handler.py` - POS mesaj işleme ve otomatik yanıt verme
- `wifi_setup.py` - WiFi Access Point kurulumu
- `web_server.py` - Web sunucusu ve log yönetimi

## Notlar

- USB Serial için Pico'nun USB CDC desteği kullanılır (sys.stdin/stdout)
- Loglar web sunucusunda otomatik yenilenir (5 saniye)
- Maksimum 1000 log saklanır
- POS protokolü otomatik olarak yanıt verir (GUI gerektirmez)
- WiFi SSID ve şifresini `wifi_setup.py` içinden değiştirebilirsiniz
- Payload'ları `pos_handler.py` içinden özelleştirebilirsiniz

## Mesaj Tipleri

- `POLL` (0x66) - Durum sorgulama
- `PRINT` (0x67) - Yazdırma
- `PAYMENT_START` (0x68) - Ödeme başlatma
- `PAYMENT_INFO` (0x69) - Ödeme bilgisi
- `SETTLEMENT_START` (0x6A) - Günsonu başlatma
- `SETTLEMENT_INFO` (0x6B) - Günsonu bilgisi
- `PAYMENT_FAILED` (0x6C) - Ödeme hatası
- `DEVICE_INFO` (0x6D) - Cihaz bilgisi

## Lisans

Bu proje örnek amaçlıdır.
