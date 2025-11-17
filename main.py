# -*- coding: utf-8 -*-

"""
Raspberry Pi Pico - POS USB Serial Web Server
MicroPython 1.26.1

USB serial üzerinden POS mesajları alır/gönderir
WiFi Access Point modunda web sunucusu açar
Tüm loglar web sunucusunda görüntülenir
"""

import machine
import uasyncio as asyncio
import sys
import uselect
from wifi_setup import setup_access_point, get_ap_ip
from web_server import start_web_server, add_log
from pos_handler import PosWithCable

try:
    from config import VERSION, WIFI_SSID, WIFI_PASSWORD, WEB_SERVER_PORT, DEBUG_MODE
except ImportError:
    # Varsayılan değerler
    VERSION = "1.0.0"
    WIFI_SSID = "POS-AP"
    WIFI_PASSWORD = "12345678"
    WEB_SERVER_PORT = 80

def print_banner():
    """Başlangıç banner'ı"""
    banner = """
╔═══════════════════════════════════════════════════════╗
║     POS USB Serial Web Server - Raspberry Pi Pico     ║
║                   Version {}                  ║
╚═══════════════════════════════════════════════════════╝
""".format(VERSION)
    if DEBUG_MODE:
        print(banner)
    add_log("=" * 60)
    add_log("POS USB Serial Web Server Başlatılıyor...")
    add_log("Versiyon: {}".format(VERSION))

async def main():
    """Ana fonksiyon"""
    try:
        print_banner()
        
        # 1. WiFi Access Point modunu başlat
        add_log("WiFi Access Point başlatılıyor...")
        try:
            ap = setup_access_point(ssid=WIFI_SSID, password=WIFI_PASSWORD)
            ap_ip = get_ap_ip(ap)
            add_log("WiFi AP hazır!")
            add_log("SSID: {}".format(WIFI_SSID))
            add_log("Şifre: {}".format(WIFI_PASSWORD))
            add_log("IP Adresi: {}".format(ap_ip))
            add_log("Web arayüzü: http://{}".format(ap_ip))
        except Exception as e:
            error_msg = "WiFi AP başlatma hatası: {}".format(str(e))
            add_log(error_msg)
            add_log("CYW43 modülü başlatılamadı. Lütfen cihazı yeniden başlatın.")
            # Hata durumunda da devam et (USB serial çalışabilir)
            ap = None
            ap_ip = "192.168.4.1"
        
        # 2. USB Serial (UART) başlat
        # Pico'da USB serial için machine.UART kullanılır
        # GPIO 0 (TX) ve GPIO 1 (RX) kullanılabilir
        # Veya USB CDC üzerinden direkt erişim için özel implementasyon gerekir
        
        # USB CDC Serial için wrapper sınıfı
        # Not: MicroPython'da USB CDC serial için özel kütüphane gerekebilir
        # Bu basit implementasyon ile başlıyoruz
        
        class USBUART:
            """USB Serial wrapper for MicroPython"""
            def __init__(self):
                # USB CDC için uselect kullan
                try:
                    self.poll = uselect.poll()
                    # sys.stdin için poll ekle
                    self.poll.register(sys.stdin, uselect.POLLIN)
                    self._has_poll = True
                except:
                    self._has_poll = False
                self._buffer = bytearray()
            
            def any(self):
                """Kullanılabilir byte sayısı"""
                if self._has_poll:
                    try:
                        # Poll ile kontrol et (non-blocking)
                        events = self.poll.poll(0)
                        if events:
                            return 1024  # En az bir byte var
                    except:
                        pass
                return 0
            
            def read(self, n):
                """n byte oku"""
                try:
                    if self._has_poll:
                        events = self.poll.poll(0)
                        if events:
                            # sys.stdin'den oku
                            data = sys.stdin.buffer.read(min(n, 1024))
                            if data:
                                return data
                except Exception as e:
                    pass
                return b''
            
            def write(self, data):
                """USB serial'e yaz"""
                try:
                    print("Gelen veri:", data)
                    if isinstance(data, bytes):
                        try:
                            data = data.decode('utf-8')
                        except Exception as e:
                            # UTF-8'e çevrilemeyen veriyi hex olarak göster
                            data = "<binary: {}>".format(data.hex())
                    print("1")
                    sys.stdout.write(str(data))
                    try:
                        sys.stdout.flush()
                    except AttributeError:
                        pass  # flush() yoksa geç
                    print("1")
                except Exception as e:
                    # add_log tanımlı değilse bile hatayı göster
                    print("USB yazma hatası:", repr(e))

        
        # Alternatif: GPIO UART kullan (USB yerine)
        # Eğer USB CDC çalışmazsa GPIO UART kullanılabilir
        try:
            # GPIO UART denemesi (opsiyonel)
            # uart = machine.UART(0, baudrate=115200, tx=machine.Pin(0), rx=machine.Pin(1))
            # add_log("GPIO UART başlatıldı")
            # pos = PosWithCable(uart)
            
            # USB Serial kullan
            uart = USBUART()
            pos = PosWithCable(uart)
            # Web sunucusuna pos handler instance'ını set et
            from web_server import set_pos_handler
            set_pos_handler(pos)
            add_log("USB Serial hazır (115200 baud)")
        except Exception as e:
            add_log("UART başlatma hatası: {}".format(str(e)))
            # Fallback
            uart = USBUART()
            pos = PosWithCable(uart)
        
        # 4. Asenkron görevleri başlat
        add_log("Asenkron görevler başlatılıyor...")
        
        # Web sunucusu görevini başlat (sadece WiFi başarılıysa)
        web_task = None
        if ap is not None:
            web_task = asyncio.create_task(start_web_server(WEB_SERVER_PORT))
        else:
            add_log("WiFi olmadığı için web sunucusu başlatılmıyor.")
        
        # USB serial okuma görevini başlat
        serial_task = asyncio.create_task(pos.read_loop())
        
        # Master mode: Her 1 saniyede bir POLL mesajı gönder
        poll_task = asyncio.create_task(pos.poll_loop())
        
        add_log("Sistem hazır! Web arayüzünden logları görüntüleyebilirsiniz.")
        add_log("Master mode aktif - Her 1 saniyede bir POLL mesajı gönderilecek.")
        add_log("=" * 60)
        
        # Tüm görevleri çalıştır (web_task None olabilir)
        tasks = [serial_task, poll_task]
        if web_task is not None:
            tasks.append(web_task)
        await asyncio.gather(*tasks)
        
    except KeyboardInterrupt:
        add_log("Program kullanıcı tarafından durduruldu")
    except Exception as e:
        add_log("Kritik hata: {}".format(str(e)))
        import sys
        sys.print_exception(e)

# Program başlat
if __name__ == "__main__":
    while True:
        try:
            asyncio.run(main())
        except Exception as e:
            if DEBUG_MODE:
                print("Başlatma hatası:", e)
            import sys
            sys.print_exception(e)
