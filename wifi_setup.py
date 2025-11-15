import network
import time

try:
    from config import DEBUG_MODE
except ImportError:
    DEBUG_MODE = False

def setup_access_point(ssid="POS-AP", password="12345678", max_retries=5):
    """
    WiFi Access Point modunda başlatır
    
    Args:
        ssid: WiFi ağ adı
        password: WiFi şifresi (en az 8 karakter)
        max_retries: Maksimum deneme sayısı
    
    Returns:
        network.WLAN: WLAN instance
    """
    # CYW43'in başlatılması için önce bir bekleme
    time.sleep(0.1)
    
    for attempt in range(max_retries):
        try:
            # WiFi modülünü başlat
            ap = network.WLAN(network.AP_IF)
            
            # Önce aktif hale getir
            ap.active(False)  # Önce kapat
            time.sleep(0.2)
            ap.active(True)   # Sonra aç
            
            # CYW43'in hazır olmasını bekle
            time.sleep(0.5)
            
            # AP yapılandırması
            ap.config(essid=ssid, password=password)
            
            # IP ayarları
            ap.ifconfig(('192.168.4.1', '255.255.255.0', '192.168.4.1', '192.168.4.1'))
            
            # Bağlantının kurulmasını bekle
            time.sleep(0.5)
            
            # Başarılı olduğunu kontrol et
            if ap.active():
                return ap
            else:
                if attempt < max_retries - 1:
                    time.sleep(1)  # Tekrar denemeden önce bekle
                    continue
                else:
                    raise Exception("WiFi AP aktif hale getirilemedi")
                    
        except Exception as e:
            if attempt < max_retries - 1:
                if DEBUG_MODE:
                    print("WiFi AP başlatma hatası (deneme {}/{}): {}".format(attempt + 1, max_retries, str(e)))
                time.sleep(1)
                continue
            else:
                raise Exception("WiFi AP başlatılamadı: {}".format(str(e)))
    
    raise Exception("WiFi AP başlatılamadı ({} deneme sonrası)".format(max_retries))

def get_ap_ip(ap):
    """Access Point'in IP adresini döndürür"""
    ifconfig = ap.ifconfig()
    return ifconfig[0] if ifconfig else "192.168.4.1"
