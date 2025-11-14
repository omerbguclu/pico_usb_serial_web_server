import network
import time

def setup_access_point(ssid="POS-AP", password="12345678"):
    """
    WiFi Access Point modunda başlatır
    
    Args:
        ssid: WiFi ağ adı
        password: WiFi şifresi (en az 8 karakter)
    
    Returns:
        network.WLAN: WLAN instance
    """
    ap = network.WLAN(network.AP_IF)
    ap.active(True)
    ap.config(essid=ssid, password=password)
    
    # IP ayarları (opsiyonel)
    ap.ifconfig(('192.168.4.1', '255.255.255.0', '192.168.4.1', '192.168.4.1'))
    
    # Bağlantının kurulmasını bekle
    time.sleep(0.5)
    
    return ap

def get_ap_ip(ap):
    """Access Point'in IP adresini döndürür"""
    ifconfig = ap.ifconfig()
    return ifconfig[0] if ifconfig else "192.168.4.1"
