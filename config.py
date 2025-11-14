"""
Konfigürasyon dosyası
WiFi ve sistem ayarlarını buradan değiştirebilirsiniz
"""

# WiFi Access Point Ayarları
WIFI_SSID = "POS-AP"
WIFI_PASSWORD = "12345678"
WIFI_IP = "192.168.4.1"
WIFI_SUBNET = "255.255.255.0"
WIFI_GATEWAY = "192.168.4.1"
WIFI_DNS = "192.168.4.1"

# Web Sunucu Ayarları
WEB_SERVER_PORT = 80
WEB_AUTO_REFRESH_SECONDS = 5  # Log otomatik yenileme süresi
MAX_LOGS = 1000  # Maksimum saklanacak log sayısı

# USB Serial Ayarları
SERIAL_BAUDRATE = 115200
SERIAL_TIMEOUT_MS = 10

# AES Şifreleme Ayarları
# AES_KEY_CR pos_protocol.py içinde tanımlı

# Sistem Ayarları
VERSION = "1.0.0"
LOG_TIMESTAMP_FORMAT = "relative"  # "relative" veya "absolute"
