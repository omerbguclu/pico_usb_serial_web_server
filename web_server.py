import uasyncio as asyncio
from pos_protocol import PosCableMessageType, get_enum_name

# Global log listesi
logs = []

# Global pos handler instance (main.py'den set edilecek)
pos_handler_instance = None

def set_pos_handler(pos_handler):
    """Pos handler instance'ını set et"""
    global pos_handler_instance
    pos_handler_instance = pos_handler

try:
    from config import MAX_LOGS, MAX_DISPLAY_LOGS, WEB_AUTO_REFRESH_SECONDS, SITE_NAME, DEBUG_MODE
except ImportError:
    MAX_LOGS = 500
    MAX_DISPLAY_LOGS = 200
    WEB_AUTO_REFRESH_SECONDS = 5
    SITE_NAME = "POS Serial Monitor"
    DEBUG_MODE = False

def add_log(message, category="UART"):
    """
    Yeni log ekle
    category: "UART" veya "HTTP"
    """
    try:
        # Sadece DEBUG_MODE aktifse print yap (USB'ye yazma)
        if DEBUG_MODE:
            print(message)
        
        import time
        timestamp = time.ticks_ms()
        
        # Mesajı kısalt (bellek tasarrufu)
        msg_str = str(message)
        if len(msg_str) > 200:  # Mesajı 200 karakter ile sınırla
            msg_str = msg_str[:200] + "..."
        
        log_entry = {
            "time": timestamp,
            "message": msg_str,
            "category": category
        }
        logs.append(log_entry)
        
        # Eski logları temizle (bellek tasarrufu için daha agresif)
        while len(logs) > MAX_LOGS:
            logs.pop(0)
            
    except MemoryError:
        # Bellek hatası durumunda en eski logları temizle
        try:
            # Yarısını sil
            remove_count = len(logs) // 2
            for _ in range(remove_count):
                if logs:
                    logs.pop(0)
        except:
            # Hala hata varsa tüm logları temizle
            logs.clear()
    except Exception:
        # Diğer hataları sessizce geç (log ekleyemezsek sistem çalışmaya devam etsin)
        pass

def get_logs_html():
    """Logları HTML formatında döndür"""
    import time
    
    # HTML header
    html = "<!DOCTYPE html>\n"
    html += "<html>\n"
    html += "<head>\n"
    html += "    <meta charset=\"UTF-8\">\n"
    html += "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
    html += "    <title>" + SITE_NAME + "</title>\n"
    html += "    <style>\n"
    html += "        body {\n"
    html += "            font-family: monospace;\n"
    html += "            margin: 0;\n"
    html += "            padding: 20px;\n"
    html += "            background-color: #1e1e1e;\n"
    html += "            color: #d4d4d4;\n"
    html += "        }\n"
    html += "        h1 {\n"
    html += "            color: #4ec9b0;\n"
    html += "            border-bottom: 2px solid #4ec9b0;\n"
    html += "            padding-bottom: 10px;\n"
    html += "        }\n"
    html += "        .stats {\n"
    html += "            background-color: #252526;\n"
    html += "            padding: 15px;\n"
    html += "            border-radius: 5px;\n"
    html += "            margin-bottom: 20px;\n"
    html += "        }\n"
    html += "        .stats div {\n"
    html += "            margin: 5px 0;\n"
    html += "        }\n"
    html += "        .log-container {\n"
    html += "            background-color: #252526;\n"
    html += "            padding: 15px;\n"
    html += "            border-radius: 5px;\n"
    html += "            max-height: 70vh;\n"
    html += "            overflow-y: auto;\n"
    html += "            display: flex;\n"
    html += "            flex-direction: column;\n"
    html += "        }\n"
    html += "        .log-entry {\n"
    html += "            padding: 5px;\n"
    html += "            border-bottom: 1px solid #3e3e42;\n"
    html += "            word-wrap: break-word;\n"
    html += "        }\n"
    html += "        .log-entry:last-child {\n"
    html += "            border-bottom: none;\n"
    html += "        }\n"
    html += "        .log-time {\n"
    html += "            color: #858585;\n"
    html += "            margin-right: 10px;\n"
    html += "        }\n"
    html += "        .log-message {\n"
    html += "            color: #d4d4d4;\n"
    html += "        }\n"
    html += "        .error {\n"
    html += "            color: #f48771;\n"
    html += "        }\n"
    html += "        .success {\n"
    html += "            color: #4ec9b0;\n"
    html += "        }\n"
    html += "        .warning {\n"
    html += "            color: #dcdcaa;\n"
    html += "        }\n"
    html += "        button {\n"
    html += "            background-color: #0e639c;\n"
    html += "            color: white;\n"
    html += "            border: none;\n"
    html += "            padding: 10px 20px;\n"
    html += "            border-radius: 5px;\n"
    html += "            cursor: pointer;\n"
    html += "            margin: 5px;\n"
    html += "        }\n"
    html += "        button:hover {\n"
    html += "            background-color: #1177bb;\n"
    html += "        }\n"
    html += "        .tabs {\n"
    html += "            display: flex;\n"
    html += "            margin-bottom: 10px;\n"
    html += "            border-bottom: 2px solid #3e3e42;\n"
    html += "        }\n"
    html += "        .tab-button {\n"
    html += "            background-color: #252526;\n"
    html += "            color: #858585;\n"
    html += "            border: none;\n"
    html += "            padding: 12px 24px;\n"
    html += "            cursor: pointer;\n"
    html += "            font-size: 14px;\n"
    html += "            border-bottom: 2px solid transparent;\n"
    html += "            margin-bottom: -2px;\n"
    html += "            transition: all 0.2s;\n"
    html += "        }\n"
    html += "        .tab-button:hover {\n"
    html += "            background-color: #2d2d30;\n"
    html += "            color: #d4d4d4;\n"
    html += "        }\n"
    html += "        .tab-button.active {\n"
    html += "            background-color: #1e1e1e;\n"
    html += "            color: #4ec9b0;\n"
    html += "            border-bottom: 2px solid #4ec9b0;\n"
    html += "        }\n"
    html += "        .tab-content {\n"
    html += "            display: none;\n"
    html += "        }\n"
    html += "        .tab-content.active {\n"
    html += "            display: block;\n"
    html += "        }\n"
    html += "        .log-entry.hidden {\n"
    html += "            display: none;\n"
    html += "        }\n"
    html += "        .connection-status {\n"
    html += "            display: inline-block;\n"
    html += "            width: 20px;\n"
    html += "            height: 20px;\n"
    html += "            border-radius: 50%;\n"
    html += "            margin-left: 10px;\n"
    html += "            vertical-align: middle;\n"
    html += "        }\n"
    html += "        .connection-status.connected {\n"
    html += "            background-color: #4ec9b0;\n"
    html += "        }\n"
    html += "        .connection-status.disconnected {\n"
    html += "            background-color: #f48771;\n"
    html += "        }\n"
    html += "        .message-controls {\n"
    html += "            background-color: #252526;\n"
    html += "            padding: 15px;\n"
    html += "            border-radius: 5px;\n"
    html += "            margin-bottom: 20px;\n"
    html += "        }\n"
    html += "        .message-control {\n"
    html += "            margin-bottom: 15px;\n"
    html += "            padding: 10px;\n"
    html += "            background-color: #1e1e1e;\n"
    html += "            border-radius: 3px;\n"
    html += "        }\n"
    html += "        .message-control button {\n"
    html += "            margin-right: 10px;\n"
    html += "            min-width: 150px;\n"
    html += "        }\n"
    html += "        .message-control textarea {\n"
    html += "            width: 100%;\n"
    html += "            min-height: 60px;\n"
    html += "            background-color: #252526;\n"
    html += "            color: #d4d4d4;\n"
    html += "            border: 1px solid #3e3e42;\n"
    html += "            border-radius: 3px;\n"
    html += "            padding: 8px;\n"
    html += "            font-family: monospace;\n"
    html += "            font-size: 12px;\n"
    html += "            margin-top: 5px;\n"
    html += "        }\n"
    html += "    </style>\n"
    html += "</head>\n"
    html += "<body>\n"
    html += "    <h1>" + SITE_NAME + "</h1>\n"
    html += "    \n"
    # Log sayılarını hesapla (bellek tasarrufu için sadece bir kez)
    uart_count = len([l for l in logs if l.get("category", "UART") == "UART"])
    http_count = len([l for l in logs if l.get("category") == "HTTP"])
    
    html += "    <div class=\"stats\">\n"
    html += "        <div><strong>Toplam Log:</strong> <span id=\"log-count\">" + str(len(logs)) + "</span></div>\n"
    html += "        <div><strong>UART Log:</strong> <span id=\"uart-count\">" + str(uart_count) + "</span> (gösterilen: " + str(min(uart_count, MAX_DISPLAY_LOGS)) + ")</div>\n"
    html += "        <div><strong>HTTP Log:</strong> <span id=\"http-count\">" + str(http_count) + "</span> (gösterilen: " + str(min(http_count, MAX_DISPLAY_LOGS)) + ")</div>\n"
    html += "        <div><strong>Bağlantı:</strong> <span id=\"connection-status-text\">Kontrol ediliyor...</span> <span class=\"connection-status disconnected\" id=\"connection-status\"></span></div>\n"
    html += "        <div><strong>Durum:</strong> <span class=\"success\">Calisiyor</span></div>\n"
    html += "        <button onclick=\"location.reload()\">Yenile</button>\n"
    html += "        <button onclick=\"clearLogs()\">Loglari Temizle</button>\n"
    html += "    </div>\n"
    html += "    \n"
    html += "    <div class=\"message-controls\">\n"
    html += "        <h2>Mesaj Kontrolü</h2>\n"
    
    # Mesaj türleri için butonlar ve text alanları
    message_types = [
        ("ACK", PosCableMessageType.ACK),
        ("NACK", PosCableMessageType.NACK),
        ("POLL", PosCableMessageType.POLL),
        ("PRINT", PosCableMessageType.PRINT),
        ("PAYMENT_START", PosCableMessageType.PAYMENT_START),
        ("PAYMENT_INFO", PosCableMessageType.PAYMENT_INFO),
        ("SETTLEMENT_START", PosCableMessageType.SETTLEMENT_START),
        ("SETTLEMENT_INFO", PosCableMessageType.SETTLEMENT_INFO),
        ("PAYMENT_FAILED", PosCableMessageType.PAYMENT_FAILED),
        ("DEVICE_INFO", PosCableMessageType.DEVICE_INFO),
    ]
    
    for msg_name, msg_type in message_types:
        default_payload = ""
        if pos_handler_instance and msg_type in pos_handler_instance.payloads:
            default_payload = pos_handler_instance.payloads[msg_type]
        
        html += "        <div class=\"message-control\">\n"
        html += "            <button onclick=\"updatePayload('{}')\">{} Payload Güncelle</button>\n".format(msg_name, msg_name)
        html += "            <textarea id=\"payload-{}\" placeholder=\"{} payload JSON...\">{}</textarea>\n".format(msg_name, msg_name, default_payload)
        html += "        </div>\n"
    
    html += "    </div>\n"
    html += "    \n"
    html += "    <div class=\"tabs\">\n"
    html += "        <button class=\"tab-button active\" onclick=\"switchTab('uart')\" id=\"tab-uart\">UART Logları</button>\n"
    html += "        <button class=\"tab-button\" onclick=\"switchTab('http')\" id=\"tab-http\">HTTP Logları</button>\n"
    html += "    </div>\n"
    html += "    \n"
    html += "    <div class=\"tab-content active\" id=\"tab-content-uart\">\n"
    html += "        <div class=\"log-container\" id=\"log-container-uart\">\n"
    
    # UART logları (sadece son N log'u göster - bellek tasarrufu)
    uart_logs = [l for l in logs if l.get("category", "UART") == "UART"]
    # Son MAX_DISPLAY_LOGS kadarını al
    uart_logs = uart_logs[-MAX_DISPLAY_LOGS:] if len(uart_logs) > MAX_DISPLAY_LOGS else uart_logs
    for log in uart_logs:
        elapsed = time.ticks_ms() - log["time"]
        elapsed_sec = elapsed / 1000
        
        # Mesajı HTML'den temizle ve uzunluğunu sınırla (bellek tasarrufu)
        msg = str(log["message"])
        # Mesaj uzunluğunu 500 karakter ile sınırla
        if len(msg) > 500:
            msg = msg[:500] + "... (kesildi)"
        msg = msg.replace('<', '&lt;')
        msg = msg.replace('>', '&gt;')
        msg = msg.replace('&', '&amp;')
        msg = msg.replace('"', '&quot;')
        
        html += "            <div class=\"log-entry\" data-category=\"UART\">\n"
        html += "                <span class=\"log-time\">+" + "{:.3f}".format(elapsed_sec) + "s</span>\n"
        html += "                <span class=\"log-message\">" + msg + "</span>\n"
        html += "            </div>\n"
    
        html += "        </div>\n"
    html += "    </div>\n"
    html += "    \n"
    html += "    <div class=\"tab-content\" id=\"tab-content-http\">\n"
    html += "        <div class=\"log-container\" id=\"log-container-http\">\n"
    
    # HTTP logları (sadece son N log'u göster - bellek tasarrufu)
    http_logs = [l for l in logs if l.get("category") == "HTTP"]
    # Son MAX_DISPLAY_LOGS kadarını al
    http_logs = http_logs[-MAX_DISPLAY_LOGS:] if len(http_logs) > MAX_DISPLAY_LOGS else http_logs
    for log in http_logs:
        elapsed = time.ticks_ms() - log["time"]
        elapsed_sec = elapsed / 1000
        
        # Mesajı HTML'den temizle ve uzunluğunu sınırla (bellek tasarrufu)
        msg = str(log["message"])
        # Mesaj uzunluğunu 500 karakter ile sınırla
        if len(msg) > 500:
            msg = msg[:500] + "... (kesildi)"
        msg = msg.replace('<', '&lt;')
        msg = msg.replace('>', '&gt;')
        msg = msg.replace('&', '&amp;')
        msg = msg.replace('"', '&quot;')
        
        html += "            <div class=\"log-entry\" data-category=\"HTTP\">\n"
        html += "                <span class=\"log-time\">+" + "{:.3f}".format(elapsed_sec) + "s</span>\n"
        html += "                <span class=\"log-message\">" + msg + "</span>\n"
        html += "            </div>\n"
    
    html += "        </div>\n"
    html += "    </div>\n"
    html += "    \n"
    html += "    <script>\n"
    html += "        var currentLogCount = " + str(len(logs)) + ";\n"
    html += "        var autoRefreshInterval = null;\n"
    html += "        \n"
    html += "        function clearLogs() {\n"
    html += "            if (confirm('Loglari temizlemek istediginize emin misiniz?')) {\n"
    html += "                fetch('/clear', {method: 'POST'}).then(function() { location.reload(); });\n"
    html += "            }\n"
    html += "        }\n"
    html += "        \n"
    html += "        var lastLogCount = " + str(len(logs)) + ";\n"
    html += "        \n"
    html += "        function addLogEntry(log, containerId) {\n"
    html += "            var container = document.getElementById(containerId);\n"
    html += "            if (!container) return;\n"
    html += "            \n"
    html += "            var entry = document.createElement('div');\n"
    html += "            entry.className = 'log-entry';\n"
    html += "            entry.setAttribute('data-category', log.category);\n"
    html += "            entry.innerHTML = '<span class=\"log-time\">+' + log.time + 's</span><span class=\"log-message\">' + log.message + '</span>';\n"
    html += "            container.appendChild(entry);\n"
    html += "            scrollToBottom();\n"
    html += "        }\n"
    html += "        \n"
    html += "        function checkForNewLogs() {\n"
    html += "            fetch('/api/logs/new?last_count=' + lastLogCount, {\n"
    html += "                method: 'GET',\n"
    html += "                cache: 'no-cache'\n"
    html += "            })\n"
    html += "                .then(function(response) {\n"
    html += "                    if (!response.ok) {\n"
    html += "                        throw new Error('HTTP ' + response.status);\n"
    html += "                    }\n"
    html += "                    return response.json();\n"
    html += "                })\n"
    html += "                .then(function(data) {\n"
    html += "                    if (data.logs && data.logs.length > 0) {\n"
    html += "                        data.logs.forEach(function(log) {\n"
    html += "                            if (log.category === 'UART') {\n"
    html += "                                addLogEntry(log, 'log-container-uart');\n"
    html += "                            } else if (log.category === 'HTTP') {\n"
    html += "                                addLogEntry(log, 'log-container-http');\n"
    html += "                            }\n"
    html += "                        });\n"
    html += "                        lastLogCount = data.count;\n"
    html += "                        document.getElementById('log-count').textContent = data.count;\n"
    html += "                    }\n"
    html += "                })\n"
    html += "                .catch(function(error) {\n"
    html += "                    console.error('Log kontrol hatası:', error);\n"
    html += "                });\n"
    html += "        }\n"
    html += "        \n"
    html += "        function checkConnectionStatus() {\n"
    html += "            fetch('/api/status', {\n"
    html += "                method: 'GET',\n"
    html += "                cache: 'no-cache'\n"
    html += "            })\n"
    html += "                .then(function(response) { return response.json(); })\n"
    html += "                .then(function(data) {\n"
    html += "                    var statusEl = document.getElementById('connection-status');\n"
    html += "                    var textEl = document.getElementById('connection-status-text');\n"
    html += "                    if (data.connected) {\n"
    html += "                        statusEl.className = 'connection-status connected';\n"
    html += "                        textEl.textContent = 'Bağlı';\n"
    html += "                    } else {\n"
    html += "                        statusEl.className = 'connection-status disconnected';\n"
    html += "                        textEl.textContent = 'Bağlantı Yok';\n"
    html += "                    }\n"
    html += "                })\n"
    html += "                .catch(function(error) {\n"
    html += "                    console.error('Bağlantı durumu kontrol hatası:', error);\n"
    html += "                });\n"
    html += "        }\n"
    html += "        \n"
    html += "        function updatePayload(msgType) {\n"
    html += "            var textarea = document.getElementById('payload-' + msgType);\n"
    html += "            var payload = textarea.value.trim();\n"
    html += "            \n"
    html += "            fetch('/api/payload', {\n"
    html += "                method: 'POST',\n"
    html += "                headers: {'Content-Type': 'application/json'},\n"
    html += "                body: JSON.stringify({msg_type: msgType, payload: payload})\n"
    html += "            })\n"
    html += "                .then(function(response) {\n"
    html += "                    if (response.ok) {\n"
    html += "                        alert('Payload güncellendi: ' + msgType);\n"
    html += "                    } else {\n"
    html += "                        alert('Hata: Payload güncellenemedi');\n"
    html += "                    }\n"
    html += "                })\n"
    html += "                .catch(function(error) {\n"
    html += "                    console.error('Payload güncelleme hatası:', error);\n"
    html += "                    alert('Hata: ' + error);\n"
    html += "                });\n"
    html += "        }\n"
    html += "        \n"
    html += "        // Tab değiştirme\n"
    html += "        var currentTab = 'uart';\n"
    html += "        function switchTab(tab) {\n"
    html += "            currentTab = tab;\n"
    html += "            // Tab butonlarını güncelle\n"
    html += "            document.getElementById('tab-uart').classList.remove('active');\n"
    html += "            document.getElementById('tab-http').classList.remove('active');\n"
    html += "            document.getElementById('tab-' + tab).classList.add('active');\n"
    html += "            // Tab içeriklerini güncelle\n"
    html += "            document.getElementById('tab-content-uart').classList.remove('active');\n"
    html += "            document.getElementById('tab-content-http').classList.remove('active');\n"
    html += "            document.getElementById('tab-content-' + tab).classList.add('active');\n"
    html += "            // Scroll et\n"
    html += "            setTimeout(scrollToBottom, 100);\n"
    html += "        }\n"
    html += "        \n"
    html += "        // Log container'ı en alta scroll et\n"
    html += "        function scrollToBottom() {\n"
    html += "            var containerId = 'log-container-' + currentTab;\n"
    html += "            var container = document.getElementById(containerId);\n"
    html += "            if (container) {\n"
    html += "                container.scrollTop = container.scrollHeight;\n"
    html += "            }\n"
    html += "        }\n"
    html += "        \n"
    html += "        // Otomatik yenileme başlat\n"
    html += "        function startAutoRefresh() {\n"
    html += "            if (autoRefreshInterval) {\n"
    html += "                clearInterval(autoRefreshInterval);\n"
    html += "            }\n"
    html += "            // Her " + str(WEB_AUTO_REFRESH_SECONDS) + " saniyede bir kontrol et\n"
    html += "            autoRefreshInterval = setInterval(checkForNewLogs, " + str(WEB_AUTO_REFRESH_SECONDS * 1000) + ");\n"
    html += "            // Bağlantı durumunu her 2 saniyede bir kontrol et\n"
    html += "            setInterval(checkConnectionStatus, 2000);\n"
    html += "        }\n"
    html += "        \n"
    html += "        // Sayfa yüklendiğinde otomatik yenilemeyi başlat ve scroll et\n"
    html += "        function initializePage() {\n"
    html += "            startAutoRefresh();\n"
    html += "            // İlk bağlantı durumu kontrolü\n"
    html += "            checkConnectionStatus();\n"
    html += "            // Sayfa yüklendiğinde en alta scroll et\n"
    html += "            setTimeout(scrollToBottom, 100);\n"
    html += "        }\n"
    html += "        \n"
    html += "        // DOM yüklendiğinde hemen başlat\n"
    html += "        if (document.readyState === 'loading') {\n"
    html += "            document.addEventListener('DOMContentLoaded', initializePage);\n"
    html += "        } else {\n"
    html += "            initializePage();\n"
    html += "        }\n"
    html += "        // İlk kontrolü hemen yap\n"
    html += "        setTimeout(checkForNewLogs, 1000);\n"
    html += "    </script>\n"
    html += "</body>\n"
    html += "</html>"
    
    return html

async def handle_client(reader, writer):
    """Web sunucusu istemci handler - hata durumunda bile çalışmaya devam eder"""
    try:
        request = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        if not request:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return
        
        # İstek geldiğinde log bas (sadece ana sayfa için, API istekleri için log basma)
        # API istekleri için gereksiz log spam'ini önlemek için
        
        # Önce spesifik endpoint'leri kontrol et (sıra önemli!)
        if b'GET /api/logs/count' in request or b'GET /api/logs/count HTTP' in request:
            # Log sayısını döndür (AJAX için)
            try:
                count = str(len(logs))
                response = 'HTTP/1.1 200 OK\r\n'
                response += 'Content-Type: text/plain; charset=utf-8\r\n'
                response += 'Content-Length: ' + str(len(count)) + '\r\n'
                response += 'Cache-Control: no-cache\r\n'
                response += 'Access-Control-Allow-Origin: *\r\n'
                response += 'Connection: close\r\n'
                response += '\r\n'
                response += count
                writer.write(response.encode('utf-8'))
                # API log sayısı için log basma (spam önleme)
                pass
            except Exception as e:
                add_log("API log sayisi hatasi: " + str(e), "HTTP")
                writer.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'.encode('utf-8'))
        elif b'GET /api/status' in request or b'GET /api/status HTTP' in request:
            # Bağlantı durumu ve payload'ları döndür
            try:
                import ujson
                status_data = {
                    "connected": pos_handler_instance.is_connected if pos_handler_instance else False,
                    "payloads": {}
                }
                if pos_handler_instance:
                    for msg_type, payload in pos_handler_instance.payloads.items():
                        status_data["payloads"][get_enum_name(msg_type)] = payload
                
                response_json = ujson.dumps(status_data)
                response = 'HTTP/1.1 200 OK\r\n'
                response += 'Content-Type: application/json; charset=utf-8\r\n'
                response += 'Content-Length: ' + str(len(response_json)) + '\r\n'
                response += 'Cache-Control: no-cache\r\n'
                response += 'Access-Control-Allow-Origin: *\r\n'
                response += 'Connection: close\r\n'
                response += '\r\n'
                response += response_json
                writer.write(response.encode('utf-8'))
            except Exception as e:
                add_log("API status hatasi: " + str(e), "HTTP")
                writer.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'.encode('utf-8'))
        elif b'POST /api/payload' in request:
            # Payload güncelle
            try:
                import ujson
                # Request body'yi oku
                content_length = 0
                for line in request.split(b'\r\n'):
                    if line.startswith(b'Content-Length:'):
                        content_length = int(line.split(b':')[1].strip())
                        break
                
                body_start = request.find(b'\r\n\r\n') + 4
                body = request[body_start:body_start+content_length]
                data = ujson.loads(body.decode('utf-8'))
                
                if pos_handler_instance and 'msg_type' in data and 'payload' in data:
                    # Mesaj tipini bul
                    msg_type_name = data['msg_type']
                    # PosCableMessageType enum değerlerini kontrol et
                    msg_type_found = None
                    if msg_type_name == "ACK":
                        msg_type_found = PosCableMessageType.ACK
                    elif msg_type_name == "NACK":
                        msg_type_found = PosCableMessageType.NACK
                    elif msg_type_name == "POLL":
                        msg_type_found = PosCableMessageType.POLL
                    elif msg_type_name == "PRINT":
                        msg_type_found = PosCableMessageType.PRINT
                    elif msg_type_name == "PAYMENT_START":
                        msg_type_found = PosCableMessageType.PAYMENT_START
                    elif msg_type_name == "PAYMENT_INFO":
                        msg_type_found = PosCableMessageType.PAYMENT_INFO
                    elif msg_type_name == "SETTLEMENT_START":
                        msg_type_found = PosCableMessageType.SETTLEMENT_START
                    elif msg_type_name == "SETTLEMENT_INFO":
                        msg_type_found = PosCableMessageType.SETTLEMENT_INFO
                    elif msg_type_name == "PAYMENT_FAILED":
                        msg_type_found = PosCableMessageType.PAYMENT_FAILED
                    elif msg_type_name == "DEVICE_INFO":
                        msg_type_found = PosCableMessageType.DEVICE_INFO
                    
                    if msg_type_found is not None:
                        pos_handler_instance.payloads[msg_type_found] = data['payload']
                        add_log("Payload güncellendi: {}".format(msg_type_name), "HTTP")
                
                writer.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'.encode('utf-8'))
            except Exception as e:
                add_log("API payload güncelleme hatasi: " + str(e), "HTTP")
                writer.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'.encode('utf-8'))
        elif b'GET /api/logs/new' in request or b'GET /api/logs/new HTTP' in request:
            # Yeni logları döndür (AJAX için)
            try:
                import ujson
                # Request'ten last_count parametresini al
                last_count = 0
                if b'?' in request:
                    query = request.split(b'?')[1].split(b' ')[0]
                    if b'last_count=' in query:
                        last_count = int(query.split(b'last_count=')[1].split(b'&')[0])
                
                # Yeni logları al
                new_logs = logs[last_count:]
                log_data = []
                import time
                for log in new_logs:
                    elapsed = time.ticks_ms() - log["time"]
                    elapsed_sec = elapsed / 1000
                    msg = str(log["message"])
                    if len(msg) > 500:
                        msg = msg[:500] + "... (kesildi)"
                    msg = msg.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;').replace('"', '&quot;')
                    log_data.append({
                        "time": "{:.3f}".format(elapsed_sec),
                        "message": msg,
                        "category": log.get("category", "UART")
                    })
                
                response_json = ujson.dumps({"logs": log_data, "count": len(logs)})
                response = 'HTTP/1.1 200 OK\r\n'
                response += 'Content-Type: application/json; charset=utf-8\r\n'
                response += 'Content-Length: ' + str(len(response_json)) + '\r\n'
                response += 'Cache-Control: no-cache\r\n'
                response += 'Access-Control-Allow-Origin: *\r\n'
                response += 'Connection: close\r\n'
                response += '\r\n'
                response += response_json
                writer.write(response.encode('utf-8'))
            except Exception as e:
                add_log("API yeni loglar hatasi: " + str(e), "HTTP")
                writer.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'.encode('utf-8'))
        elif b'POST /clear' in request:
            # Logları temizle
            try:
                logs.clear()
                add_log("Loglar temizlendi (POST /clear)", "HTTP")
                writer.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'.encode('utf-8'))
            except Exception as e:
                add_log("Log temizleme hatasi: " + str(e), "HTTP")
                writer.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'.encode('utf-8'))
        elif b'GET / ' in request or b'GET / HTTP' in request or (request.startswith(b'GET /') and b'GET /api/' not in request):
            try:
                # Ana sayfa isteği için log bas
                try:
                    request_line = request.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    add_log("HTTP isteği alındı: {}".format(request_line), "HTTP")
                except:
                    add_log("HTTP isteği alındı (ana sayfa)", "HTTP")
                
                response = get_logs_html()
                response_bytes = response.encode('utf-8')
                
                header = 'HTTP/1.1 200 OK\r\n'
                header += 'Content-Type: text/html; charset=utf-8\r\n'
                header += 'Content-Length: ' + str(len(response_bytes)) + '\r\n'
                header += 'Connection: keep-alive\r\n'
                header += 'Cache-Control: no-cache\r\n'
                header += '\r\n'
                
                writer.write(header.encode('utf-8'))
                writer.write(response_bytes)
                add_log("HTTP 200 OK yanıtı gönderildi", "HTTP")
            except Exception as e:
                error_msg = "HTML olusturma hatasi: " + str(e)
                add_log(error_msg, "HTTP")
                error_response = 'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
                writer.write(error_response.encode('utf-8'))
        else:
            add_log("HTTP 404 Not Found yanıtı gönderildi", "HTTP")
            writer.write('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode('utf-8'))
        
        try:
            await writer.drain()
        except:
            pass
        
        # Keep-alive için bağlantıyı hemen kapatma
        # Client bağlantıyı kapatacak veya timeout olacak
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except:
            pass
            
    except asyncio.TimeoutError:
        # Timeout durumunda sessizce kapat
        try:
            writer.close()
        except:
            pass
    except Exception as e:
        # Hata durumunda log kaydet ama sunucuyu çalıştırmaya devam et
        error_msg = "Web server istemci hatasi: " + str(e)
        add_log(error_msg)
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def start_web_server(port=80):
    """Web sunucusunu başlat - restart olmadan sürekli çalışır"""
    add_log("Web sunucusu başlatılıyor... (Port: {})".format(port), "HTTP")
    
    while True:
        try:
            server = await asyncio.start_server(handle_client, "0.0.0.0", port)
            add_log("Web sunucusu hazır! Tarayıcıdan bağlanabilirsiniz.", "HTTP")
            add_log("Sunucu dinlemede... (Port: {})".format(port), "HTTP")
            
            # Sunucu kapanana kadar bekle
            await server.wait_closed()
            
            # Eğer sunucu kapandıysa, hata mesajı ver ve yeniden başlat
            add_log("Web sunucusu kapandi, yeniden baslatiliyor...", "HTTP")
            await asyncio.sleep(2)  # 2 saniye bekle
            
        except Exception as e:
            error_msg = "Web sunucu hatasi: {}".format(str(e))
            add_log(error_msg, "HTTP")
            # Hata durumunda 5 saniye bekle ve yeniden dene
            add_log("Web sunucusu 5 saniye sonra yeniden baslatilacak...", "HTTP")
            await asyncio.sleep(5)
