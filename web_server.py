import uasyncio as asyncio
from pos_protocol import PosCableMessageType, get_enum_name

# Global log listesi
logs = []

try:
    from config import MAX_LOGS, WEB_AUTO_REFRESH_SECONDS
except ImportError:
    MAX_LOGS = 1000
    WEB_AUTO_REFRESH_SECONDS = 5

def add_log(message):
    """Yeni log ekle"""
    import time
    timestamp = time.ticks_ms()
    log_entry = {
        "time": timestamp,
        "message": str(message)
    }
    logs.append(log_entry)
    # Eski logları temizle
    if len(logs) > MAX_LOGS:
        logs.pop(0)

def get_logs_html():
    """Logları HTML formatında döndür"""
    import time
    
    # HTML header
    html = "<!DOCTYPE html>\n"
    html += "<html>\n"
    html += "<head>\n"
    html += "    <meta charset=\"UTF-8\">\n"
    html += "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
    html += "    <title>POS Serial Monitor</title>\n"
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
    html += "    </style>\n"
    html += "</head>\n"
    html += "<body>\n"
    html += "    <h1>POS USB Serial Monitor</h1>\n"
    html += "    \n"
    html += "    <div class=\"stats\">\n"
    html += "        <div><strong>Toplam Log:</strong> <span id=\"log-count\">" + str(len(logs)) + "</span></div>\n"
    html += "        <div><strong>Durum:</strong> <span class=\"success\">Calisiyor</span></div>\n"
    html += "        <button onclick=\"location.reload()\">Yenile</button>\n"
    html += "        <button onclick=\"clearLogs()\">Loglari Temizle</button>\n"
    html += "    </div>\n"
    html += "    \n"
    html += "    <div class=\"log-container\" id=\"logs\">\n"
    
    # Son logları ekle (en yeni üstte)
    for log in reversed(logs[-500:]):  # Son 500 log
        elapsed = time.ticks_ms() - log["time"]
        elapsed_sec = elapsed / 1000
        
        # Mesajı HTML'den temizle
        msg = str(log["message"])
        msg = msg.replace('<', '&lt;')
        msg = msg.replace('>', '&gt;')
        msg = msg.replace('&', '&amp;')
        msg = msg.replace('"', '&quot;')
        
        html += "        <div class=\"log-entry\">\n"
        html += "            <span class=\"log-time\">+" + "{:.3f}".format(elapsed_sec) + "s</span>\n"
        html += "            <span class=\"log-message\">" + msg + "</span>\n"
        html += "        </div>\n"
    
    html += "    </div>\n"
    html += "    \n"
    html += "    <script>\n"
    html += "        function clearLogs() {\n"
    html += "            if (confirm('Loglari temizlemek istediginize emin misiniz?')) {\n"
    html += "                fetch('/clear', {method: 'POST'}).then(function() { location.reload(); });\n"
    html += "            }\n"
    html += "        }\n"
    html += "        \n"
    html += "        // Otomatik yenileme KAPALI - manuel yenileme icin 'Yenile' butonuna basin\n"
    html += "        // Otomatik yenilemeyi acmak isterseniz asagidaki yoruma alinmis kodu acin:\n"
    html += "        // setTimeout(function() { location.reload(); }, " + str(WEB_AUTO_REFRESH_SECONDS * 1000) + ");\n"
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
        
        # GET isteği mi kontrol et
        if b'GET / ' in request or b'GET / HTTP' in request or request.startswith(b'GET /'):
            try:
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
            except Exception as e:
                error_msg = "HTML olusturma hatasi: " + str(e)
                add_log(error_msg)
                error_response = 'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
                writer.write(error_response.encode('utf-8'))
        elif b'POST /clear' in request:
            # Logları temizle
            try:
                logs.clear()
                writer.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'.encode('utf-8'))
            except Exception as e:
                add_log("Log temizleme hatasi: " + str(e))
                writer.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'.encode('utf-8'))
        else:
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
    add_log("Web sunucusu başlatılıyor... (Port: {})".format(port))
    
    while True:
        try:
            server = await asyncio.start_server(handle_client, "0.0.0.0", port)
            add_log("Web sunucusu hazır! Tarayıcıdan bağlanabilirsiniz.")
            
            # Sunucu kapanana kadar bekle
            await server.wait_closed()
            
            # Eğer sunucu kapandıysa, hata mesajı ver ve yeniden başlat
            add_log("Web sunucusu kapandi, yeniden baslatiliyor...")
            await asyncio.sleep(2)  # 2 saniye bekle
            
        except Exception as e:
            error_msg = "Web sunucu hatasi: {}".format(str(e))
            add_log(error_msg)
            # Hata durumunda 5 saniye bekle ve yeniden dene
            add_log("Web sunucusu 5 saniye sonra yeniden baslatilacak...")
            await asyncio.sleep(5)
