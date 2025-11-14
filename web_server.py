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
    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POS Serial Monitor</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 20px;
            background-color: #1e1e1e;
            color: #d4d4d4;
        }
        h1 {
            color: #4ec9b0;
            border-bottom: 2px solid #4ec9b0;
            padding-bottom: 10px;
        }
        .stats {
            background-color: #252526;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .stats div {
            margin: 5px 0;
        }
        .log-container {
            background-color: #252526;
            padding: 15px;
            border-radius: 5px;
            max-height: 70vh;
            overflow-y: auto;
        }
        .log-entry {
            padding: 5px;
            border-bottom: 1px solid #3e3e42;
            word-wrap: break-word;
        }
        .log-entry:last-child {
            border-bottom: none;
        }
        .log-time {
            color: #858585;
            margin-right: 10px;
        }
        .log-message {
            color: #d4d4d4;
        }
        .error {
            color: #f48771;
        }
        .success {
            color: #4ec9b0;
        }
        .warning {
            color: #dcdcaa;
        }
        button {
            background-color: #0e639c;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover {
            background-color: #1177bb;
        }
    </style>
</head>
<body>
    <h1>🔌 POS USB Serial Monitor</h1>
    
    <div class="stats">
        <div><strong>Toplam Log:</strong> <span id="log-count">{}</span></div>
        <div><strong>Durum:</strong> <span class="success">Çalışıyor</span></div>
        <button onclick="location.reload()">Yenile</button>
        <button onclick="clearLogs()">Logları Temizle</button>
    </div>
    
    <div class="log-container" id="logs">
""".format(len(logs))
    
    # Son logları ekle (en yeni üstte)
    for log in reversed(logs[-500:]):  # Son 500 log
        import time
        elapsed = time.ticks_ms() - log["time"]
        elapsed_sec = elapsed / 1000
        
        html += '        <div class="log-entry">'
        html += '<span class="log-time">+{:.3f}s</span>'.format(elapsed_sec)
        html += '<span class="log-message">{}</span>'.format(
            log["message"].replace('<', '&lt;').replace('>', '&gt;')
        )
        html += '</div>\n'
    
    html += """    </div>
    
    <script>
        function clearLogs() {
            if (confirm('Logları temizlemek istediğinize emin misiniz?')) {
                fetch('/clear', {method: 'POST'}).then(() => location.reload());
            }
        }
        
        // Otomatik yenileme (""" + str(WEB_AUTO_REFRESH_SECONDS) + """ saniyede bir)
        setTimeout(function() {
            location.reload();
        }, """ + str(WEB_AUTO_REFRESH_SECONDS * 1000) + """);
    </script>
</body>
</html>"""
    
    return html

async def handle_client(reader, writer):
    """Web sunucusu istemci handler"""
    try:
        request = await reader.read(1024)
        request_str = request.decode('utf-8')
        
        # GET isteği mi kontrol et
        if b'GET / ' in request or b'GET / HTTP' in request:
            response = get_logs_html()
            writer.write('HTTP/1.1 200 OK\r\n')
            writer.write('Content-Type: text/html; charset=utf-8\r\n')
            writer.write('Content-Length: {}\r\n\r\n'.format(len(response)))
            writer.write(response)
        elif b'POST /clear' in request:
            # Logları temizle
            logs.clear()
            writer.write('HTTP/1.1 200 OK\r\n\r\nOK')
        else:
            writer.write('HTTP/1.1 404 Not Found\r\n\r\n')
        
        await writer.drain()
        writer.close()
    except Exception as e:
        add_log("Web server hatası: {}".format(str(e)))

async def start_web_server(port=80):
    """Web sunucusunu başlat"""
    add_log("Web sunucusu başlatılıyor... (Port: {})".format(port))
    try:
        server = await asyncio.start_server(handle_client, "0.0.0.0", port)
        add_log("Web sunucusu hazır! Tarayıcıdan bağlanabilirsiniz.")
        await server.wait_closed()
    except Exception as e:
        add_log("Web sunucu hatası: {}".format(str(e)))
