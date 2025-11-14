import ujson
import time
import uasyncio as asyncio
from pos_protocol import (
    PosCableMessageType, AesEncryptorDecryptor, PosData, 
    Crc8, STX, ETX, get_enum_name
)
from web_server import add_log

class PosWithCable:
    def __init__(self, uart):
        self.poll_cnt = 0
        self.uart = uart
        self.aes_enc_dec = AesEncryptorDecryptor.get_instance()
        self.current_status = "IDLE"
        
        # Varsayılan payload'lar
        self.payloads = {
            PosCableMessageType.ACK: ujson.dumps(''),
            PosCableMessageType.NACK: ujson.dumps(''),
            PosCableMessageType.POLL: ujson.dumps({"status": "IDLE", "cnt": 1}),
            PosCableMessageType.PRINT: ujson.dumps({"slip": ujson.dumps([
                {"t":"t","c":"TECHPOS TEST MESAJI","s":"1","a":"1"},
                {"t":"t","c":"Bu bir test yazdırmadır","s":"1","a":"1"}
            ])}),
            PosCableMessageType.PAYMENT_START: ujson.dumps({"errorCode": "", "errorMessage":""}),
            PosCableMessageType.PAYMENT_INFO: ujson.dumps({
                "bankAcquirerId": "0001",
                "bankMerchantId": "000000000000002",
                "bankReferenceNo": "0000531071197371",
                "bankTerminalNo": "10002393",
                "cardBin": "9792 *",
                "customerSlip": ujson.dumps([{"t":"t","c":"Test Bankası","s":"1","a":"1"}]),
                "merchantSlip": ujson.dumps([{"t":"t","c":"Test A.Ş.","s":"1","a":"1"}]),
                "qrPayment": "0"
            }),
            PosCableMessageType.SETTLEMENT_START: ujson.dumps(''),
            PosCableMessageType.SETTLEMENT_INFO: ujson.dumps({
                "slipDetail": ujson.dumps([{"t":"t","c":"Günsonu detay","s":"1","a":"1"}]),
                "slipSummary": ujson.dumps([{"t":"t","c":"Günsonu özet","s":"1","a":"1"}])
            }),
            PosCableMessageType.PAYMENT_FAILED: ujson.dumps({
                "errorCode": "ecode",
                "errorMessage": "emsg",
                "errorDefinition": "edef",
                "slip": ""
            }),
            PosCableMessageType.DEVICE_INFO: ujson.dumps(''),
        }
    
    def update_status(self, new_status):
        """Status güncelle"""
        self.current_status = new_status
        current_payload = self.payloads.get(PosCableMessageType.POLL, '{}')
        try:
            payload_dict = ujson.loads(current_payload)
        except:
            payload_dict = {}
        payload_dict["status"] = new_status
        self.payloads[PosCableMessageType.POLL] = ujson.dumps(payload_dict)
        add_log("Status güncellendi: {}".format(new_status))
    
    def send(self, msg_type, msg):
        """Mesaj gönder"""
        try:
            data = PosData(msg_type, msg).get_prepared_data()
            enc_data = self.aes_enc_dec.encrypt(data)
            
            self.uart.write(enc_data)
            
            add_log("Gönderildi: {} ({} bytes) - {}".format(
                get_enum_name(msg_type),
                len(enc_data),
                msg[:50] if msg else ""
            ))
        except Exception as e:
            add_log("Gönderme hatası: {}".format(str(e)))
    
    async def read_loop(self):
        """USB serial okuma döngüsü"""
        buffer = bytearray()
        add_log("USB Serial okuma başlatıldı...")
        
        while True:
            try:
                # Veri kontrol et
                if self.uart.any():
                    data = self.uart.read(self.uart.any())
                    if data:
                        buffer.extend(data)
                        
                        # Tüm veriyi işle
                        await self._process_data(buffer)
                        buffer = bytearray()  # Buffer'ı temizle
                
                await asyncio.sleep_ms(10)  # CPU'yu rahatlat
                
            except Exception as e:
                add_log("Okuma hatası: {}".format(str(e)))
                await asyncio.sleep_ms(100)
    
    async def _process_data(self, encrypted_data):
        """Gelen şifrelenmiş veriyi işle"""
        try:
            add_log("Gelen veri: {} bytes".format(len(encrypted_data)))
            add_log("Hex: {}".format(' '.join('{:02X}'.format(b) for b in encrypted_data[:32])))
            
            # Şifreyi çöz
            data = self.aes_enc_dec.decrypt(encrypted_data)
            add_log("Çözülmüş veri: {} bytes".format(len(data)))
            
            if len(data) < 8:
                add_log("Hata: Veri çok kısa")
                return
            
            # STX kontrolü
            if data[0] != STX:
                add_log("Hata: STX eksik. Gelen: 0x{:02X}".format(data[0]))
                return
            
            # Mesaj tipini oku
            msg_type = data[1]
            length = int.from_bytes(data[2:6], 'big')
            
            if len(data) < 6 + length + 2:
                add_log("Hata: Veri uzunluğu yetersiz")
                return
            
            payload_bytes = data[6:6+length]
            payload = payload_bytes.decode('utf-8', errors='ignore')
            crc = data[6+length]
            etx = data[6+length+1]
            
            # ETX kontrolü
            if etx != ETX:
                add_log("Hata: ETX eksik. Gelen: 0x{:02X}".format(etx))
                return
            
            # CRC kontrolü
            calc_crc = Crc8().calculate(payload_bytes)
            if crc != calc_crc:
                add_log("CRC Hatası! Beklenen: 0x{:02X}, Hesaplanan: 0x{:02X}".format(crc, calc_crc))
                self.send(PosCableMessageType.NACK, ujson.dumps({
                    "hataMesajı": "CRC_ERROR",
                    "hataKodu": 7
                }))
                return
            
            add_log("Mesaj alındı: {} - {}".format(
                get_enum_name(msg_type),
                payload[:100] if payload else ""
            ))
            
            # JSON parse
            try:
                json_data = ujson.loads(payload)
                cnt_value = json_data.get("cnt")
                if cnt_value:
                    if self.poll_cnt == 0:
                        self.poll_cnt = int(cnt_value) - 1
                    if self.poll_cnt != int(cnt_value) - 1:
                        add_log("Sayaç uyumsuzluğu: beklenen {}, gelen {}".format(
                            self.poll_cnt + 1, cnt_value
                        ))
                    add_log("Sayaç (cnt): {}".format(cnt_value))
            except:
                pass
            
            # Algoritma akışını çalıştır
            await self.algorithm_flow(msg_type, payload)
            
        except Exception as e:
            add_log("İşleme hatası: {}".format(str(e)))
            import sys
            sys.print_exception(e)
    
    async def algorithm_flow(self, msg_type, payload):
        """Mesaj tipine göre otomatik yanıt ver"""
        try:
            # Mesaj tipine göre işle
            if msg_type in [
                PosCableMessageType.POLL,
                PosCableMessageType.PRINT,
                PosCableMessageType.PAYMENT_INFO,
                PosCableMessageType.PAYMENT_START,
                PosCableMessageType.SETTLEMENT_INFO,
                PosCableMessageType.PAYMENT_FAILED,
                PosCableMessageType.NACK
            ]:
                # Bu mesajlar için payload'dan yanıt ver
                new_payload = self.payloads.get(msg_type, ujson.dumps(''))
                add_log("{} → Yanıt gönderiliyor".format(get_enum_name(msg_type)))
                
                # Özel durumlar
                if msg_type == PosCableMessageType.PAYMENT_START:
                    self.update_status("PAYMENT_FAILED")
                    # PAYMENT_FAILED mesajı gönder
                    failed_payload = self.payloads.get(PosCableMessageType.PAYMENT_FAILED)
                    self.send(PosCableMessageType.PAYMENT_FAILED, failed_payload)
                    return
                
                if msg_type == PosCableMessageType.PAYMENT_FAILED:
                    self.update_status("IDLE")
                
                # POLL mesajı için cnt güncelle
                if msg_type == PosCableMessageType.POLL:
                    try:
                        payload_dict = ujson.loads(new_payload)
                        if self.poll_cnt > 0:
                            payload_dict["cnt"] = self.poll_cnt + 1
                            new_payload = ujson.dumps(payload_dict)
                        self.poll_cnt += 1
                    except:
                        pass
                
                self.send(msg_type, new_payload)
            else:
                # Diğer mesajlar için boş yanıt
                add_log("{} → Sabit içerik gönderiliyor".format(get_enum_name(msg_type)))
                self.send(msg_type, "")
                
        except Exception as e:
            add_log("Algoritma akışı hatası: {}".format(str(e)))
