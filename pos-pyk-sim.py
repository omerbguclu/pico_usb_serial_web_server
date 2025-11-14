import serial
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import subprocess
import json, time, os, sys
import serial.tools.list_ports

class ComPortSelector:
    def __init__(self):
        self.selected_port = None
        self.window = tk.Tk()
        self.window.title("COM Port Seçimi")
        self.window.geometry("300x150")

        ports = [port.device for port in serial.tools.list_ports.comports()]
        ttk.Label(self.window, text="Lütfen COM port seçin:").pack(pady=10)

        self.combo = ttk.Combobox(self.window, values=ports)
        self.combo.pack()

        ttk.Button(self.window, text="Devam", command=self.confirm_selection).pack(pady=10)

        self.window.mainloop()

    def confirm_selection(self):
        self.selected_port = self.combo.get()
        self.window.destroy()

    def get_selected_port(self):
        return self.selected_port


class PosCableMessageType:
    ACK = 0x64
    NACK = 0x65
    POLL = 0x66
    PRINT = 0x67
    PAYMENT_START = 0x68
    PAYMENT_INFO = 0x69
    SETTLEMENT_START = 0x6A
    SETTLEMENT_INFO = 0x6B
    PAYMENT_FAILED = 0x6C
    DEVICE_INFO = 0x6D

class AesEncryptorDecryptor:
    _instance = None
    AES_KEY_CR = bytes([
        0x76, 0x7d, 0x82, 0xb4, 0xf9, 0x3d, 0x4d, 0xf0,
        0x66, 0x58, 0x7a, 0x37, 0x93, 0x42, 0x3a, 0x73,
        0x56, 0xc0, 0x40, 0xcb, 0x90, 0xc8, 0x83, 0x74
    ])

    def __init__(self):
        self.aes = AES.new(self.AES_KEY_CR, AES.MODE_ECB)

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = AesEncryptorDecryptor()
        return cls._instance

    def encrypt(self, data: bytes) -> bytes:
        padded = self._pad(data)
        encrypted = b''.join(
            self.aes.encrypt(padded[i:i+16]) for i in range(0, len(padded), 16)
        )
        return encrypted

    def decrypt(self, encrypted_data: bytes) -> bytes:
        decrypted = b''.join(
            self.aes.decrypt(encrypted_data[i:i+16]) for i in range(0, len(encrypted_data), 16)
        )
        return self._unpad(decrypted)

    def _pad(self, data: bytes) -> bytes:
        pad_len = 16 - (len(data) % 16)
        return data + get_random_bytes(pad_len)

    def _unpad(self, data: bytes) -> bytes:
        return data.rstrip(b'\x00')

# Global AES instance
aes_enc_dec = AesEncryptorDecryptor.get_instance()

def print_version():
    try:
        script_path = os.path.abspath(sys.argv[0])
        script_dir = os.path.dirname(script_path)
        os.chdir(script_dir)
        tag = subprocess.check_output(["git", "describe", "--tags", "--abbrev=0"])
        print(f"********************POS COM SIM - VERSION {tag.decode('utf-8').strip()}********************")
    except Exception:
        print("********************POS COM SIM - VERSION 0.0********************")

class Crc8:
    def Calculate(self, data: bytes) -> int:
        crc = 0
        for b in data:
            crc ^= b
            for _ in range(8):
                if crc & 0x80:
                    crc = (crc << 1) ^ 0x07
                else:
                    crc <<= 1
                crc &= 0xFF
        return crc

STX, ETX = 0x87, 0x88
class PosData:
    def __init__(self, msg_type: int, msg: str):
        self.msg_type = msg_type
        self.msg = msg.encode("utf-8")
        self.frame = bytearray()
        self.frame.append(STX)
        self.frame.append(msg_type)
        self.frame += self.encode_length(len(self.msg))
        self.frame += self.msg
        self.crc = Crc8().Calculate(self.msg)
        self.frame.append(self.crc)
        self.frame.append(ETX)
        print(f"Msg: {msg} - Crc:{self.crc:02X}")

    def encode_length(self, length: int) -> bytes:
        return length.to_bytes(4, byteorder='big')

    def get_prepared_data(self) -> bytes:
        return self.frame

class PosWithCable:
    def __init__(self, port):
        self.poll_cnt = 0
        self.port = port
        self.ser = serial.Serial(self.port, baudrate=115200, timeout=0.001)

    def send(self, msg_type: int, msg: str):
        print("")
        data = PosData(msg_type, msg).get_prepared_data()
        print("")
        enc_data = aes_enc_dec.encrypt(data)
        print(enc_data.hex())
        print("")
        self.ser.write(enc_data)
        print("Sent msg size", len(enc_data), "FINISHED")

    def read(self):
        while True:
            try:
                data = self.ser.read(1024)
                if not data:
                    continue

                print("Gelen veri:", ' '.join(f'0x{b:02X}' for b in data))

                data = aes_enc_dec.decrypt(data)

                print("Çözülmüş veri:", ' '.join(f'0x{b:02X}' for b in data))

                if data[0] != STX:
                    print("Framing hatası: STX eksik.")
                    continue

                msg_type = data[1]
                length = int.from_bytes(data[2:6], byteorder='big')
                payload = data[6:6+length].decode('utf-8', errors='ignore')
                crc = data[6+length]
                calc_crc = Crc8().Calculate(data[6:6+length])

                try:
                    json_data = json.loads(payload)  # stringi sözlüğe çevir
                    cnt_value = json_data["cnt"] if "cnt" in json_data else None
                    if self.poll_cnt == 0:
                        self.poll_cnt = int(cnt_value) - 1
                    if self.poll_cnt != int(cnt_value) - 1:
                        exit
                    print("cnt:", cnt_value)
                except json.JSONDecodeError as e:
                    print("Geçersiz JSON:", e)
                except:
                    pass

                if data[7+length] != ETX:
                    print("Framing hatası: ETX eksik.")
                    continue

                if crc != calc_crc:
                    print(f"CRC Hatası! Beklenen: {crc:02X}, Hesaplanan: {calc_crc:02X}")
                    self.send(PosCableMessageType.NACK, json.dumps({
                        "hataMesajı": "CRC_ERROR",
                        "hataKodu": 7
                    }))
                    continue

                print(f"MsgType: {msg_type}, Payload: {payload}")

                self.AlgorithmFlow(msg_type, payload)

            except KeyboardInterrupt:
                print("Dinleme durduruldu.")
            except serial.SerialException as e:
                print("Seri port hatası:", e)
                self.reconnect_loop()

    def reconnect_loop(self):
        while True:
            try:
                self.ser = serial.Serial(self.port, baudrate=115200, timeout=0.001)
                self.gui.log("Bağlantı yeniden kuruldu.")
                return True
            except serial.SerialException as e:
                self.gui.log(f"Bağlantı denemesi başarısız: {e}")
                time.sleep(1)


    def AlgorithmFlow(self, msg_type, payload):
        try:
            data = json.loads(payload) if payload else {}
        except Exception as e:
            self.gui.log("Payload parse hatası:", e)
            data = {}

        if msg_type in [PosCableMessageType.POLL,
                        PosCableMessageType.PRINT,
                        PosCableMessageType.PAYMENT_INFO,
                        PosCableMessageType.PAYMENT_START,
                        PosCableMessageType.SETTLEMENT_INFO,
                        PosCableMessageType.PAYMENT_FAILED,
                        PosCableMessageType.NACK]:
            new_payload = self.gui.get_payload(msg_type)
            self.gui.log(f"{hex(msg_type)} okundu → GUI içeriği gönderiliyor.")
            self.gui.highlight_label(msg_type)
            if (msg_type is PosCableMessageType.PAYMENT_START):
                self.gui.update_status("PAYMENT_FAILED")
            if (msg_type is PosCableMessageType.PAYMENT_FAILED):
                self.gui.update_status("IDLE")
            self.send(msg_type, new_payload)
        else:
            self.gui.log(f"{hex(msg_type)} okundu → sabit içerik gönderiliyor.")
            self.send(msg_type, "")


import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont

def get_enum_name(value):
    for name, val in vars(PosCableMessageType).items():
        if isinstance(val, int) and val == value:
            return name
    return "UNKNOWN"

STATUS_OPTIONS = [
    "IDLE", "BUSY",
    "PAYMENT_CONTINUE", "PAYMENT_COMPLETED", "PAYMENT_FAILED", "PAYMENT_CANCELED",
    "SETTLEMENT_CONTINUE", "SETTLEMENT_COMPLETED", "SETTLEMENT_FAILED", "SETTLEMENT_CANCELED",
    "PRINT_REQUEST"
]

class PosCableEditorGUI(tk.Tk):
    def __init__(self, pos_instance):
        super().__init__()
        self.title("POS Cable Message Editor")
        self.geometry("1024x768")
        self.pos = pos_instance
        self.pos.gui = self  # GUI referansını PosWithCable'a aktar
        self.label_refs = {}

        self.payloads = {
            PosCableMessageType.ACK: tk.StringVar(
                value=json.dumps('')
            ),
            PosCableMessageType.NACK: tk.StringVar(
                value=json.dumps('')
            ),
            PosCableMessageType.POLL: tk.StringVar(value=json.dumps({"status": "IDLE"})),
            PosCableMessageType.PRINT: tk.StringVar(
                value=json.dumps({"slip": json.dumps([{"t":"t","c":"TECHPOS GÜNSONU DETAY BELGESİ","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Test A.Ş.","s":"1","a":"1"}, {"t":"t","c":"Test Adresi\n\n\n","s":"1","a":"1"}, {"t":"t","c":"İSTANBUL","s":"1","a":"1"}, {"t":"t","c":"2122423432","s":"1","a":"1"}, {"t":"t","c":"SN:ED0PI0003419 DRP\/P10         VER:0117","s":"1","a":"1"}, {"t":"t","c":"BELGE REF. NO:                       306","s":"1","a":"1"}, {"t":"t","c":"TARİH:06.11.2025              SAAT:16:18","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Test Bankası","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000000000002","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    10002393","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":"000545           SATIŞ    06\/11 16:16:22","s":"1","a":"1"}, {"t":"t","c":"979229*** ****   000546          14,53 ₺","s":"1","a":"1"}, {"t":"t","c":"1019                                    ","s":"1","a":"1"}, {"t":"t","c":"--------------------","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        1             14,53 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0001"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.C.ZİRAAT BANKASI A.Ş.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000000106674","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    01003971","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0010"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.HALK BANKASI A.Ş.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000001002585","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    01002717","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0012"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.VAKIFLAR BANKASI T.A.O.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               001800000025231","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    PS269646","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0015"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"GENEL TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası                      14,53 ₺","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"RAPOR SONU","s":"1","a":"1"}, {"t":"t","c":"BU BELGEYİ SAKLAYINIZ","s":"1","a":"1"}, {"t":"t","c":"GÜNSONU İŞLEMİ BAŞARILI OLARAK","s":"1","a":"1"}, {"t":"t","c":"TAMAMLANMIŞTIR","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TechPOS Günsonu Mesajı İyi Günler Test","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}], ensure_ascii=False)})
            ),
            PosCableMessageType.PAYMENT_START: tk.StringVar(
                value=json.dumps({"errorCode": "", "errorMessage":""})
            ),
            PosCableMessageType.PAYMENT_INFO: tk.StringVar(
                value=json.dumps({    "bankAcquirerId": "0001",    "bankMerchantId": "000000000000002",    "bankReferenceNo": "0000531071197371",    "bankTerminalNo": "10002393",    "cardBin": "9792 *",    "customerSlip": json.dumps([        {            "t": "t",            "c": "Test Bankası",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "TARİH: 06.11.2025              SAAT: 16: 16",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İŞYERİ: 000000000000002      POS: 10002393",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "BATCH NO:AB-306                      L11",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "ISLEM NO: 000002              STAN: 000545",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "SN:ED0PI0003419   DRP\/P10",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "",            "s": "1",            "a": "0"        },        {            "t": "t",            "c": "SATIŞ",            "s": "2",            "a": "1"        },        {            "t": "t",            "c": "**** **** **** 1019",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "",            "s": "1",            "a": "0"        },        {            "t": "t",            "c": "TROY \/ KREDI \/ YURT ICI",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İŞLEM TUTARI",            "s": "2",            "a": "1"        },        {            "t": "t",            "c": "14,53 ₺",            "s": "2",            "a": "1"        },        {            "t": "t",            "c": "TESTPUAN: 2,00TL",            "s": "2",            "a": "1"        },        {            "t": "t",            "c": "1 AY ERTELENMİŞTİR.      ALIŞVERİŞ TUTARINIZ 30\/01\/2022  TARİHİNDE EKSTRENİZE YANSITILACAKTIR.                            BU ÜYE İŞYERİNDEN YAPTIĞINIZ",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İŞLEM SONUCUNDA EKSTRA 2 TEST PUAN          (2.00 TL) KAZANDINIZ. ****************************************",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "",            "s": "1",            "a": "0"        },        {            "t": "t",            "c": "ONAY KODU: 000546        RRN: 531071197371",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "BANKA REFERANS: 0000531071197371",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "AID:A0000006723010   AC:FCF549FD800D3CD2",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "ACQUIRER ID : 0001",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "",            "s": "1",            "a": "0"        },        {            "t": "t",            "c": "TUTAR KARŞILIĞI MAL VEYA HİZMET ALDIM",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İşlem Temassız Yapılmıştır",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "MÜŞTERİ NÜSHASI",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "BU BELGEYİ SAKLAYINIZ",            "s": "1",            "a": "1"        },        {            "t": "b",            "c": "logo_0001"        }    ], ensure_ascii=False),    "merchantSlip": json.dumps([        {            "t": "t",            "c": "Test A.Ş.",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "Test Adresi\n\n\n",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İSTANBUL",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "1234567890",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "Test Bankası",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "TARİH: 06.11.2025              SAAT: 16: 16",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İŞYERİ: 000000000000002      POS: 10002393",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "BATCH NO:AB-306                      L11",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "ISLEM NO: 000002              STAN: 000545",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "SN:ED0PI0003419 DRP\/P10         VER: 0117",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "",            "s": "1",            "a": "0"        },        {            "t": "t",            "c": "SATIŞ",            "s": "2",            "a": "1"        },        {            "t": "t",            "c": "9792 **** **** 1019",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "",            "s": "1",            "a": "0"        },        {            "t": "t",            "c": "TROY \/ KREDI \/ YURT ICI",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İŞLEM TUTARI",            "s": "2",            "a": "1"        },        {            "t": "t",            "c": "14,53 ₺",            "s": "2",            "a": "1"        },        {            "t": "t",            "c": "",            "s": "1",            "a": "0"        },        {            "t": "t",            "c": "ONAY KODU: 000546        RRN: 531071197371",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "BANKA REFERANS: 0000531071197371",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "AID:A0000006723010   AC:FCF549FD800D3CD2",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "ACQUIRER ID : 0001",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "",            "s": "1",            "a": "0"        },        {            "t": "t",            "c": "TUTAR KARŞILIĞI MAL VEYA HİZMET ALDIM",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İşlem Temassız Yapılmıştır",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "MALİ DEĞERİ YOKTUR",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "İŞYERİ NÜSHASI",            "s": "1",            "a": "1"        },        {            "t": "t",            "c": "BU BELGEYİ SAKLAYINIZ",            "s": "1",            "a": "1"        },        {            "t": "b",            "c": "logo_0001"        }    ], ensure_ascii=False),    "qrPayment": "0"})
            ),
            PosCableMessageType.SETTLEMENT_START: tk.StringVar(
                value=json.dumps('')
            ),
            PosCableMessageType.SETTLEMENT_INFO: tk.StringVar(
                value=json.dumps({"slipDetail": json.dumps([{"t":"t","c":"TECHPOS GÜNSONU DETAY BELGESİ","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Test A.Ş.","s":"1","a":"1"}, {"t":"t","c":"Test Adresi\n\n\n","s":"1","a":"1"}, {"t":"t","c":"İSTANBUL","s":"1","a":"1"}, {"t":"t","c":"2122423432","s":"1","a":"1"}, {"t":"t","c":"SN:ED0PI0003419 DRP\/P10         VER:0117","s":"1","a":"1"}, {"t":"t","c":"BELGE REF. NO:                       306","s":"1","a":"1"}, {"t":"t","c":"TARİH:06.11.2025              SAAT:16:18","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Test Bankası","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000000000002","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    10002393","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":"000545           SATIŞ    06\/11 16:16:22","s":"1","a":"1"}, {"t":"t","c":"979229*** ****   000546          14,53 ₺","s":"1","a":"1"}, {"t":"t","c":"1019                                    ","s":"1","a":"1"}, {"t":"t","c":"--------------------","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        1             14,53 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0001"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.C.ZİRAAT BANKASI A.Ş.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000000106674","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    01003971","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0010"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.HALK BANKASI A.Ş.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000001002585","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    01002717","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0012"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.VAKIFLAR BANKASI T.A.O.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               001800000025231","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    PS269646","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0015"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"GENEL TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası                      14,53 ₺","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"RAPOR SONU","s":"1","a":"1"}, {"t":"t","c":"BU BELGEYİ SAKLAYINIZ","s":"1","a":"1"}, {"t":"t","c":"GÜNSONU İŞLEMİ BAŞARILI OLARAK","s":"1","a":"1"}, {"t":"t","c":"TAMAMLANMIŞTIR","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TechPOS Günsonu Mesajı İyi Günler Test","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}], ensure_ascii=False), "slipSummary": json.dumps([{"t":"t","c":"TECHPOS GÜNSONU DETAY BELGESİ","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Test A.Ş.","s":"1","a":"1"}, {"t":"t","c":"Test Adresi\n\n\n","s":"1","a":"1"}, {"t":"t","c":"İSTANBUL","s":"1","a":"1"}, {"t":"t","c":"2122423432","s":"1","a":"1"}, {"t":"t","c":"SN:ED0PI0003419 DRP\/P10         VER:0117","s":"1","a":"1"}, {"t":"t","c":"BELGE REF. NO:                       306","s":"1","a":"1"}, {"t":"t","c":"TARİH:06.11.2025              SAAT:16:18","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Test Bankası","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000000000002","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    10002393","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":"000545           SATIŞ    06\/11 16:16:22","s":"1","a":"1"}, {"t":"t","c":"979229*** ****   000546          14,53 ₺","s":"1","a":"1"}, {"t":"t","c":"1019                                    ","s":"1","a":"1"}, {"t":"t","c":"--------------------","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        1             14,53 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0001"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.C.ZİRAAT BANKASI A.Ş.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000000106674","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    01003971","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0010"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.HALK BANKASI A.Ş.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               000000001002585","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    01002717","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0012"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"T.VAKIFLAR BANKASI T.A.O.","s":"1","a":"0"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"İŞYERİ NO:               001800000025231","s":"1","a":"1"}, {"t":"t","c":"TERMİNAL NO:                    PS269646","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TECHPOS SLİP BİLGİLERİ","s":"2","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"Türk Lirası","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"                  ADET             TUTAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası        0              0,00 ₺","s":"1","a":"1"}, {"t":"b","c":"logo_0015"}, {"t":"t","c":"------------------------------------------","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"GENEL TOPLAMLAR","s":"1","a":"1"}, {"t":"t","c":"Türk Lirası                      14,53 ₺","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"RAPOR SONU","s":"1","a":"1"}, {"t":"t","c":"BU BELGEYİ SAKLAYINIZ","s":"1","a":"1"}, {"t":"t","c":"GÜNSONU İŞLEMİ BAŞARILI OLARAK","s":"1","a":"1"}, {"t":"t","c":"TAMAMLANMIŞTIR","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}, {"t":"t","c":"TechPOS Günsonu Mesajı İyi Günler Test","s":"1","a":"1"}, {"t":"t","c":" ","s":"1","a":"0"}], ensure_ascii=False)})
            ),
            PosCableMessageType.PAYMENT_FAILED: tk.StringVar(
                value=json.dumps({"errorCode": "ecode", "errorMessage":"emsg", "errorDefinition":"edef", "slip":""})
            ),
        }

        self.create_widgets()

    def update_status(self, new_status):
            self.status_var.set(new_status)
            current_payload = self.payloads[PosCableMessageType.POLL].get()
            try:
                payload_dict = json.loads(current_payload)
            except json.JSONDecodeError:
                payload_dict = {}
            payload_dict["status"] = new_status
            self.payloads[PosCableMessageType.POLL].set(json.dumps(payload_dict))
            self.log(f"Status güncellendi: {new_status}")

    def create_widgets(self):
        self.status_var = tk.StringVar(value="IDLE")  # Varsayılan seçim
        def update_status(new_status):
            self.status_var.set(new_status)
            current_payload = self.payloads[PosCableMessageType.POLL].get()
            try:
                payload_dict = json.loads(current_payload)
            except json.JSONDecodeError:
                payload_dict = {}
            payload_dict["status"] = new_status
            self.payloads[PosCableMessageType.POLL].set(json.dumps(payload_dict))
            self.log(f"Status güncellendi: {new_status}")

        mono_font = tkFont.Font(family="Courier New", size=10)

        row = 0
        for msg_type, var in self.payloads.items():
            label = tk.Label(self, text=f"{hex(msg_type)}({msg_type}) | {get_enum_name(msg_type):<17}", font=mono_font)
            label.grid(row=row, column=0, sticky="w", padx=5, pady=5)
            self.label_refs[msg_type] = label

            entry = tk.Entry(self, textvariable=var, width=80)
            entry.grid(row=row, column=1, padx=5, pady=5)
            row += 1

            if (msg_type is PosCableMessageType.POLL):
                status_frame = tk.LabelFrame(self, text="POLL Status Seçimi")
                status_frame.grid(row=row, column=0, columnspan=2, padx=5, pady=10, sticky="w")

                for i, status in enumerate(STATUS_OPTIONS):
                    btn = tk.Button(status_frame, text=status, width=18,
                                    command=lambda s=status: update_status(s))
                    btn.grid(row=i//6, column=i%6, padx=2, pady=2)
                row += 3

        self.status_label = tk.Label(self, text="Dinleme başladı...")
        self.status_label.grid(row=row, column=0, columnspan=2, pady=10)

    def highlight_label(self, msg_type):
        label = self.label_refs.get(msg_type)
        if label:
            label.config(bg="#d0f0ff")  # açık mavi
            label.after(500, lambda: label.config(bg="white")) 

    def get_payload(self, msg_type):
        return self.payloads.get(msg_type, tk.StringVar(value=json.dumps({}))).get()

    def log(self, *args):
        print("GUI LOG:", *args)
        self.status_label.config(text=' '.join(str(a) for a in args))

import threading

if __name__ == "__main__":
    print("Dinleme başladı...")
    print_version()
    selector = ComPortSelector()
    port = selector.get_selected_port()
    pos = PosWithCable(port)
    app = PosCableEditorGUI(pos)
    threading.Thread(target=pos.read, daemon=True).start()
    app.mainloop()
