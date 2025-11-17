import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import ttk
import json
from enum import Enum
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import serial
import serial.tools.list_ports


class ComPortSelector:
    def __init__(self):
        self.selected_port = None
        self.window = tk.Toplevel()
        self.window.title("COM Port Seçimi")
        self.window.geometry("300x150")
        self.window.grab_set()

        ports = [port.device for port in serial.tools.list_ports.comports()]
        ttk.Label(self.window, text="Lütfen COM port seçin:").pack(pady=10)

        self.combo = ttk.Combobox(self.window, values=ports, state="readonly")
        self.combo.pack()

        ttk.Button(self.window, text="Devam", command=self.confirm_selection).pack(pady=10)

        self.window.wait_window()

    def confirm_selection(self):
        self.selected_port = self.combo.get()
        self.window.destroy()

    def get_selected_port(self):
        return self.selected_port

STX, ETX = 0x87, 0x88
class TypeOfData:
    ACK = 0x64
    NACK = 0x65
    POLL = 0x66
    PRINT_REQUEST = 0x67
    PAYMENT_START_REQUEST = 0x68
    PAYMENT_INFO = 0x69
    SETTLEMENT_START_REQUEST = 0x6A
    SETTLEMENT_INFO = 0x6B
    PAYMENT_FAILED_INFO = 0x6C
    SETTLEMENT_WAITING = 0x71
    DEVICE_INFO = 0x6D
    # Runtime status notifications from Android (not used for detection anymore)
    PAYMENT_IN_PROGRESS = 0x96  # 150
    PAYMENT_COMPLETED = 0x97    # 151
    PAYMENT_FAILED = 0x98       # 152

class FMCommunication:
    def fm_widgets(self):
       
        # Data Entry (additional data to send)
        self.data_label = tk.Label(self.tab1, text="Data:")
        self.data_label.grid(row=3, column=0)
        self.data_entry = tk.Entry(self.tab1, width=50)
        self.data_entry.grid(row=3, column=1, columnspan=3)

        # Get Total Z Report number
        self.button_z_report_number = tk.Button(self.tab1, text="Kayıtlı Z Sayısı", command=lambda: self.send_message(TypeOfData.ZREPORTNUMBER))
        self.button_z_report_number.grid(row=5, column=1)
        self.button_z_report_number.config(state=tk.DISABLED)  # Initially disabled until a client connects
        
        # Get data of Z Report
        self.button_z_report_data = tk.Button(self.tab1, text="Belirli Z raporu Datası", command=lambda: self.send_message(TypeOfData.ZREPORTDATA))
        self.button_z_report_data.grid(row=5, column=2)
        self.button_z_report_data.config(state=tk.DISABLED)  # Initially disabled until a client connects

        # Get all data of FM
        self.button_dump = tk.Button(self.tab1, text="Dump FM", command=lambda: self.send_message(TypeOfData.DUMPALL))
        self.button_dump.grid(row=5, column=3)
        self.button_dump.config(state=tk.DISABLED)  # Initially disabled until a client connects

        # Get last cumulative values
        self.button_cumulative = tk.Button(self.tab1, text="Kümülatif", command=lambda: self.send_message(TypeOfData.CUMULATIVE))
        self.button_cumulative.grid(row=5, column=4)
        self.button_cumulative.config(state=tk.DISABLED)  # Initially disabled until a client connects

class DailyMemory:
    def dm_widgets(self):
        # get all data of DM
        self.button_dm_get_all_data = tk.Button(self.tab2, text="Dump DM", command=lambda: TCPServerApp.send_message(self, TypeOfData.DMDUMP))
        self.button_dm_get_all_data.grid(row=5, column=1)
        
    
class TCPServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ECR Connect PC - ECP")

        # COM port display
        self.com_label = tk.Label(root, text="Seçilen COM: (bağlı değil)")
        self.com_label.grid(row=0, column=0, padx=5, pady=5)

        # Connect/Disconnect buttons
        self.start_button = tk.Button(root, text="Bağlan", command=self.start_server)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)

        self.stop_button = tk.Button(root, text="Bağlantıyı Kes", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)

        # Clear text box
        self.clear_button = tk.Button(root, text="Temizle", command=self.clear_textbox)
        self.clear_button.grid(row=0, column=4, padx=5, pady=5)

        # Action buttons (placed into a uniform grid frame)
        self.buttons_frame = tk.Frame(root)
        self.buttons_frame.grid(row=1, column=0, columnspan=5, padx=8, pady=8, sticky="nsew")

        btn_opts = {"width": 18, "height": 2}
        self.idle_button = tk.Button(self.buttons_frame, text="IDLE", command=self.send_idle, **btn_opts)
        self.idle_button.config(state=tk.DISABLED)

        self.sale_button = tk.Button(self.buttons_frame, text="Satış", command=self.send_sale, **btn_opts)
        self.sale_button.config(state=tk.DISABLED)

        self.payment_waiting_button = tk.Button(self.buttons_frame, text="Ödeme Bekleniyor", command=self.send_payment_waiting, **btn_opts)
        self.payment_waiting_button.config(state=tk.DISABLED)

        self.payment_info_button = tk.Button(self.buttons_frame, text="PAYMENT_INFO", command=self.send_payment_info, **btn_opts)
        self.payment_info_button.config(state=tk.DISABLED)

        self.settlement_button = tk.Button(self.buttons_frame, text="SETTLEMENT", command=self.send_settlement, **btn_opts)
        self.settlement_button.config(state=tk.DISABLED)

        self.settlement_info_button = tk.Button(self.buttons_frame, text="SETTLEMENT_INFO", command=self.send_settlement_info, **btn_opts)
        self.settlement_info_button.config(state=tk.DISABLED)

        self.print_info_button = tk.Button(self.buttons_frame, text="Print", command=self.send_print_info, **btn_opts)
        self.print_info_button.config(state=tk.DISABLED)

        self.device_info_button = tk.Button(self.buttons_frame, text="DEVICE_INFO", command=self.send_device_info, **btn_opts)
        self.device_info_button.config(state=tk.DISABLED)
        self.payment_failed_info_button = tk.Button(self.buttons_frame, text="PAYMENT_FAILED_INFO", command=self.send_payment_failed_info, **btn_opts)
        self.payment_failed_info_button.config(state=tk.DISABLED)
        self.settlement_waiting_button = tk.Button(self.buttons_frame, text="SETTLEMENT_WAITING", command=self.send_settlement_waiting, **btn_opts)
        self.settlement_waiting_button.config(state=tk.DISABLED)

        # New: Sale Scenario button
        self.sale_scenario_button = tk.Button(self.buttons_frame, text="SATIŞ ÖRNEĞİ", command=self.run_sale_scenario, **btn_opts)
        self.sale_scenario_button.config(state=tk.DISABLED)

        # place buttons in 3 columns
        self.action_buttons = [
            self.idle_button,
            self.sale_button,
            self.payment_waiting_button,
            self.payment_info_button,
            self.settlement_button,
            self.settlement_info_button,
            self.print_info_button,
            self.device_info_button,
            self.payment_failed_info_button,
            self.settlement_waiting_button,
            self.sale_scenario_button,
        ]
        for i, b in enumerate(self.action_buttons):
            r, c = divmod(i, 3)
            b.grid(row=r, column=c, padx=6, pady=6, sticky="nsew")
        for c in range(3):
            self.buttons_frame.grid_columnconfigure(c, weight=1)

        # Messages Text Area (moved below buttons)
        self.messages_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=40)
        self.messages_area.grid(row=2, column=0, columnspan=5, padx=8, pady=8, sticky="nsew")

        # Serial bağlantı yönetimi
        self.serial_conn = None
        self.selected_port = None
        self.is_running = False

        # Runtime RX tracking
        self._lock = threading.Lock()
        self.last_rx_type = None
        self.payment_start_resp_event = threading.Event()
        self.payment_completed_event = threading.Event()
        self.payment_info_resp_event = threading.Event()
        self.poll_resp_event = threading.Event()
        self.mismatch_event = threading.Event()
        self.expected_resp_type = None

    def set_action_buttons_state(self, state):
        for btn in self.action_buttons:
            btn.config(state=state)

    def start_server(self):
        selector = ComPortSelector()
        port = selector.get_selected_port()
        if not port:
            return
        try:
            self.serial_conn = serial.Serial(port, baudrate=115200, timeout=0.01)
            self.selected_port = port
            self.com_label.config(text=f"Seçilen COM: {port}")
            self.append_message(f"COM port bağlantısı açıldı: {port}")
            self.set_action_buttons_state(tk.NORMAL)
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.is_running = True
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except serial.SerialException as e:
            messagebox.showerror("Bağlantı Hatası", str(e))
            self.serial_conn = None

    def stop_server(self):
        self.is_running = False
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.close()
            except serial.SerialException:
                pass
        self.serial_conn = None
        self.selected_port = None
        self.com_label.config(text="Seçilen COM: (bağlı değil)")
        self.set_action_buttons_state(tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.append_message("Bağlantı sonlandırıldı.")

    def send_message(self, typeOfDataPrm: int, msg):
        if self.serial_conn and self.serial_conn.is_open:
            # Beklenen cevap tipini POLL ya da PAYMENT_START için ayarlayalım
            with self._lock:
                if typeOfDataPrm == TypeOfData.POLL:
                    self.expected_resp_type = TypeOfData.POLL
                elif typeOfDataPrm == TypeOfData.PAYMENT_START_REQUEST:
                    self.expected_resp_type = TypeOfData.PAYMENT_START_REQUEST
                else:
                    self.expected_resp_type = None
            frame = PosData(typeOfDataPrm, msg).get_prepared_data()
            enc_data = aes_enc_dec.encrypt(frame)
            type_name = self.type_name_of(typeOfDataPrm)

            # Human readable outbound log
            self.append_message(f"GÖNDERİLEN İSTEK ({type_name})")
            try:
                parsed = json.loads(msg)
                if isinstance(parsed, dict) and parsed:
                    for key, value in parsed.items():
                        self.append_message(f"  {key}: {value}")
                elif isinstance(parsed, list):
                    self.append_message(f"  İçerik: {json.dumps(parsed, ensure_ascii=False)}")
                else:
                    self.append_message(f"  İçerik: {parsed}")
            except Exception:
                if msg:
                    self.append_message(f"  İçerik: {msg}")
                else:
                    self.append_message("  İçerik: (boş)")

            frame_hex = ' '.join(f"{b:02X}" for b in frame)
            self.append_message(f"  RAW HEX: {frame_hex}")
            enc_hex = ' '.join(f"{b:02X}" for b in enc_data)
            self.append_message(f"  ŞİFRELİ HEX: {enc_hex}")
            self.append_message("")
            try:
                self.serial_conn.write(enc_data)
            except serial.SerialException as e:
                messagebox.showerror("Yazma Hatası", str(e))
        else:
            messagebox.showwarning("Uyarı", "Önce COM bağlantısı kurun.")

    def receive_messages(self):
        try:
            buffer = b""
            while self.is_running and self.serial_conn and self.serial_conn.is_open:
                enc_bytes = self.serial_conn.read(1024)
                if not enc_bytes:
                    time.sleep(0.01)
                    continue

                buffer += enc_bytes

                # AES/ECB requires data aligned to 16 bytes. Beklemeye devam et.
                if len(buffer) % 16 != 0:
                    continue

                try:
                    dec = aes_enc_dec.decrypt(buffer)
                    buffer = b""
                    if len(dec) < 8:
                        continue
                    cursor = 0
                    if dec[cursor] != STX:
                        continue
                    cursor += 1
                    msg_type = dec[cursor]
                    type_name = self.type_name_of(msg_type)
                    cursor += 1
                    data_len = int.from_bytes(dec[cursor:cursor+4], byteorder='big')
                    cursor += 4
                    if cursor + data_len + 2 > len(dec):
                        continue
                    data_bytes = dec[cursor:cursor+data_len]
                    try:
                        plain = data_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        plain = ''
                    # Log RX with type, raw and plain
                    dec_hex = ' '.join(f"{b:02X}" for b in dec)
                    self.append_message(f"GELEN CEVAP ({type_name})")
                    self.append_message(f"  RAW HEX: {dec_hex}")

                    status_upper = None
                    if plain:
                        try:
                            parsed = json.loads(plain)
                            if isinstance(parsed, dict) and parsed:
                                for key, value in parsed.items():
                                    self.append_message(f"  {key}: {value}")
                                status_upper = str(parsed.get("status", "")).upper()
                            elif isinstance(parsed, list):
                                self.append_message(f"  İçerik: {json.dumps(parsed, ensure_ascii=False)}")
                            else:
                                self.append_message(f"  İçerik: {parsed}")
                        except Exception:
                            self.append_message(f"  İçerik: {plain}")
                    else:
                        self.append_message("  İçerik: (boş)")
                    self.append_message("")

                    # Track last RX type and completion
                    with self._lock:
                        self.last_rx_type = msg_type
                        # Yanıt tipi eşleşme kontrolü (sadece POLL ve PAYMENT_START için katı kontrol)
                        if self.expected_resp_type in (TypeOfData.POLL, TypeOfData.PAYMENT_START_REQUEST):
                            if msg_type != self.expected_resp_type:
                                exp = self.type_name_of(self.expected_resp_type)
                                got = self.type_name_of(msg_type)
                                self.append_message(f"! Hata: Yanlış cevap tipi. Beklenen={exp}, Gelen={got}")
                                self.mismatch_event.set()
                            # Bir cevap geldi; beklenen tipi sıfırla
                            self.expected_resp_type = None
                    # PAYMENT_START yanıtı (type 0x68) geldi mi?
                    if msg_type == TypeOfData.PAYMENT_START_REQUEST:
                        self.payment_start_resp_event.set()
                    # POLL cevabı geldi bilgisini işaretle
                    if msg_type == TypeOfData.POLL:
                        self.poll_resp_event.set()
                    # PAYMENT_COMPLETED is reported via POLL status
                    if msg_type == TypeOfData.POLL and status_upper == "PAYMENT_COMPLETED":
                        self.payment_completed_event.set()
                    # PAYMENT_INFO response
                    if msg_type == TypeOfData.PAYMENT_INFO:
                        self.payment_info_resp_event.set()
                except Exception as e:
                    self.append_message(f"Decrypt/parse error: {e}")
        except Exception as e:
            self.append_message(f"Error: {e}")
        finally:
            self.stop_server()

    def append_message(self, message):
        """Append a message to the text area."""
        self.messages_area.config(state=tk.NORMAL)
        self.messages_area.insert(tk.END, message + '\n')
        self.messages_area.yview(tk.END)

    def type_name_of(self, v: int) -> str:
        mapping = {
            TypeOfData.ACK: "ACK",
            TypeOfData.NACK: "NACK",
            TypeOfData.POLL: "POLL",
            TypeOfData.PRINT_REQUEST: "PRINT_REQUEST",
            TypeOfData.PAYMENT_START_REQUEST: "PAYMENT_START",
            TypeOfData.PAYMENT_INFO: "PAYMENT_INFO_REQUEST",
            TypeOfData.SETTLEMENT_START_REQUEST: "SETTLEMENT_START",
            TypeOfData.SETTLEMENT_INFO: "SETTLEMENT_INFO",
            TypeOfData.PAYMENT_FAILED_INFO: "PAYMENT_FAILED_INFO",
            TypeOfData.SETTLEMENT_WAITING: "SETTLEMENT_WAITING",
            TypeOfData.DEVICE_INFO: "DEVICE_INFO",
            TypeOfData.PAYMENT_IN_PROGRESS: "PAYMENT_IN_PROGRESS",
            TypeOfData.PAYMENT_COMPLETED: "PAYMENT_COMPLETED",
            TypeOfData.PAYMENT_FAILED: "PAYMENT_FAILED",
        }
        return mapping.get(v, f"0x{v:02X}")

    def clear_textbox(self):
        self.messages_area.delete('1.0', tk.END)

    def send_idle(self):
        self.send_message(TypeOfData.POLL, json.dumps({
            "status": "IDLE"
        }))

    def send_payment_waiting(self):
        self.send_message(TypeOfData.POLL, json.dumps({
            "status": "PAYMENT_WAITING"
        }))

        
    def send_settlement_info(self):
        # Boş istek
        self.send_message(TypeOfData.SETTLEMENT_INFO, json.dumps({}))


    def send_sale(self):
        self.send_message(TypeOfData.PAYMENT_START_REQUEST, json.dumps({
            "price": "1453",
            "transactionType": "TRN_TYPE_SALE"
        }))

    def send_payment_info(self):
        self.send_message(TypeOfData.PAYMENT_INFO, json.dumps({
        }))

    def send_settlement(self):
        self.send_message(TypeOfData.SETTLEMENT_START_REQUEST, json.dumps({
        }))

    def send_print_info(self):
        self.send_message(TypeOfData.PRINT_REQUEST, json.dumps({    
        }))

    def send_device_info(self):
        self.send_message(TypeOfData.DEVICE_INFO, json.dumps({
            "pykMaliNo": "BCK00000010"
        }))

    def send_payment_failed_info(self):
        # Boş istek
        self.send_message(TypeOfData.PAYMENT_FAILED_INFO, json.dumps({}))

    def send_settlement_waiting(self):
        self.send_message(TypeOfData.SETTLEMENT_WAITING, json.dumps({
            "status": "SETTLEMENT_WAITING"
        }))

    # New: Satış örneği akışı
    def run_sale_scenario(self):
        threading.Thread(target=self._sale_scenario_worker, daemon=True).start()

    def _sale_scenario_worker(self):
        try:
            # Disable button during scenario
            self.sale_scenario_button.config(state=tk.DISABLED)
            self.append_message("=== SATIŞ ÖRNEĞİ BAŞLADI ===")

            # 1) İlk 5 POLL -> IDLE, her biri için cevap bekle
            for i in range(5):
                self.poll_resp_event.clear()
                self.mismatch_event.clear()
                self.append_message(f"[STEP] IDLE POLL {i+1}/5")
                self.send_idle()
                # 1.5 sn içinde POLL cevabı gelmeli
                if self.mismatch_event.wait(timeout=0.0):
                    return
                if not self.poll_resp_event.wait(timeout=1.5):
                    self.append_message("! Hata: IDLE POLL cevabı gelmedi")
                    return
                time.sleep(0.15)

            # 2) SATIŞ (PAYMENT_START) ve yanıtını bekle
            self.payment_start_resp_event.clear()
            self.mismatch_event.clear()
            self.append_message("[STEP] PAYMENT_START gönderiliyor")
            self.send_sale()
            if self.mismatch_event.wait(timeout=0.0):
                return
            if not self.payment_start_resp_event.wait(timeout=10.0):
                self.append_message("! Hata: PAYMENT_START yanıtı gelmedi (10 sn)")
                return

            # 3) PAYMENT_COMPLETED alana kadar hızlı PAYMENT_WAITING POLL at
            self.payment_completed_event.clear()
            self.payment_info_resp_event.clear()
            self.append_message("[STEP] PAYMENT_COMPLETED bekleniyor (hızlı POLL: PAYMENT_WAITING)")
            start = time.time()
            while time.time() - start < 60:
                self.poll_resp_event.clear()
                self.mismatch_event.clear()
                self.send_payment_waiting()
                # 700 ms içinde POLL cevabı gelmeli
                if self.mismatch_event.wait(timeout=0.0):
                    return
                if not self.poll_resp_event.wait(timeout=0.7):
                    self.append_message("! Uyarı: PAYMENT_WAITING POLL cevabı gelmedi (devam ediliyor)")
                # POLL içinde PAYMENT_COMPLETED bildirildiyse bitir
                if self.payment_completed_event.is_set():
                    break
                time.sleep(0.15)

            if not self.payment_completed_event.is_set():
                self.append_message("! Hata: PAYMENT_COMPLETED alınamadı (60 sn)")
                return

            # 4) PAYMENT_COMPLETED geldi, PAYMENT_INFO iste ve yanıtını bekle
            self.append_message("PAYMENT_COMPLETED alındı -> PAYMENT_INFO isteği gönderiliyor")
            self.send_payment_info()
            if not self.payment_info_resp_event.wait(timeout=10.0):
                self.append_message("! Zaman aşımı: PAYMENT_INFO yanıtı gelmedi (10 sn)")
                return

            self.append_message("=== SATIŞ ÖRNEĞİ BİTTİ ===")
        finally:
            self.sale_scenario_button.config(state=tk.NORMAL)


class Crc8:
    def calculate(self, data: bytes) -> int:
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
    
class PosData:
    def __init__(self, msg_type: int, msg: str):
        self.msg_type = msg_type
        self.msg = msg.encode("utf-8")
        self.frame = bytearray()
        self.frame.append(STX)
        self.frame.append(msg_type)
        self.frame += self.encode_length(len(self.msg))
        self.frame += self.msg
        self.crc = Crc8().calculate(self.msg)
        self.frame.append(self.crc)
        self.frame.append(ETX)
        print(f"Msg: {msg} - Crc:{self.crc:02X}")

    def encode_length(self, length: int) -> bytes:
        return length.to_bytes(4, byteorder='big')

    def get_prepared_data(self) -> bytes:
        return self.frame


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
    
AesEncryptorDecryptor.get_instance()
aes_enc_dec = AesEncryptorDecryptor.get_instance()

if __name__ == "__main__":
    root = tk.Tk()
    app = TCPServerApp(root)
    root.mainloop()
