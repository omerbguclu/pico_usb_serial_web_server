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
import sys


class ComPortSelector:
    def __init__(self):
        self.selected_port = "/dev/ttyGS0"
        # self.window = tk.Toplevel()
        # self.window.title("COM Port Seçimi")
        # self.window.geometry("300x150")
        # self.window.grab_set()

        # ports = [port.device for port in serial.tools.list_ports.comports()]
        
        # # Linux'ta ttyGS0 varsa ekle
        # if sys.platform.startswith("linux"):
        #     ports += ["/dev/ttyGS0"]

        # ttk.Label(self.window, text="Lütfen COM port seçin:").pack(pady=10)
        # self.combo = ttk.Combobox(self.window, values=ports, state="readonly")
        # self.combo.pack()
        # ttk.Button(self.window, text="Devam", command=self.confirm_selection).pack(pady=10)

        # self.window.wait_window()

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
    DEVICE_INFO = 0x6D

STATUS_OPTIONS = [
    "IDLE",
    "PAYMENT_WAITING",
    "PAYMENT_CONTINUE",
    "PAYMENT_COMPLETED",
    "PAYMENT_FAILED",
    "PAYMENT_CANCELED",
    "SETTLEMENT_WAITING",
    "SETTLEMENT_COMPLETED",
    "SETTLEMENT_FAILED"
]

DEFAULT_PAYLOADS = {
    TypeOfData.POLL: json.dumps({"status": "IDLE"}),
    TypeOfData.PAYMENT_START_REQUEST: json.dumps({"price": "1453", "transactionType": "TRN_TYPE_SALE"}),
    TypeOfData.PAYMENT_INFO: json.dumps({}),
    TypeOfData.SETTLEMENT_START_REQUEST: json.dumps({}),
    TypeOfData.SETTLEMENT_INFO: json.dumps({}),
    TypeOfData.PAYMENT_FAILED_INFO: json.dumps({}),
    TypeOfData.PRINT_REQUEST: json.dumps({}),
    TypeOfData.DEVICE_INFO: json.dumps({"pykMaliNo": "BCK00000010"})
}


class PosSerialCommApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ECR Connect PC - ECP")

        # COM port display
        self.com_label = tk.Label(root, text="Seçilen COM: (bağlı değil)")
        self.com_label.grid(row=0, column=0, padx=5, pady=5)

        # Connect/Disconnect buttons
        self.start_button = tk.Button(root, text="Bağlan", command=self.start_connection)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)

        self.stop_button = tk.Button(root, text="Bağlantıyı Kes", command=self.stop_connection, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)

        # Clear text box
        self.clear_button = tk.Button(root, text="Temizle", command=self.clear_textbox)
        self.clear_button.grid(row=0, column=4, padx=5, pady=5)

        # Payload editors
        self.payload_frame = tk.LabelFrame(root, text="Mesaj Kontrolü")
        self.payload_frame.grid(row=1, column=0, columnspan=5, padx=8, pady=8, sticky="nsew")
        root.grid_rowconfigure(1, weight=1)
        self.payload_texts = {}
        self.label_frames = {}
        self.payload_controls = {}
        self.create_payload_editors()
        self.set_payload_controls_state(False)

        # Messages Text Area
        self.messages_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=12)
        self.messages_area.grid(row=2, column=0, columnspan=5, padx=8, pady=8, sticky="nsew")
        root.grid_rowconfigure(2, weight=1)

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

    def create_payload_editors(self):
        self.auto_poll_var = tk.BooleanVar(value=False)
        self.auto_poll_job = None

        top_controls = tk.Frame(self.payload_frame)
        top_controls.pack(fill="x", padx=5, pady=5)
        tk.Checkbutton(
            top_controls,
            text="Auto POLL (her 1 saniyede bir)",
            variable=self.auto_poll_var,
            command=self.toggle_auto_poll
        ).pack(side=tk.LEFT, padx=5)
        self.sale_scenario_button = tk.Button(top_controls, text="Satış Senaryosu", command=self.run_sale_scenario, state=tk.DISABLED)
        self.sale_scenario_button.pack(side=tk.LEFT, padx=5)

        self.payload_canvas = tk.Canvas(self.payload_frame, height=360)
        self.payload_canvas.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar = tk.Scrollbar(self.payload_frame, orient="vertical", command=self.payload_canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.payload_canvas.configure(yscrollcommand=scrollbar.set)
        self.payload_inner = tk.Frame(self.payload_canvas)
        self.payload_canvas.create_window((0, 0), window=self.payload_inner, anchor="nw")
        self.payload_inner.bind("<Configure>", lambda e: self.payload_canvas.configure(scrollregion=self.payload_canvas.bbox("all")))

        self.poll_status_var = tk.StringVar(value="IDLE")

        payload_configs = [
            {"type": TypeOfData.POLL, "title": "POLL"},
            {"type": TypeOfData.PAYMENT_START_REQUEST, "title": "PAYMENT_START"},
            {"type": TypeOfData.PAYMENT_INFO, "title": "PAYMENT_INFO"},
            {"type": TypeOfData.SETTLEMENT_START_REQUEST, "title": "SETTLEMENT_START"},
            {"type": TypeOfData.SETTLEMENT_INFO, "title": "SETTLEMENT_INFO"},
            {"type": TypeOfData.PAYMENT_FAILED_INFO, "title": "PAYMENT_FAILED_INFO"},
            {"type": TypeOfData.PRINT_REQUEST, "title": "PRINT"},
            {"type": TypeOfData.DEVICE_INFO, "title": "DEVICE_INFO"}
        ]

        for idx, cfg in enumerate(payload_configs):
            self.create_payload_row(idx, cfg["type"], cfg["title"])

    def create_payload_row(self, row_idx, msg_type, title):
        row_frame = tk.Frame(self.payload_inner, borderwidth=1, relief="groove", padx=4, pady=4)
        row_frame.grid(row=row_idx, column=0, sticky="ew", pady=3)
        row_frame.grid_columnconfigure(2, weight=1)
        row_frame.default_bg = row_frame.cget("bg")
        row_frame.after_id = None
        label = tk.Label(row_frame, text=title, width=18, anchor="w")
        label.grid(row=0, column=0, sticky="w")
        control_frame = tk.Frame(row_frame)
        control_frame.grid(row=0, column=1, padx=5, sticky="nw")
        send_btn = tk.Button(control_frame, text="Gönder", width=12, command=lambda t=msg_type: self.send_from_editor(t), state=tk.DISABLED)
        send_btn.pack(fill="x")
        if msg_type == TypeOfData.POLL:
            status_combo = ttk.Combobox(control_frame, values=STATUS_OPTIONS, state="readonly", width=16)
            status_combo.set("IDLE")
            status_combo.pack(pady=3)
            tk.Button(control_frame, text="Durumu Uygula", command=lambda: self.apply_poll_status(status_combo.get())).pack(fill="x")
            self.poll_status_combo = status_combo
        text = tk.Text(row_frame, width=70, height=3, wrap=tk.WORD)
        text.insert("1.0", self.get_default_payload(msg_type))
        text.grid(row=0, column=2, sticky="ew")
        self.payload_texts[msg_type] = text
        self.label_frames[msg_type] = row_frame
        self.payload_controls[msg_type] = {"button": send_btn, "text": text}

    def get_default_payload(self, msg_type):
        return DEFAULT_PAYLOADS.get(msg_type, "{}")

    def set_payload_text(self, msg_type, content):
        widget = self.payload_texts.get(msg_type)
        if widget:
            widget.delete("1.0", tk.END)
            widget.insert("1.0", content)

    def get_payload_text(self, msg_type):
        widget = self.payload_texts.get(msg_type)
        if widget:
            return widget.get("1.0", tk.END).strip()
        return "{}"

    def send_from_editor(self, msg_type):
        payload = self.get_payload_text(msg_type)
        if not payload:
            payload = "{}"
        self.flash_message_type(msg_type)
        self.send_message(msg_type, payload)

    def apply_poll_status(self, status):
        self.poll_status_var.set(status)
        payload_text = self.get_payload_text(TypeOfData.POLL)
        try:
            payload = json.loads(payload_text) if payload_text else {}
        except json.JSONDecodeError:
            payload = {}
        payload["status"] = status
        self.set_payload_text(TypeOfData.POLL, json.dumps(payload, ensure_ascii=False))
        self.append_message(f"POLL status güncellendi → {status}")

    def flash_message_type(self, msg_type):
        frame = self.label_frames.get(msg_type)
        if not frame:
            return
        if getattr(frame, "after_id", None):
            frame.after_cancel(frame.after_id)
        original = getattr(frame, "default_bg", frame.cget("bg"))
        frame.config(bg="#ffe08a")
        def reset():
            frame.config(bg=original)
            frame.after_id = None
        frame.after_id = frame.after(400, reset)

    def toggle_auto_poll(self):
        if self.auto_poll_var.get():
            if not (self.serial_conn and self.serial_conn.is_open):
                messagebox.showwarning("Auto POLL", "Önce COM bağlantısı kurmalısınız.")
                self.auto_poll_var.set(False)
                return
            self.schedule_auto_poll()
        else:
            if self.auto_poll_job:
                self.root.after_cancel(self.auto_poll_job)
                self.auto_poll_job = None

    def schedule_auto_poll(self):
        if not self.auto_poll_var.get():
            self.auto_poll_job = None
            return
        if self.serial_conn and self.serial_conn.is_open:
            self.send_from_editor(TypeOfData.POLL)
        self.auto_poll_job = self.root.after(1000, self.schedule_auto_poll)

    def set_payload_controls_state(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        for info in self.payload_controls.values():
            info["button"].config(state=state)
        if hasattr(self, "poll_status_combo"):
            self.poll_status_combo.config(state="readonly" if enabled else "disabled")
        if hasattr(self, "sale_scenario_button"):
            self.sale_scenario_button.config(state=state)

    def start_connection(self):
        selector = ComPortSelector()
        port = selector.get_selected_port()
        if not port:
            return
        try:
            self.serial_conn = serial.Serial(port, baudrate=115200, timeout=0.01)
            self.selected_port = port
            self.com_label.config(text=f"Seçilen COM: {port}")
            self.append_message(f"COM port bağlantısı açıldı: {port}")
            self.set_payload_controls_state(True)
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.is_running = True
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except serial.SerialException as e:
            messagebox.showerror("Bağlantı Hatası", str(e))
            self.serial_conn = None

    def stop_connection(self):
        self.is_running = False
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.close()
            except serial.SerialException:
                pass
        self.serial_conn = None
        self.selected_port = None
        self.com_label.config(text="Seçilen COM: (bağlı değil)")
        self.set_payload_controls_state(False)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if hasattr(self, "auto_poll_job") and self.auto_poll_job:
            self.root.after_cancel(self.auto_poll_job)
            self.auto_poll_job = None
        if hasattr(self, "auto_poll_var"):
            self.auto_poll_var.set(False)
        self.append_message("Bağlantı sonlandırıldı.")

    def send_message(self, typeOfDataPrm: int, msg):
        if not msg:
            msg = "{}"
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
                    print("1")
                    self.flash_message_type(msg_type)
                    print("2")
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
            self.stop_connection()

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
            TypeOfData.DEVICE_INFO: "DEVICE_INFO"
        }
        return mapping.get(v, f"0x{v:02X}")

    def clear_textbox(self):
        self.messages_area.delete('1.0', tk.END)

    def send_idle(self):
        self.apply_poll_status("IDLE")
        self.send_from_editor(TypeOfData.POLL)

    def send_payment_waiting(self):
        self.apply_poll_status("PAYMENT_WAITING")
        self.send_from_editor(TypeOfData.POLL)

        
    def send_settlement_info(self):
        self.send_from_editor(TypeOfData.SETTLEMENT_INFO)


    def send_sale(self):
        self.send_from_editor(TypeOfData.PAYMENT_START_REQUEST)

    def send_payment_info(self):
        self.send_from_editor(TypeOfData.PAYMENT_INFO)

    def send_settlement(self):
        self.send_from_editor(TypeOfData.SETTLEMENT_START_REQUEST)

    def send_print_info(self):
        self.send_from_editor(TypeOfData.PRINT_REQUEST)

    def send_device_info(self):
        self.send_from_editor(TypeOfData.DEVICE_INFO)

    def send_payment_failed_info(self):
        self.send_from_editor(TypeOfData.PAYMENT_FAILED_INFO)

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
    app = PosSerialCommApp(root)
    root.mainloop()
