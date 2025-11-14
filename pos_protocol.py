import ujson
import uos
from ucryptolib import aes

# POS Message Types
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

# AES Encryption Key (24 bytes)
AES_KEY_CR = bytes([
    0x76, 0x7d, 0x82, 0xb4, 0xf9, 0x3d, 0x4d, 0xf0,
    0x66, 0x58, 0x7a, 0x37, 0x93, 0x42, 0x3a, 0x73,
    0x56, 0xc0, 0x40, 0xcb, 0x90, 0xc8, 0x83, 0x74
])

STX, ETX = 0x87, 0x88

class Crc8:
    def calculate(self, data):
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

class AesEncryptorDecryptor:
    _instance = None
    
    def __init__(self):
        # ucryptolib aes requires key to be 16, 24, or 32 bytes
        # We have 24 bytes key, so use MODE_ECB (mode=1)
        self.aes_enc = aes(AES_KEY_CR, 1)
        self.aes_dec = aes(AES_KEY_CR, 1)
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = AesEncryptorDecryptor()
        return cls._instance
    
    def _pad(self, data):
        """PKCS7 padding"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad(self, data):
        """Remove PKCS7 padding"""
        if len(data) == 0:
            return data
        pad_len = data[-1]
        if pad_len > 16 or pad_len == 0:
            # Try zero padding removal (original code style)
            return data.rstrip(b'\x00')
        return data[:-pad_len]
    
    def encrypt(self, data):
        padded = self._pad(data)
        encrypted = bytearray()
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            # Pad to 16 bytes if needed
            if len(block) < 16:
                block += b'\x00' * (16 - len(block))
            encrypted += self.aes_enc.encrypt(block)
        return bytes(encrypted)
    
    def decrypt(self, encrypted_data):
        decrypted = bytearray()
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i+16]
            # Pad to 16 bytes if needed
            if len(block) < 16:
                block += b'\x00' * (16 - len(block))
            decrypted += self.aes_dec.decrypt(block)
        return self._unpad(bytes(decrypted))

class PosData:
    def __init__(self, msg_type, msg):
        self.msg_type = msg_type
        self.msg = msg.encode("utf-8") if isinstance(msg, str) else msg
        self.frame = bytearray()
        self.frame.append(STX)
        self.frame.append(msg_type)
        self.frame += self._encode_length(len(self.msg))
        self.frame += self.msg
        self.crc = Crc8().calculate(self.msg)
        self.frame.append(self.crc)
        self.frame.append(ETX)
    
    def _encode_length(self, length):
        return length.to_bytes(4, 'big')
    
    def get_prepared_data(self):
        return bytes(self.frame)

def get_enum_name(value):
    for name, val in vars(PosCableMessageType).items():
        if isinstance(val, int) and val == value:
            return name
    return "UNKNOWN"
