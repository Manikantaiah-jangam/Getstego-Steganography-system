import cv2
import numpy as np
import wave
import hashlib
import base64
from Crypto.Cipher import AES

# =========================
# AES-256-GCM ENCRYPTION
# =========================
def _derive_key(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()

def encrypt_msg(message: str, key: str) -> str:
    cipher = AES.new(_derive_key(key), AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_msg(data: str, key: str) -> str:
    raw = base64.b64decode(data)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(_derive_key(key), AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# =========================
# BIT UTILITIES
# =========================
_END_MARKER = "1111111111111110"

def msg_to_bin(msg: str) -> str:
    return ''.join(format(ord(c), '08b') for c in msg) + _END_MARKER

def bin_to_msg(binary: str) -> str:
    chars = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        if len(byte) < 8:
            break
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

# =========================
# CAPACITY CHECK
# =========================
def get_capacity(path: str, media_type: str) -> int:
    if media_type == "Image":
        img = cv2.imread(path)
        return img.size // 8

    if media_type == "Audio":
        with wave.open(path, 'rb') as a:
            return a.getnframes() // 8

    if media_type == "Video":
        cap = cv2.VideoCapture(path)
        frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        w = int(cap.get(3))
        h = int(cap.get(4))
        cap.release()
        return (frames * w * h * 3) // 8

    return 0

# =========================
# IMAGE STEGANOGRAPHY
# =========================
def embed_image(input_path, output_path, message, key):
    img = cv2.imread(input_path)
    encrypted = encrypt_msg(message, key)
    data = msg_to_bin(encrypted)

    flat = img.flatten()

    if len(data) > len(flat):
        raise ValueError("Message too large for image")

    flat[:len(data)] = (flat[:len(data)] & ~1) | np.array(list(data), dtype=np.uint8)
    cv2.imwrite(output_path, flat.reshape(img.shape), [cv2.IMWRITE_PNG_COMPRESSION, 0])

def extract_image(input_path, key):
    img = cv2.imread(input_path)
    bits = []

    for v in img.flatten():
        bits.append(str(v & 1))
        if ''.join(bits[-16:]) == _END_MARKER:
            break

    encrypted = bin_to_msg(''.join(bits[:-16]))
    return decrypt_msg(encrypted, key)

# =========================
# AUDIO STEGANOGRAPHY
# =========================
def embed_audio(input_path, output_path, message, key):
    with wave.open(input_path, 'rb') as audio:
        params = audio.getparams()
        frames = bytearray(audio.readframes(audio.getnframes()))

    encrypted = encrypt_msg(message, key)
    data = msg_to_bin(encrypted)

    if len(data) > len(frames):
        raise ValueError("Message too large for audio")

    for i, bit in enumerate(data):
        frames[i] = (frames[i] & ~1) | int(bit)

    with wave.open(output_path, 'wb') as out:
        out.setparams(params)
        out.writeframes(frames)

def extract_audio(input_path, key):
    with wave.open(input_path, 'rb') as audio:
        frames = bytearray(audio.readframes(audio.getnframes()))

    bits = []
    for b in frames:
        bits.append(str(b & 1))
        if ''.join(bits[-16:]) == _END_MARKER:
            break

    encrypted = bin_to_msg(''.join(bits[:-16]))
    return decrypt_msg(encrypted, key)

# =========================
# VIDEO STEGANOGRAPHY
# =========================
def embed_video(input_path, output_path, message, key):
    cap = cv2.VideoCapture(input_path)
    fps = cap.get(cv2.CAP_PROP_FPS)
    w = int(cap.get(3))
    h = int(cap.get(4))

    out = cv2.VideoWriter(
        output_path,
        cv2.VideoWriter_fourcc(*'FFV1'),
        fps,
        (w, h)
    )

    encrypted = encrypt_msg(message, key)
    data = msg_to_bin(encrypted)
    ptr = 0

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        flat = frame.flatten()
        for i in range(len(flat)):
            if ptr >= len(data):
                break
            flat[i] = (flat[i] & ~1) | int(data[ptr])
            ptr += 1

        out.write(flat.reshape(frame.shape))

    cap.release()
    out.release()

def extract_video(input_path, key):
    cap = cv2.VideoCapture(input_path)
    bits = []

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        for v in frame.flatten():
            bits.append(str(v & 1))
            if ''.join(bits[-16:]) == _END_MARKER:
                cap.release()
                encrypted = bin_to_msg(''.join(bits[:-16]))
                return decrypt_msg(encrypted, key)

    cap.release()
    return "No hidden message found"
