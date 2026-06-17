"""Generators and decoders for the multimodal probe assets.

Each ``encode_*`` produces an image embedding a payload; each matching
``decode_*`` recovers it, so the verifier can prove a round-trip. Typography
techniques are render-only (recovering them needs OCR, which is out of scope).

All functions are pure and non-destructive: they return image bytes / Pillow
images and never write over committed files. The CLI layer decides where to
write.
"""

from __future__ import annotations

import io
import random

import numpy as np
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin

# Deterministic seed for the adaptive-LSB pixel permutation. Embedder and
# extractor must share it; in a real attack it would be a key handed to the
# decoder-equipped pipeline, not derivable from the image alone.
ADAPTIVE_LSB_SEED = 0x4155_4755_5354_5553  # "AUGUSTUS" bytes

_CANVAS = (512, 512)


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for name in ("DejaVuSans.ttf", "Arial.ttf", "Helvetica.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


# --------------------------------------------------------------------------- #
# Typography (render-only)
# --------------------------------------------------------------------------- #
def encode_typography_plain(text: str) -> bytes:
    """Plain black-on-white centered instruction text."""
    img = Image.new("RGB", _CANVAS, (255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, _CANVAS[1] // 2), text, fill=(0, 0, 0), font=_font(13))
    return _png_bytes(img)


def encode_typography_lowcontrast(text: str) -> bytes:
    """Near-invisible text ~5 RGB units off the white background."""
    img = Image.new("RGB", _CANVAS, (255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, _CANVAS[1] // 2), text, fill=(250, 250, 250), font=_font(13))
    return _png_bytes(img)


def encode_typography_tinyfont(text: str) -> bytes:
    """~11px fine-print footer on a near-white page."""
    img = Image.new("RGB", (1024, 1024), (246, 246, 246))
    draw = ImageDraw.Draw(img)
    draw.text((40, 930), "Confidential — internal review draft. Generated automatically by document service.",
              fill=(150, 150, 150), font=_font(11))
    draw.text((40, 952), text, fill=(20, 20, 20), font=_font(11))
    return _png_bytes(img)


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #
def encode_metadata_png_text(text: str) -> bytes:
    """Hide the payload in a PNG ``tEXt`` chunk (key 'Comment')."""
    img = Image.new("RGB", _CANVAS, (200, 200, 200))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Comment", text)
    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=meta)
    return buf.getvalue()


def decode_metadata_png_text(data: bytes) -> str:
    img = Image.open(io.BytesIO(data))
    return img.info.get("Comment", "")


_EXIF_IMAGE_DESCRIPTION = 0x010E


def encode_metadata_exif(text: str) -> bytes:
    """Hide the payload in JPEG EXIF ImageDescription."""
    img = Image.new("RGB", _CANVAS, (180, 180, 180))
    exif = img.getexif()
    exif[_EXIF_IMAGE_DESCRIPTION] = text
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


def decode_metadata_exif(data: bytes) -> str:
    img = Image.open(io.BytesIO(data))
    return img.getexif().get(_EXIF_IMAGE_DESCRIPTION, "")


# --------------------------------------------------------------------------- #
# Steganography helpers
# --------------------------------------------------------------------------- #
def _payload_bits(text: str) -> np.ndarray:
    """32-bit big-endian length prefix + UTF-8 bytes, as a bit array (MSB first)."""
    body = text.encode("utf-8")
    header = len(body).to_bytes(4, "big")
    raw = np.frombuffer(header + body, dtype=np.uint8)
    return np.unpackbits(raw)


def _bits_to_text(bits: np.ndarray) -> str:
    raw = np.packbits(bits[: (len(bits) // 8) * 8])
    if len(raw) < 4:
        return ""
    length = int.from_bytes(raw[:4].tobytes(), "big")
    body = raw[4 : 4 + length].tobytes()
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _base_image(size=(256, 256)) -> np.ndarray:
    rng = np.random.default_rng(7)
    return rng.integers(60, 200, size=(size[1], size[0], 3), dtype=np.uint8)


# --- Classical sequential LSB --------------------------------------------- #
def encode_stego_lsb(text: str) -> bytes:
    arr = _base_image().copy()
    flat = arr.reshape(-1)
    bits = _payload_bits(text)
    if bits.size > flat.size:
        raise ValueError("payload too large for cover image")
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits
    return _png_bytes(Image.fromarray(arr, "RGB"))


def decode_stego_lsb(data: bytes) -> str:
    arr = np.asarray(Image.open(io.BytesIO(data)).convert("RGB"))
    return _bits_to_text(arr.reshape(-1) & 1)


def scan_stego_lsb_committed(data: bytes) -> str:
    """Recover the LSB stream of a committed asset as printable text.

    The committed stego assets were produced by an out-of-tree encoder whose
    header framing differs from this repo's length-prefixed format, so the
    framed ``decode_stego_lsb`` cannot parse them. Auditing the committed file
    only needs to confirm the canary is PRESENT in the bit-plane, so this scans
    the raw MSB-first LSB stream into ASCII and lets the verifier substring-match
    the canary (the same method used to confirm the mapping by hand).
    """
    arr = np.asarray(Image.open(io.BytesIO(data)).convert("RGB"))
    raw = np.packbits(arr.reshape(-1) & 1).tobytes()
    return "".join(chr(b) if 32 <= b < 127 else " " for b in raw)


# --- Adaptive LSB: cryptographically-seeded pseudorandom subpixel order ---- #
def _adaptive_order(n: int) -> np.ndarray:
    perm = list(range(n))
    random.Random(ADAPTIVE_LSB_SEED).shuffle(perm)
    return np.asarray(perm, dtype=np.int64)


def encode_stego_adaptive_lsb(text: str) -> bytes:
    arr = _base_image().copy()
    flat = arr.reshape(-1)
    bits = _payload_bits(text)
    if bits.size > flat.size:
        raise ValueError("payload too large for cover image")
    order = _adaptive_order(flat.size)[: bits.size]
    flat[order] = (flat[order] & 0xFE) | bits
    return _png_bytes(Image.fromarray(arr, "RGB"))


def decode_stego_adaptive_lsb(data: bytes) -> str:
    arr = np.asarray(Image.open(io.BytesIO(data)).convert("RGB"))
    flat = arr.reshape(-1)
    order = _adaptive_order(flat.size)
    return _bits_to_text(flat[order] & 1)


# --- DCT-domain QIM -------------------------------------------------------- #
_DCT_Q = 40.0          # quantization step for QIM
_DCT_COEF = (3, 2)     # mid-frequency coefficient to modulate


def _dct_matrix(n: int = 8) -> np.ndarray:
    # Orthonormal DCT-II: row = frequency k, column = spatial index x.
    # m[k, x] = alpha(k) * cos(pi * (2x + 1) * k / (2n)), alpha(0)=sqrt(1/n).
    k = np.arange(n)
    m = np.sqrt(2.0 / n) * np.cos(np.pi * (2 * k[None, :] + 1) * k[:, None] / (2 * n))
    m[0, :] = np.sqrt(1.0 / n)
    return m


_D = _dct_matrix(8)


def encode_stego_dct(text: str) -> bytes:
    arr = _base_image((256, 256)).astype(np.float64)
    ch = arr[:, :, 2]  # blue channel
    bits = _payload_bits(text)
    h, w = ch.shape
    blocks = (h // 8) * (w // 8)
    if bits.size > blocks:
        raise ValueError("payload too large for cover image")
    bi = 0
    for by in range(0, h - 7, 8):
        for bx in range(0, w - 7, 8):
            if bi >= bits.size:
                break
            block = ch[by : by + 8, bx : bx + 8]
            coef = _D @ block @ _D.T
            q = round(coef[_DCT_COEF] / _DCT_Q)
            if (q % 2 + 2) % 2 != int(bits[bi]):
                q += 1
            coef[_DCT_COEF] = q * _DCT_Q
            ch[by : by + 8, bx : bx + 8] = _D.T @ coef @ _D
            bi += 1
    arr[:, :, 2] = np.clip(np.round(ch), 0, 255)
    return _png_bytes(Image.fromarray(arr.astype(np.uint8), "RGB"))


def decode_stego_dct(data: bytes) -> str:
    arr = np.asarray(Image.open(io.BytesIO(data)).convert("RGB")).astype(np.float64)
    ch = arr[:, :, 2]
    h, w = ch.shape
    bits = []
    for by in range(0, h - 7, 8):
        for bx in range(0, w - 7, 8):
            coef = _D @ ch[by : by + 8, bx : bx + 8] @ _D.T
            q = round(coef[_DCT_COEF] / _DCT_Q)
            bits.append((q % 2 + 2) % 2)
    return _bits_to_text(np.asarray(bits, dtype=np.uint8))


# --------------------------------------------------------------------------- #
def _png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# technique key -> (encoder, decoder|None). decoder None == render-only.
ENCODERS = {
    "typography_plain": (encode_typography_plain, None),
    "typography_lowcontrast": (encode_typography_lowcontrast, None),
    "typography_tinyfont": (encode_typography_tinyfont, None),
    "metadata_png_text": (encode_metadata_png_text, decode_metadata_png_text),
    "metadata_exif": (encode_metadata_exif, decode_metadata_exif),
    "stego_lsb": (encode_stego_lsb, decode_stego_lsb),
    "stego_adaptive_lsb": (encode_stego_adaptive_lsb, decode_stego_adaptive_lsb),
    "stego_dct": (encode_stego_dct, decode_stego_dct),
}

# Committed-file decoders that match the format of the assets shipped in the
# repo (independently confirmed). Used by ``verify.py --check-committed`` to
# audit the actual committed bytes, not just a freshly generated round-trip.
COMMITTED_DECODERS = {
    "metadata_png_text": decode_metadata_png_text,
    "metadata_exif": decode_metadata_exif,
    "stego_lsb": scan_stego_lsb_committed,
}
