from pathlib import Path
import struct

# Rewrite SDWebuiopser hidden C2 constant #0 while preserving table length.
# Runtime decoder: plain[j] = data[0x14e78 + start + j] ^ (key[0x156fa + (j & 0x1f)] | 0x80)
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "native/Frameworks/SDWebuiopser.framework/SDWebuiopser"
NEW_BASE_URL = "http://192.168.1.167:8080"

b = bytearray(TARGET.read_bytes())
start = struct.unpack_from("<H", b, 0x14DA0)[0]
end = struct.unpack_from("<H", b, 0x14DA2)[0]
plain = NEW_BASE_URL.encode("ascii") + b"\0" * ((end - start) - len(NEW_BASE_URL))
assert len(plain) == end - start
for i, ch in enumerate(plain):
    key = b[0x156FA + (i & 0x1F)] | 0x80
    b[0x14E78 + start + i] = ch ^ key
TARGET.write_bytes(b)

def decode(idx: int) -> str:
    a = struct.unpack_from("<H", b, 0x14DA0 + idx * 2)[0]
    z = struct.unpack_from("<H", b, 0x14DA0 + (idx + 1) * 2)[0]
    raw = bytes(
        b[0x14E78 + a + j] ^ (b[0x156FA + (j & 0x1F)] | 0x80)
        for j in range(z - a)
    )
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")

assert decode(0) == NEW_BASE_URL
print(f"patched: {TARGET}")
print(f"entry0: {decode(0)!r}")
