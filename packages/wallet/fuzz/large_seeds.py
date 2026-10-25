"""Generate large, structurally valid public blocks without a codec dependency."""
from pathlib import Path
import argparse
import struct


def block(length):
    count = 4095
    # Header, one transaction, version/flag/CompactSize, fixed input fields,
    # zero outputs and lock time. Each script length uses a u16 CompactSize.
    overhead = 79 + 8 + count * 43 + 5
    size, remainder = divmod(length - overhead, count)
    assert 253 <= size <= size + 1 <= 10_000
    result = bytearray(76) + bytes([0, 0, 1, 2, 0, 0, 0, 0, 253]) + struct.pack('<H', count)
    for index in range(count):
        script = size + (index < remainder)
        result += bytes(32) + bytes([255]) * 4 + bytes([253]) + struct.pack('<H', script)
        result += bytes(script) + bytes([255]) * 4
    result += bytes(5)
    assert len(result) == length
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('corpus', type=Path)
    args = parser.parse_args()
    args.corpus.mkdir(parents=True, exist_ok=True)
    for length in [2_000_000, 4_000_000]:
        (args.corpus/('block-'+str(length))).write_bytes(block(length))
