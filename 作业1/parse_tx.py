#!/usr/bin/env python3
"""Parse a Bitcoin transaction from raw hex without using Bitcoin Core RPC."""

import argparse
import hashlib
import json
from pathlib import Path


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.rows = []

    def take(self, size: int, field: str, decoded=None) -> bytes:
        start = self.pos
        end = start + size
        if end > len(self.data):
            raise ValueError(f"{field}: need {size} bytes at offset {start}, only {len(self.data)-start} remain")
        raw = self.data[start:end]
        self.pos = end
        self.rows.append({
            "byte_start": start,
            "byte_end": end - 1,
            "bit_start": start * 8,
            "bit_end": end * 8 - 1,
            "length": size,
            "field": field,
            "hex": raw.hex(),
            "binary": " ".join(f"{b:08b}" for b in raw),
            "decoded": str(decoded) if decoded is not None else "",
        })
        return raw

    def compact_size(self, field: str) -> int:
        first = self.data[self.pos]
        size = 1 if first < 0xFD else {0xFD: 3, 0xFE: 5, 0xFF: 9}[first]
        raw = self.data[self.pos:self.pos + size]
        if len(raw) != size:
            raise ValueError(f"truncated CompactSize at offset {self.pos}")
        value = first if size == 1 else int.from_bytes(raw[1:], "little")
        self.take(size, field, value)
        return value


def classify_script(script: bytes) -> str:
    if len(script) == 22 and script[:2] == b"\x00\x14":
        return "P2WPKH: OP_0 PUSH20 " + script[2:].hex()
    if len(script) == 34 and script[:2] == b"\x00\x20":
        return "P2WSH: OP_0 PUSH32 " + script[2:].hex()
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return "P2TR: OP_1 PUSH32 " + script[2:].hex()
    if script.startswith(b"\x6a"):
        return "OP_RETURN " + script[1:].hex()
    if (len(script) == 25 and script[:3] == b"\x76\xa9\x14"
            and script[-2:] == b"\x88\xac"):
        return "P2PKH: OP_DUP OP_HASH160 PUSH20 " + script[3:23].hex() + " OP_EQUALVERIFY OP_CHECKSIG"
    return "unclassified script"


def parse_transaction(data: bytes):
    r = Reader(data)
    version_raw = r.take(4, "version", int.from_bytes(data[:4], "little", signed=True))

    segwit = len(data) >= 6 and data[4] == 0 and data[5] != 0
    if segwit:
        r.take(1, "marker", "SegWit marker")
        r.take(1, "flag", "witness present")

    body_start = r.pos
    input_count = r.compact_size("input_count")
    inputs = []
    for i in range(input_count):
        prev_raw = r.take(32, f"input[{i}].previous_txid")
        prev_txid = prev_raw[::-1].hex()
        prev_vout_raw = r.take(4, f"input[{i}].previous_vout")
        prev_vout = int.from_bytes(prev_vout_raw, "little")
        script_len = r.compact_size(f"input[{i}].scriptSig_length")
        script = r.take(script_len, f"input[{i}].scriptSig")
        # Fill the decoded value after reading because take() must consume first.
        r.rows[-1]["decoded"] = script.hex() if script else "empty (native SegWit unlock is in witness)"
        sequence_raw = r.take(4, f"input[{i}].sequence")
        sequence = int.from_bytes(sequence_raw, "little")
        inputs.append({
            "previous_txid": prev_txid,
            "previous_vout": prev_vout,
            "scriptSig": script.hex(),
            "sequence": sequence,
        })

    output_count = r.compact_size("output_count")
    outputs = []
    for i in range(output_count):
        value_raw = r.take(8, f"output[{i}].value")
        value = int.from_bytes(value_raw, "little")
        r.rows[-1]["decoded"] = f"{value} sat"
        script_len = r.compact_size(f"output[{i}].scriptPubKey_length")
        script = r.take(script_len, f"output[{i}].scriptPubKey")
        script_type = classify_script(script)
        r.rows[-1]["decoded"] = script_type
        outputs.append({"value_sats": value, "scriptPubKey": script.hex(), "script_type": script_type})

    outputs_end = r.pos
    witnesses = []
    if segwit:
        for i in range(input_count):
            item_count = r.compact_size(f"witness[{i}].item_count")
            items = []
            for j in range(item_count):
                item_len = r.compact_size(f"witness[{i}].item[{j}].length")
                item = r.take(item_len, f"witness[{i}].item[{j}]")
                if j == 0 and item:
                    decoded = f"{item_len} bytes; possible signature; sighash=0x{item[-1]:02x}"
                elif item_len == 33 and item[:1] in (b"\x02", b"\x03"):
                    decoded = f"33-byte compressed public key; prefix=0x{item[0]:02x}"
                else:
                    decoded = f"{item_len} bytes"
                r.rows[-1]["decoded"] = decoded
                items.append(item.hex())
            witnesses.append(items)

    locktime_raw = r.take(4, "locktime")
    locktime = int.from_bytes(locktime_raw, "little")
    r.rows[-1]["decoded"] = str(locktime)
    if r.pos != len(data):
        raise ValueError(f"unconsumed bytes: parsed {r.pos} of {len(data)}")

    stripped = version_raw + data[body_start:outputs_end] + locktime_raw
    txid = sha256d(stripped)[::-1].hex()
    wtxid = sha256d(data)[::-1].hex()
    is_coinbase = (len(inputs) == 1 and inputs[0]["previous_txid"] == "00" * 32
                   and inputs[0]["previous_vout"] == 0xFFFFFFFF)
    coinbase_height = None
    if is_coinbase and inputs[0]["scriptSig"]:
        script = bytes.fromhex(inputs[0]["scriptSig"])
        push_len = script[0]
        if 1 <= push_len <= 5 and len(script) >= 1 + push_len:
            coinbase_height = int.from_bytes(script[1:1 + push_len], "little")

    return {
        "summary": {
            "bytes": len(data), "parsed_bytes": r.pos, "segwit": segwit,
            "version": int.from_bytes(version_raw, "little", signed=True),
            "input_count": input_count, "output_count": output_count,
            "locktime": locktime, "txid": txid, "wtxid": wtxid,
            "is_coinbase": is_coinbase, "coinbase_height": coinbase_height,
        },
        "inputs": inputs, "outputs": outputs, "witnesses": witnesses,
        "rows": r.rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hex_file", type=Path)
    parser.add_argument("--expected-txid")
    parser.add_argument("--expected-wtxid")
    parser.add_argument("--prefix", type=Path)
    args = parser.parse_args()

    raw_hex = "".join(args.hex_file.read_text().split())
    data = bytes.fromhex(raw_hex)
    result = parse_transaction(data)
    prefix = args.prefix or args.hex_file.with_suffix("")
    json_path = Path(str(prefix) + "-parsed.json")
    tsv_path = Path(str(prefix) + "-bytes.tsv")
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    with tsv_path.open("w") as out:
        out.write("byte_range\tbit_range\tlength\tfield\thex\tbinary\tdecoded\n")
        for row in result["rows"]:
            out.write(
                f'{row["byte_start"]}-{row["byte_end"]}\t'
                f'{row["bit_start"]}-{row["bit_end"]}\t{row["length"]}\t'
                f'{row["field"]}\t{row["hex"]}\t{row["binary"]}\t{row["decoded"]}\n'
            )

    s = result["summary"]
    print(json.dumps(s, indent=2, ensure_ascii=False))
    print(f'Parsed bytes: {s["parsed_bytes"]}/{s["bytes"]}: PASS')
    if args.expected_txid:
        print("TXID verification:", "PASS" if s["txid"] == args.expected_txid else "FAIL")
    if args.expected_wtxid:
        print("WTXID verification:", "PASS" if s["wtxid"] == args.expected_wtxid else "FAIL")
    print(f"Byte table: {tsv_path}")
    print(f"JSON result: {json_path}")


if __name__ == "__main__":
    main()
