#!/usr/bin/env python3
"""Independently parse and verify a raw Bitcoin block."""

import argparse
import json
from pathlib import Path

from parse_tx import parse_transaction, sha256d


def compact_size(data: bytes, pos: int):
    first = data[pos]
    if first < 0xFD:
        return first, pos + 1
    widths = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    width = widths[first]
    end = pos + 1 + width
    return int.from_bytes(data[pos + 1:end], "little"), end


def transaction_end(data: bytes, start: int) -> int:
    pos = start + 4
    segwit = data[pos:pos + 1] == b"\x00" and data[pos + 1:pos + 2] not in (b"", b"\x00")
    if segwit:
        pos += 2
    input_count, pos = compact_size(data, pos)
    for _ in range(input_count):
        pos += 36
        length, pos = compact_size(data, pos)
        pos += length + 4
    output_count, pos = compact_size(data, pos)
    for _ in range(output_count):
        pos += 8
        length, pos = compact_size(data, pos)
        pos += length
    if segwit:
        for _ in range(input_count):
            count, pos = compact_size(data, pos)
            for _ in range(count):
                length, pos = compact_size(data, pos)
                pos += length
    pos += 4
    if pos > len(data):
        raise ValueError("transaction extends beyond block")
    return pos


def merkle_root(hashes):
    level = list(hashes)
    if not level:
        raise ValueError("empty Merkle tree")
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def header_row(start, size, field, raw, decoded):
    return {
        "byte_range": f"{start}-{start + size - 1}",
        "bit_range": f"{start * 8}-{(start + size) * 8 - 1}",
        "length": size,
        "field": field,
        "hex": raw.hex(),
        "binary": " ".join(f"{b:08b}" for b in raw),
        "decoded": decoded,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hex_file", type=Path)
    ap.add_argument("--expected-hash")
    ap.add_argument("--prefix", type=Path, default=Path("14-block"))
    args = ap.parse_args()

    data = bytes.fromhex("".join(args.hex_file.read_text().split()))
    if len(data) < 81:
        raise ValueError("block is too short")
    header = data[:80]
    version = int.from_bytes(header[0:4], "little", signed=True)
    previous = header[4:36][::-1].hex()
    header_merkle = header[36:68]
    timestamp = int.from_bytes(header[68:72], "little")
    compact = int.from_bytes(header[72:76], "little")
    nonce = int.from_bytes(header[76:80], "little")
    exponent = compact >> 24
    coefficient = compact & 0x007FFFFF
    target = coefficient << (8 * (exponent - 3)) if exponent >= 3 else coefficient >> (8 * (3 - exponent))
    digest = sha256d(header)
    block_hash = digest[::-1].hex()
    hash_integer = int.from_bytes(digest, "little")

    tx_count, pos = compact_size(data, 80)
    transactions = []
    txids_internal = []
    wtxids_internal = []
    for index in range(tx_count):
        start = pos
        pos = transaction_end(data, start)
        parsed = parse_transaction(data[start:pos])
        summary = parsed["summary"]
        transactions.append({
            "position": index, "byte_start": start, "byte_end": pos - 1,
            "length": pos - start, "txid": summary["txid"],
            "wtxid": summary["wtxid"], "coinbase": summary["is_coinbase"],
        })
        txids_internal.append(bytes.fromhex(summary["txid"])[::-1])
        wtxids_internal.append(bytes.fromhex(summary["wtxid"])[::-1])

    calculated_merkle = merkle_root(txids_internal)
    witness_hashes = [b"\x00" * 32] + wtxids_internal[1:]
    witness_merkle = merkle_root(witness_hashes)
    coinbase_start = transactions[0]["byte_start"]
    coinbase_end = transactions[0]["byte_end"] + 1
    coinbase = parse_transaction(data[coinbase_start:coinbase_end])
    reserved = bytes.fromhex(coinbase["witnesses"][0][0]) if coinbase["witnesses"] and coinbase["witnesses"][0] else b""
    commitments = []
    for output in coinbase["outputs"]:
        script = bytes.fromhex(output["scriptPubKey"])
        if len(script) >= 38 and script.startswith(bytes.fromhex("6a24aa21a9ed")):
            commitments.append(script[6:38])
    commitment = commitments[-1] if commitments else None
    calculated_commitment = sha256d(witness_merkle + reserved) if len(reserved) == 32 else None

    checks = {
        "all_block_bytes_consumed": pos == len(data),
        "transaction_count": len(transactions) == tx_count,
        "block_hash": args.expected_hash is None or block_hash == args.expected_hash,
        "proof_of_work": hash_integer <= target,
        "merkle_root": calculated_merkle == header_merkle,
        "witness_commitment": commitment is not None and calculated_commitment == commitment,
        "coinbase_first": transactions[0]["coinbase"],
    }
    rows = [
        header_row(0, 4, "version", header[0:4], str(version)),
        header_row(4, 32, "previous_block_hash", header[4:36], previous),
        header_row(36, 32, "merkle_root", header[36:68], header_merkle[::-1].hex()),
        header_row(68, 4, "timestamp", header[68:72], str(timestamp)),
        header_row(72, 4, "nBits", header[72:76], f"0x{compact:08x}"),
        header_row(76, 4, "nonce", header[76:80], str(nonce)),
    ]
    result = {
        "block_bytes": len(data), "parsed_bytes": pos, "block_hash": block_hash,
        "version": version, "previous_block_hash": previous,
        "header_merkle_root": header_merkle[::-1].hex(),
        "calculated_merkle_root": calculated_merkle[::-1].hex(),
        "timestamp": timestamp, "nBits": f"{compact:08x}", "nonce": nonce,
        "target": f"{target:064x}", "hash_integer": f"{hash_integer:064x}",
        "transaction_count": tx_count, "transactions": transactions,
        "witness_merkle_root": witness_merkle[::-1].hex(),
        "coinbase_reserved_value": reserved.hex(),
        "stored_witness_commitment": commitment.hex() if commitment else None,
        "calculated_witness_commitment": calculated_commitment.hex() if calculated_commitment else None,
        "checks": checks,
    }
    json_path = Path(str(args.prefix) + "-parsed.json")
    tsv_path = Path(str(args.prefix) + "-header-bytes.tsv")
    json_path.write_text(json.dumps(result, indent=2) + "\n")
    with tsv_path.open("w") as out:
        out.write("byte_range\tbit_range\tlength\tfield\thex\tbinary\tdecoded\n")
        for row in rows:
            out.write("\t".join(str(row[k]) for k in
                ("byte_range", "bit_range", "length", "field", "hex", "binary", "decoded")) + "\n")

    print(json.dumps({k: result[k] for k in (
        "block_bytes", "parsed_bytes", "block_hash", "nBits", "target",
        "hash_integer", "transaction_count")}, indent=2))
    for name, passed in checks.items():
        print(f'{name.replace("_", " ").title()}: {"PASS" if passed else "FAIL"}')
    print(f"JSON result: {json_path}")
    print(f"Header byte table: {tsv_path}")
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
