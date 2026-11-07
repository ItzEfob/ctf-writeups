#!/usr/bin/env python3
"""Reference relay for the Silent Orbit mission profile.
Parses raw concatenated CCSDS Space Packets, runs the CFDP receiver state
machine for transaction 0x01/0x07/0x02, and emits the first deferred NAK PDU."""
import sys

TUPLE = (0x01, 0x07, 0x02)


def space_packets(buf):
    i = 0
    while i < len(buf):
        if i + 6 > len(buf):
            raise SystemExit(f"truncated outer recording: header at {i}")
        h = buf[i:i + 6]
        w1 = (h[0] << 8) | h[1]
        w2 = (h[2] << 8) | h[3]
        n = ((h[4] << 8) | h[5]) + 1
        if i + 6 + n > len(buf):
            raise SystemExit(f"truncated outer recording: packet at {i} wants {n} bytes")
        yield dict(off=i, pvn=w1 >> 13, ptype=(w1 >> 12) & 1, shf=(w1 >> 11) & 1,
                   apid=w1 & 0x7FF, seqf=w2 >> 14, seqc=w2 & 0x3FFF,
                   data=buf[i + 6:i + 6 + n])
        i += 6 + n


def parse_pdu(d):
    """Return a dict for a well-formed target-encoded PDU, or a string reason."""
    if len(d) < 4:
        return "too short for CFDP header"
    b0 = d[0]
    hdr = dict(version=b0 >> 5, ftype=(b0 >> 4) & 1, direction=(b0 >> 3) & 1,
               mode=(b0 >> 2) & 1, crc=(b0 >> 1) & 1, large=b0 & 1,
               dlen=(d[1] << 8) | d[2], segctl=d[3] >> 7, eidlen=((d[3] >> 4) & 7) + 1,
               segmeta=(d[3] >> 3) & 1, tsnlen=(d[3] & 7) + 1)
    if (hdr["version"], hdr["direction"], hdr["mode"], hdr["crc"], hdr["large"]) != (1, 0, 0, 0, 0):
        return f"header flags not target encoding {hdr}"
    if hdr["eidlen"] != 1 or hdr["tsnlen"] != 1:
        return "entity/TSN length not one octet"
    if len(d) < 7:
        return "too short for IDs"
    if tuple(d[4:7]) != TUPLE:
        return f"other transaction {tuple(d[4:7])}"
    body = d[7:]
    if hdr["dlen"] != len(body):
        return f"data-field length {hdr['dlen']} != remaining {len(body)}"
    hdr["body"] = body
    return hdr


def main(path):
    buf = open(path, "rb").read()
    state, size, cover, eof_size, snapshot = "WAIT_METADATA", None, [], None, None
    for p in space_packets(buf):
        tag = f"@{p['off']:4} apid={p['apid']:#05x} seq={p['seqc']:5}"
        if (p["pvn"], p["ptype"], p["apid"], p["shf"], p["seqf"]) != (0, 0, 0x321, 0, 3):
            print(tag, "SKIP ineligible packet", (p["pvn"], p["ptype"], hex(p["apid"]), p["shf"], p["seqf"]))
            continue
        r = parse_pdu(p["data"])
        if isinstance(r, str):
            print(tag, "SKIP", r)
            continue
        body = r["body"]
        if r["ftype"] == 1:  # File Data
            if r["segctl"] or r["segmeta"]:
                print(tag, "SKIP file data with seg ctl/meta flag")
                continue
            if len(body) < 4:
                print(tag, "SKIP file data too short")
                continue
            off = int.from_bytes(body[:4], "big")
            end = off + len(body) - 4
            if state != "COLLECT" or snapshot is not None:
                print(tag, f"DISCARD file data [{off},{end}) state={state} snapshot={'yes' if snapshot else 'no'}")
                continue
            if end > 0xFFFFFFFF + 1 or end > size:
                print(tag, f"REJECT file data [{off},{end}) beyond size {size}")
                continue
            cover.append((off, end))
            print(tag, f"ACCEPT file data [{off},{end})")
            continue
        if not body:
            print(tag, "SKIP empty directive")
            continue
        code = body[0]
        if code == 0x07:  # Metadata
            if state != "WAIT_METADATA":
                print(tag, "IGNORE later metadata")
                continue
            if len(body) < 6:
                print(tag, "SKIP metadata too short")
                continue
            flags, fsize = body[1], int.from_bytes(body[2:6], "big")
            i = 6
            ok = True
            for _ in range(2):  # source and destination filename LVs
                if i >= len(body) or i + 1 + body[i] > len(body):
                    ok = False
                    break
                i += 1 + body[i]
            closure, cks = (flags >> 6) & 1, flags & 0x0F
            if not ok or i != len(body) or closure != 0 or cks != 15:
                print(tag, f"SKIP metadata (flags={flags:#04x} closure={closure} cks={cks} LV_ok={ok} tail={len(body) - i})")
                continue
            state, size = "COLLECT", fsize
            print(tag, f"ACCEPT metadata size={fsize} names={body[6:i]!r}")
        elif code == 0x04:  # EOF
            if state != "COLLECT" or snapshot is not None:
                print(tag, f"IGNORE EOF state={state}")
                continue
            if len(body) != 10:
                print(tag, f"SKIP EOF length {len(body)} (fault TLV / malformed)")
                continue
            cond, cks, fsz = body[1], body[2:6], int.from_bytes(body[6:10], "big")
            if cond != 0 or cks != b"\0\0\0\0" or fsz != size:
                print(tag, f"SKIP EOF cond={cond:#04x} cks={cks.hex()} size={fsz}")
                continue
            eof_size, snapshot = fsz, sorted(cover)
            print(tag, f"ACCEPT EOF size={fsz} -> coverage snapshot")
        else:
            print(tag, f"SKIP directive {code:#04x}")

    if snapshot is None:
        raise SystemExit("no EOF accepted")
    merged = []
    for s, e in snapshot:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    gaps, pos = [], 0
    for s, e in merged:
        if s > pos:
            gaps.append((pos, min(s, eof_size)))
        pos = max(pos, e)
    if pos < eof_size:
        gaps.append((pos, eof_size))
    print("coverage:", merged, "\nmissing:", gaps)

    body = bytes([0x08]) + (0).to_bytes(4, "big") + eof_size.to_bytes(4, "big")
    for s, e in gaps:
        body += s.to_bytes(4, "big") + e.to_bytes(4, "big")
    nak = bytes([0b001_0_1_0_0_0, len(body) >> 8, len(body) & 0xFF, 0x00, *TUPLE]) + body
    print("NAK:", nak.hex().upper())
    print(f"CSCTF{{{nak.hex().upper()}}}")


if __name__ == "__main__":
    main(sys.argv[1])
