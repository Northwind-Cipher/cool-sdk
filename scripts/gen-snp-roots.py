#!/usr/bin/env python3
# CooL
# Copyright (c) 2026 Northwind Cipher Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0
"""Regenerate src/snp/roots.ts from AMD's Key Distribution Service.

    python3 scripts/gen-snp-roots.py            # fetch from kdsintf.amd.com, verify, write
    python3 scripts/gen-snp-roots.py --check    # fail if the pinned roots differ from AMD's

For each product it downloads the VCEK and VLEK cert_chain bundles, checks
with OpenSSL that each ARK is self-signed and signs its ASK/ASVK, checks that
the ARK in both bundles is byte-identical, and pins the ARK SHA-256. Review the
diff before committing: a changed ARK fingerprint is a trust decision.
"""
import base64
import hashlib
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

PRODUCTS = ["Milan", "Genoa", "Turin"]
OUT = Path(__file__).resolve().parent.parent / "src" / "snp" / "roots.ts"


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 (fixed https URL)
        return r.read().decode()


def ders(pem: str) -> list:
    return [base64.b64decode("".join(b.split())) for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)]


def openssl_verify(ca: bytes, cert: bytes) -> None:
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for name, der in (("ca", ca), ("c", cert)):
            p = Path(d, f"{name}.der")
            p.write_bytes(der)
            subprocess.run(["openssl", "x509", "-inform", "der", "-in", str(p), "-out", f"{p}.pem"], check=True, capture_output=True)
            paths.append(f"{p}.pem")
        r = subprocess.run(["openssl", "verify", "-partial_chain", "-CAfile", paths[0], paths[1]], capture_output=True, text=True)
        if "OK" not in r.stdout:
            sys.exit(f"openssl verify failed: {r.stdout}{r.stderr}")


def main() -> None:
    entries = []
    for p in PRODUCTS:
        ask, ark = ders(fetch(f"https://kdsintf.amd.com/vcek/v1/{p}/cert_chain"))
        asvk, ark2 = ders(fetch(f"https://kdsintf.amd.com/vlek/v1/{p}/cert_chain"))
        if ark != ark2:
            sys.exit(f"{p}: the ARK differs between the VCEK and VLEK chains")
        openssl_verify(ark, ark)
        openssl_verify(ark, ask)
        openssl_verify(ark, asvk)
        entries.append((p, hashlib.sha256(ark).hexdigest(), ark, ask, asvk))
        print(f"{p}: ARK sha256 {entries[-1][1]}")

    current = OUT.read_text(encoding="utf8")
    if "--check" in sys.argv:
        bad = [p for p, fp, ark, ask, asvk in entries if fp not in current or base64.b64encode(ask).decode() not in current or base64.b64encode(asvk).decode() not in current]
        if bad:
            sys.exit(f"pinned roots differ from AMD KDS for: {', '.join(bad)}")
        print("pinned roots match AMD KDS")
        return

    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    body = "".join(
        f'\nconst {p.upper()}: SnpProductRoots = {{\n  product: "{p}",\n  arkSha256: "{fp}",\n  ark: b64("{b64(ark)}"),\n  ask: b64("{b64(ask)}"),\n  asvk: b64("{b64(asvk)}"),\n}};\n'
        for p, fp, ark, ask, asvk in entries
    )
    header = current.partition("\nconst MILAN")[0]
    footer = "".join(current.partition("\nexport const AMD_SNP_ROOTS")[1:])
    OUT.write_text(header + body + footer, encoding="utf8", newline="")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
