#!/usr/bin/env python3
"""
PII Detection + Redaction Script
- written for ISCP dataset experiments
- draft v1.0 (might tweak later)
"""

import re
import json
import pandas as pd
import sys
import os

# Not using all of typing here, but keeping it in case we expand later
from typing import Dict, Any, Tuple, List


class PIIRedactor:
    """
    Quick-and-dirty class to scan CSV/json rows and hide PII.
    Note: This follows ISCP-ish guidelines, but I’ve added my own tweaks.
    """

    def __init__(self):
        # might expand this list later if new PII pops up
        self.primary_pii = ['phone', 'aadhar', 'passport', 'upi_id']
        self.secondary_pii = ['name', 'email', 'address', 'device_id', 'ip_address']

    def _to_str(self, val):
        """
        Convert stuff to string (handles weird Excel exports where numbers
        become floats or scientific notation)
        """
        if isinstance(val, (int, float)):
            # quick hack to avoid "1.23e+12" formatting
            if val == int(val):
                return str(int(val))
            else:
                return str(val)
        return str(val) if val is not None else ""

    def _is_phone(self, txt):
        """Basic Indian phone number check"""
        only_digits = re.sub(r"\D", "", str(txt))
        return len(only_digits) == 10 and only_digits[0] in "6789"

    def _is_aadhar(self, txt):
        """12 digit Aadhar (super naive check, not checksum validated)"""
        digits = re.sub(r"\D", "", str(txt))
        return len(digits) == 12

    def _is_passport(self, txt):
        """Indian passport like A1234567 or AB123456"""
        cleaned = str(txt).strip().upper()
        return bool(
            re.match(r"^[A-Z]\d{7,8}$", cleaned)
            or re.match(r"^[A-Z]{1,2}\d{6,7}$", cleaned)
        )

    def _is_upi(self, txt):
        """UPI ID: something@bank (not quite email)"""
        s = str(txt).strip()
        if "@" not in s:
            return False
        user, provider = s.split("@", 1)
        # crude heuristic: UPI providers don’t look like domains
        if "." in provider and len(provider.split(".")) > 1:
            return False
        return True

    def _is_email(self, txt):
        """regex-y email detection"""
        return bool(
            re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$", str(txt))
        )

    def _is_name(self, txt):
        """Naive full name check: at least 2 words, no obvious junk"""
        if not txt or not isinstance(txt, str):
            return False
        words = txt.strip().split()
        if len(words) < 2:
            return False
        if any(w.lower() in ["test", "user", "admin"] for w in words):
            return False
        return all(re.match(r"^[A-Za-z][A-Za-z\.\-']*$", w) for w in words)

    def _is_address(self, txt):
        """Check for address-ish strings: commas + numbers + length"""
        if not txt or not isinstance(txt, str):
            return False
        val = txt.strip()
        return (
            len(val) > 20
            and "," in val
            and bool(re.search(r"\d", val))
            and bool(re.search(r"\b\d{6}\b", val))
        )

    def _is_device_or_ip(self, txt):
        """Check for IP or device IDs"""
        s = str(txt).strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
            try:
                return all(0 <= int(x) <= 255 for x in s.split("."))
            except:
                return False
        return bool(re.match(r"^[A-Z0-9]{6,}$", s))

    # === Masking functions ===
    def _mask_phone(self, val):
        d = re.sub(r"\D", "", val)
        return d[:2] + "XXXXXX" + d[-2:] if len(d) == 10 else d

    def _mask_aadhar(self, val):
        d = re.sub(r"\D", "", val)
        return "XXXX XXXX " + d[-4:] if len(d) == 12 else d

    def _mask_passport(self, val):
        v = str(val).upper()
        return v[0] + "X" * (len(v) - 1) if len(v) > 1 else "XXXXXXXX"

    def _mask_upi(self, val):
        if "@" not in val:
            return val
        user, prov = val.split("@", 1)
        return (user[0] + "X" * (len(user) - 1)) + "@" + prov

    def _mask_email(self, val):
        if "@" not in val:
            return val
        user, dom = val.split("@", 1)
        return user[0] + "X" * (len(user) - 1) + "@" + dom

    def _mask_name(self, val):
        return " ".join(w[0].upper() + "X" * (len(w) - 1) for w in val.split())

    def _mask_address(self, val):
        return ", ".join("X" * len(part.strip()) for part in val.split(","))

    def _mask_device(self, val):
        return val[:3] + "X" * (len(val) - 3)

    def _mask_ip(self, val):
        chunks = val.split(".")
        return "XXX.XXX.XXX." + chunks[-1] if len(chunks) == 4 else "XXX.XXX.XXX.XXX"

    def _mask(self, pii_type, val):
        """dispatch masking"""
        val = self._to_str(val)
        if pii_type == "phone":
            return self._mask_phone(val)
        elif pii_type == "aadhar":
            return self._mask_aadhar(val)
        elif pii_type == "passport":
            return self._mask_passport(val)
        elif pii_type == "upi_id":
            return self._mask_upi(val)
        elif pii_type == "email":
            return self._mask_email(val)
        elif pii_type == "name":
            return self._mask_name(val)
        elif pii_type == "address":
            return self._mask_address(val)
        elif pii_type == "device_id":
            return self._mask_device(val)
        elif pii_type == "ip_address":
            return self._mask_ip(val)
        return val

    def analyze(self, row_dict: dict):
        """
        Check one record dict for PII.
        Returns: (bool, dict with redacted vals)
        """
        found_any = False
        redacted = {}
        detected_types = {}

        # first pass: standalone
        for k, v in row_dict.items():
            s = self._to_str(v)
            if k == "phone" or self._is_phone(s):
                detected_types[k] = "phone"
                found_any = True
            elif k == "aadhar" or self._is_aadhar(s):
                detected_types[k] = "aadhar"
                found_any = True
            elif k == "passport" or self._is_passport(s):
                detected_types[k] = "passport"
                found_any = True
            elif k == "upi_id" or self._is_upi(s):
                detected_types[k] = "upi_id"
                found_any = True

        # second pass: combinatorial
        combo = {}
        for k, v in row_dict.items():
            s = self._to_str(v)
            if k == "name" and self._is_name(s):
                combo[k] = "name"
            elif k == "email" and self._is_email(s):
                combo[k] = "email"
            elif k == "address" and self._is_address(s):
                combo[k] = "address"
            elif k in ["device_id", "ip_address"] and self._is_device_or_ip(s):
                combo[k] = k

        # heuristics: 2+ combo fields OR combo + device/ip
        if len([v for v in combo.values() if v in ["name", "email", "address"]]) >= 2:
            detected_types.update(combo)
            found_any = True
        elif combo and any(c in ["device_id", "ip_address"] for c in combo.values()):
            detected_types.update(combo)
            found_any = True

        # finally, redact
        for k, v in row_dict.items():
            if k in detected_types:
                redacted[k] = self._mask(detected_types[k], v)
            else:
                redacted[k] = v

        return found_any, redacted

    def process_csv(self, infile, outfile):
        """
        Run full CSV through redaction.
        Input: CSV with record_id + data_json
        """
        df = pd.read_csv(infile)
        results = []
        errors = 0

        for i, row in df.iterrows():
            try:
                rid = row["record_id"]
                data = json.loads(row["data_json"])
                has_pii, masked = self.analyze(data)
                results.append(
                    {
                        "record_id": rid,
                        "redacted_data_json": json.dumps(masked, ensure_ascii=False),
                        "is_pii": has_pii,
                    }
                )
            except Exception as e:
                # fall back: dump original json if error
                errors += 1
                results.append(
                    {
                        "record_id": row.get("record_id", i),
                        "redacted_data_json": row.get("data_json", "{}"),
                        "is_pii": False,
                    }
                )

            if (i + 1) % 100 == 0:
                print(f"...processed {i+1} rows")

        pd.DataFrame(results).to_csv(outfile, index=False)
        print(f"Done. Errors={errors}, Outfile={outfile}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python pii_redactor.py <input.csv>")
        sys.exit(1)

    infile = sys.argv[1]
    if not os.path.exists(infile):
        print(f"File not found: {infile}")
        sys.exit(1)

    out = "pii_redacted_output.csv"
    print("Running PII redaction...")
    worker = PIIRedactor()
    worker.process_csv(infile, out)


if __name__ == "__main__":
    main()
