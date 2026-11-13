"""BOLT11 invoice amount extraction (local, dependency-free).

This module exists so the REST API can enforce a payment amount limit
*before* talking to a Lightning node.  It deliberately implements only
the small, well-specified part of BOLT11 that determines the amount:

* bech32 envelope validation (character set + checksum, BIP-173), and
* parsing of the amount encoded in the human-readable part (HRP),
  e.g. ``lnbc2500u`` -> 2500 * 10**-6 BTC.

It does NOT decode tagged fields and does NOT verify the invoice
signature; that remains the node's job when the payment is executed.

Fail-closed contract:

* :func:`extract_amount_msat` returns ``None`` for amountless invoices
  (the caller must reject those when a limit has to be enforced).
* Any malformed input raises :class:`Bolt11AmountError`.
"""

from __future__ import annotations

import re
from typing import List, Optional

__all__ = ["Bolt11AmountError", "extract_amount_msat", "extract_amount_sats"]


class Bolt11AmountError(ValueError):
    """Raised when an invoice string is malformed or fails validation."""


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_INDEX = {c: i for i, c in enumerate(_BECH32_CHARSET)}

# Millisatoshis per unit of the HRP amount for each BOLT11 multiplier.
# 1 BTC = 10**11 msat; the multiplier scales the HRP number down from BTC.
_MSAT_PER_UNIT = {
    None: 10 ** 11,  # whole BTC
    "m": 10 ** 8,    # milli-BTC  (10**-3 BTC)
    "u": 10 ** 5,    # micro-BTC  (10**-6 BTC)
    "n": 10 ** 2,    # nano-BTC   (10**-9 BTC)
    "p": 10 ** -1,   # pico-BTC   (10**-12 BTC) -> fractional, handled specially
}

_HRP_AMOUNT_RE = re.compile(r"^(?P<digits>[0-9]+)(?P<mult>[munp])?$")


def _bech32_polymod(values: List[int]) -> int:
    """BIP-173 polymod checksum computation."""
    chk = 1
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _split_bech32(invoice: str) -> tuple:
    """Validate the bech32 envelope and return ``(hrp, data_words)``.

    Raises :class:`Bolt11AmountError` for any structural or checksum
    problem.  Accepts all-lowercase or all-uppercase input (BIP-173);
    mixed case is rejected.
    """
    if not isinstance(invoice, str):
        raise Bolt11AmountError("Invoice must be a string")

    invoice = invoice.strip()
    if not invoice:
        raise Bolt11AmountError("Invoice is empty")

    if invoice.lower() != invoice and invoice.upper() != invoice:
        raise Bolt11AmountError("Invoice mixes uppercase and lowercase characters")

    normalized = invoice.lower()

    sep = normalized.rfind("1")
    if sep < 1:
        raise Bolt11AmountError("Invoice has no bech32 separator")

    hrp = normalized[:sep]
    data_part = normalized[sep + 1:]

    # 6 checksum chars + at least 7 timestamp words is the smallest
    # data part that can belong to a real invoice.
    if len(data_part) < 6 + 7:
        raise Bolt11AmountError("Invoice data part is too short")

    try:
        data_words = [_BECH32_INDEX[c] for c in data_part]
    except KeyError:
        raise Bolt11AmountError("Invoice contains non-bech32 characters") from None

    if _bech32_polymod(_bech32_hrp_expand(hrp) + data_words) != 1:
        raise Bolt11AmountError("Invoice bech32 checksum mismatch")

    return hrp, data_words


def extract_amount_msat(invoice: str) -> Optional[int]:
    """Return the invoice amount in millisatoshis.

    Returns ``None`` when the invoice carries no amount (amountless
    invoice).  Raises :class:`Bolt11AmountError` when the invoice is
    malformed, the checksum fails, the HRP is not a Lightning HRP, the
    amount is not a whole number of millisatoshis, or the amount is
    zero.
    """
    hrp, _ = _split_bech32(invoice)

    if not hrp.startswith("ln"):
        raise Bolt11AmountError("Not a Lightning invoice HRP")

    rest = hrp[2:]
    if not rest:
        raise Bolt11AmountError("Invoice HRP has no currency code")

    # The currency code is the run of letters before the first digit
    # (e.g. "bc", "tb", "bcrt").  Everything after it must be the
    # optional amount: digits plus an optional multiplier suffix.
    first_digit = next((i for i, c in enumerate(rest) if c.isdigit()), len(rest))
    currency = rest[:first_digit]
    amount_part = rest[first_digit:]

    if not currency.isalpha():
        raise Bolt11AmountError("Invoice HRP has an invalid currency code")

    if not amount_part:
        return None  # Amountless invoice.

    match = _HRP_AMOUNT_RE.match(amount_part)
    if not match:
        raise Bolt11AmountError("Invoice HRP has a malformed amount")

    digits = int(match.group("digits"))
    multiplier = match.group("mult")

    if multiplier == "p":
        # pico-BTC: value = digits / 10 msat; must be a whole msat.
        if digits % 10 != 0:
            raise Bolt11AmountError("Invoice amount is not a whole number of millisatoshis")
        amount_msat = digits // 10
    else:
        amount_msat = digits * _MSAT_PER_UNIT[multiplier]

    if amount_msat <= 0:
        raise Bolt11AmountError("Invoice amount must be greater than zero")

    return amount_msat


def extract_amount_sats(invoice: str) -> Optional[int]:
    """Return the invoice amount in whole satoshis (floor of msat/1000).

    Same contract as :func:`extract_amount_msat`.
    """
    amount_msat = extract_amount_msat(invoice)
    if amount_msat is None:
        return None
    return amount_msat // 1000
