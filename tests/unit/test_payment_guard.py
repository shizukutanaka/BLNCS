"""Tests for the Lightning payment guard on POST /api/lightning/pay.

Covers:
* BOLT11 amount extraction (blncs.lightning.bolt11_amount)
* single-use confirmation tokens (blncs.core.payment_confirmation)
* the guarded endpoint flow (amount limit + confirmation) with the
  Lightning client replaced by a fake -- no real payment is ever made.

The invoice fixtures below are real, validly signed BOLT11 invoices
generated with an independent reference implementation (the ``bolt11``
Python package) using a throwaway test-only key, and their amounts
were confirmed through that library's decoder.
"""

import time

import pytest

from blncs.core.payment_confirmation import PaymentConfirmationStore
from blncs.lightning.bolt11_amount import (
    Bolt11AmountError,
    extract_amount_msat,
    extract_amount_sats,
)

# --- Reference-generated invoice fixtures (amounts verified) ---------------
# Each string is reproduced exactly as emitted by the reference encoder.
INVOICE_1000_SAT = "lnbc10u1pj48ugqpp5jxj4mnds5pncqctj00cln2x2uta45kc8r4d0s4tjajwfzqrsnx4qsp5xmywlkcthg99f3jeg0wtwtacwwmu8466wugf564fwp3vjjwyjetsdq5w3jhxapqve5hsar4wfjskdturz3th3flnytu7rxqna7wcx4ez87ywna9ppqg040m0ndjp6fpzywddel9h3mmv0yeutjl9fdfpugse86nqtaqln39g52eungwv4qpe3sty5"  # 1,000,000 msat
INVOICE_100_SAT = "lnbc1u1pj48ugqpp5jxj4mnds5pncqctj00cln2x2uta45kc8r4d0s4tjajwfzqrsnx4qsp5xmywlkcthg99f3jeg0wtwtacwwmu8466wugf564fwp3vjjwyjetsdq5w3jhxapqve5hsar4wfjsf3ecqvwrzrpau96rzxyqhzv5ww4qdns4wlk24l9uusmeeusajg9xkn7ffyjc7775yt2c53g9vn9ehmrv99m0c2pd5gjrxzh04f9x78cpsn8qdp"  # 100,000 msat
INVOICE_250000_SAT = "lnbc2500u1pj48ugqpp5jxj4mnds5pncqctj00cln2x2uta45kc8r4d0s4tjajwfzqrsnx4qsp5xmywlkcthg99f3jeg0wtwtacwwmu8466wugf564fwp3vjjwyjetsdq5w3jhxapqve5hsar4wfjshr8tx0y38ycen0apmxn0f8p4wfqdymtxq9g29q8ldxw27ys6hdz8x5084s8pgh8dmq8xgssuyjut7zs830xj087p2w5hxhqruh3w78qp5kqf2y"  # 250,000,000 msat
INVOICE_AMOUNTLESS = "lnbc1pj48ugqpp5jxj4mnds5pncqctj00cln2x2uta45kc8r4d0s4tjajwfzqrsnx4qsp5xmywlkcthg99f3jeg0wtwtacwwmu8466wugf564fwp3vjjwyjetsdq5w3jhxapqve5hsar4wfjska9277xvq8p8p3t0g72z0z4qygammmv8vpslrjx844usgky0rysj86tfkygp58nvpwljyd5g49zc9yl9ydkl9p2jhhppnz4u7pputwgqt8w0ds"  # no amount
INVOICE_21_MSAT = "lnbc210p1pj48ugqpp5jxj4mnds5pncqctj00cln2x2uta45kc8r4d0s4tjajwfzqrsnx4qsp5xmywlkcthg99f3jeg0wtwtacwwmu8466wugf564fwp3vjjwyjetsdq5w3jhxapqve5hsar4wfjs5796cd24u7s70lgs2fmk7jmxqklghjsg4392ca20dvza5y97j8qqxlfvyp5ftxvnvqlvwh6gnd7hcgjrdnenuyw0w0t0pwrsmtuagrcqkzdeh6"  # 21 msat


# --- Minimal bech32 encoder (BIP-173) for synthetic HRP cases --------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    chk = 1
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _make_invoice(hrp, data_words=None):
    if data_words is None:
        data_words = [0] * 120  # well above the minimum data length
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = _polymod(expanded + data_words + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data_words + checksum)


# --- BOLT11 amount extraction ----------------------------------------------

@pytest.mark.parametrize(
    "invoice,expected_msat",
    [
        (INVOICE_1000_SAT, 1_000_000),
        (INVOICE_100_SAT, 100_000),
        (INVOICE_250000_SAT, 250_000_000),
        (INVOICE_21_MSAT, 21),
        (INVOICE_AMOUNTLESS, None),
    ],
)
def test_extract_amount_from_reference_invoices(invoice, expected_msat):
    assert extract_amount_msat(invoice) == expected_msat


def test_extract_amount_uppercase_invoice():
    assert extract_amount_msat(INVOICE_1000_SAT.upper()) == 1_000_000


def test_extract_amount_sats():
    assert extract_amount_sats(INVOICE_1000_SAT) == 1000
    assert extract_amount_sats(INVOICE_AMOUNTLESS) is None


@pytest.mark.parametrize(
    "hrp,expected_msat",
    [
        ("lnbc2m", 200_000_000),   # 2 milli-BTC = 10**8 msat per unit
        ("lntb5u", 500_000),       # 5 micro-BTC = 10**5 msat per unit
        ("lnbcrt30n", 3_000),      # 30 nano-BTC = 100 msat per unit
        ("lnbc3", 300_000_000_000),  # 3 whole BTC, no multiplier
    ],
)
def test_extract_amount_multipliers(hrp, expected_msat):
    assert extract_amount_msat(_make_invoice(hrp)) == expected_msat


def test_extract_amount_rejects_zero_amount():
    with pytest.raises(Bolt11AmountError):
        extract_amount_msat(_make_invoice("lnbc0u"))


def test_extract_amount_rejects_fractional_msat():
    # 211p = 21.1 msat is not a whole number of millisatoshis.
    with pytest.raises(Bolt11AmountError):
        extract_amount_msat(_make_invoice("lnbc211p"))


def test_extract_amount_rejects_malformed_amount():
    with pytest.raises(Bolt11AmountError):
        extract_amount_msat(_make_invoice("lnbc10x"))


def test_extract_amount_rejects_bad_checksum():
    corrupted = INVOICE_1000_SAT[:-1] + ("q" if INVOICE_1000_SAT[-1] != "q" else "p")
    with pytest.raises(Bolt11AmountError):
        extract_amount_msat(corrupted)


def test_extract_amount_rejects_mixed_case():
    mixed = INVOICE_1000_SAT[:8] + INVOICE_1000_SAT[8:].upper()
    with pytest.raises(Bolt11AmountError):
        extract_amount_msat(mixed)


@pytest.mark.parametrize("bad", ["", "not-an-invoice", "lnbc", "ln1qqqqqqqqqqq"])
def test_extract_amount_rejects_garbage(bad):
    with pytest.raises(Bolt11AmountError):
        extract_amount_msat(bad)


# --- Confirmation token store ----------------------------------------------

def test_confirmation_happy_path():
    store = PaymentConfirmationStore(ttl_seconds=60)
    token, expires_at = store.issue("token-id-1", INVOICE_1000_SAT, 1_000_000)
    assert token
    assert expires_at > time.time()
    assert store.consume(token, "token-id-1", INVOICE_1000_SAT, 1_000_000) is True


def test_confirmation_is_single_use():
    store = PaymentConfirmationStore(ttl_seconds=60)
    token, _ = store.issue("id", INVOICE_1000_SAT, 1_000_000)
    assert store.consume(token, "id", INVOICE_1000_SAT, 1_000_000) is True
    assert store.consume(token, "id", INVOICE_1000_SAT, 1_000_000) is False


@pytest.mark.parametrize(
    "identity,invoice,amount",
    [
        ("other-id", INVOICE_1000_SAT, 1_000_000),   # wrong caller
        ("id", INVOICE_100_SAT, 1_000_000),          # wrong invoice
        ("id", INVOICE_1000_SAT, 999_999),           # wrong amount
    ],
)
def test_confirmation_binding_mismatch_burns_token(identity, invoice, amount):
    store = PaymentConfirmationStore(ttl_seconds=60)
    token, _ = store.issue("id", INVOICE_1000_SAT, 1_000_000)
    assert store.consume(token, identity, invoice, amount) is False
    # A failed attempt consumes the token as well (no probing).
    assert store.consume(token, "id", INVOICE_1000_SAT, 1_000_000) is False


def test_confirmation_expires():
    now = [1_000.0]
    store = PaymentConfirmationStore(ttl_seconds=30, clock=lambda: now[0])
    token, _ = store.issue("id", INVOICE_1000_SAT, 1_000_000)
    now[0] += 31
    assert store.consume(token, "id", INVOICE_1000_SAT, 1_000_000) is False


def test_confirmation_unknown_token():
    store = PaymentConfirmationStore(ttl_seconds=60)
    assert store.consume("no-such-token", "id", INVOICE_1000_SAT, 1_000_000) is False
    assert store.consume(None, "id", INVOICE_1000_SAT, 1_000_000) is False


# --- Guarded endpoint --------------------------------------------------------

class FakeLightningClient:
    """Stand-in for SimpleLightningClient; records payments, never pays."""

    def __init__(self):
        self.connected = True
        self.pay_calls = []

    def connect(self):
        self.connected = True
        return True

    def pay_invoice(self, payment_request):
        self.pay_calls.append(payment_request)
        return {"payment_hash": "ab" * 32, "status": "SUCCEEDED"}


@pytest.fixture()
def api_env(tmp_path, monkeypatch):
    import blncs.api.unified_rest_api as api_module
    from blncs.core.simple_auth import SimpleAuth

    auth = SimpleAuth(storage_path=str(tmp_path / "auth.json"))
    monkeypatch.setattr(api_module, "_auth", auth)
    write_key = auth.generate_api_key("writer", {"read": True, "write": True})
    read_key = auth.generate_api_key("reader", {"read": True, "write": False})

    fake_client = FakeLightningClient()
    monkeypatch.setattr(
        "blncs.lightning.simple_client.SimpleLightningClient",
        lambda *args, **kwargs: fake_client,
    )

    app = api_module.create_app()
    app.testing = True
    return app.test_client(), write_key, read_key, fake_client


def _auth_header(key):
    return {"Authorization": f"Bearer {key}"}


def test_pay_requires_confirmation_then_executes(api_env):
    client, write_key, _, fake = api_env

    step1 = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_1000_SAT},
        headers=_auth_header(write_key),
    )
    assert step1.status_code == 428
    body = step1.get_json()
    assert body["confirmation_required"] is True
    assert body["amount_sats"] == 1000
    assert body["max_amount_sats"] == 10_000
    assert fake.pay_calls == []  # nothing paid yet

    step2 = client.post(
        "/api/lightning/pay",
        json={
            "payment_request": INVOICE_1000_SAT,
            "confirmation_token": body["confirmation_token"],
        },
        headers=_auth_header(write_key),
    )
    assert step2.status_code == 200
    assert fake.pay_calls == [INVOICE_1000_SAT]


def test_pay_confirmation_token_cannot_be_reused(api_env):
    client, write_key, _, fake = api_env
    token = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_100_SAT},
        headers=_auth_header(write_key),
    ).get_json()["confirmation_token"]

    payload = {"payment_request": INVOICE_100_SAT, "confirmation_token": token}
    assert client.post("/api/lightning/pay", json=payload,
                       headers=_auth_header(write_key)).status_code == 200
    assert client.post("/api/lightning/pay", json=payload,
                       headers=_auth_header(write_key)).status_code == 403
    assert fake.pay_calls == [INVOICE_100_SAT]


def test_pay_confirmation_token_bound_to_invoice(api_env):
    client, write_key, _, fake = api_env
    token = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_100_SAT},
        headers=_auth_header(write_key),
    ).get_json()["confirmation_token"]

    resp = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_1000_SAT, "confirmation_token": token},
        headers=_auth_header(write_key),
    )
    assert resp.status_code == 403
    assert fake.pay_calls == []


def test_pay_rejects_over_limit(api_env):
    client, write_key, _, fake = api_env
    resp = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_250000_SAT},
        headers=_auth_header(write_key),
    )
    assert resp.status_code == 403
    body = resp.get_json()
    assert body["amount_sats"] == 250_000
    assert body["max_amount_sats"] == 10_000
    assert fake.pay_calls == []


def test_pay_rejects_amountless_invoice(api_env):
    client, write_key, _, fake = api_env
    resp = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_AMOUNTLESS},
        headers=_auth_header(write_key),
    )
    assert resp.status_code == 400
    assert fake.pay_calls == []


def test_pay_rejects_bad_checksum_invoice(api_env):
    client, write_key, _, fake = api_env
    bad = INVOICE_1000_SAT[:-1] + ("q" if INVOICE_1000_SAT[-1] != "q" else "p")
    resp = client.post(
        "/api/lightning/pay",
        json={"payment_request": bad},
        headers=_auth_header(write_key),
    )
    assert resp.status_code == 400
    assert fake.pay_calls == []


def test_pay_rejects_unknown_confirmation_token(api_env):
    client, write_key, _, fake = api_env
    resp = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_100_SAT, "confirmation_token": "bogus"},
        headers=_auth_header(write_key),
    )
    assert resp.status_code == 403
    assert fake.pay_calls == []


def test_pay_requires_write_permission(api_env):
    client, _, read_key, fake = api_env
    resp = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_100_SAT},
        headers=_auth_header(read_key),
    )
    assert resp.status_code == 403
    assert fake.pay_calls == []


def test_pay_requires_authentication(api_env):
    client, _, _, fake = api_env
    resp = client.post("/api/lightning/pay", json={"payment_request": INVOICE_100_SAT})
    assert resp.status_code == 401
    assert fake.pay_calls == []


def test_pay_limit_configurable_via_env(tmp_path, monkeypatch):
    import blncs.api.unified_rest_api as api_module
    from blncs.core.simple_auth import SimpleAuth

    monkeypatch.setenv("BLNCS_PAY_MAX_AMOUNT_SATS", "50")
    auth = SimpleAuth(storage_path=str(tmp_path / "auth.json"))
    monkeypatch.setattr(api_module, "_auth", auth)
    write_key = auth.generate_api_key("writer", {"read": True, "write": True})
    fake = FakeLightningClient()
    monkeypatch.setattr(
        "blncs.lightning.simple_client.SimpleLightningClient",
        lambda *args, **kwargs: fake,
    )
    app = api_module.create_app()
    app.testing = True
    client = app.test_client()

    # 100 sats now exceeds the configured limit of 50 sats.
    resp = client.post(
        "/api/lightning/pay",
        json={"payment_request": INVOICE_100_SAT},
        headers=_auth_header(write_key),
    )
    assert resp.status_code == 403
    assert resp.get_json()["max_amount_sats"] == 50
    assert fake.pay_calls == []
