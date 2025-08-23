"""
Lightning helpers for LND:
- Minimal REST client for connectivity checks
- Simple process manager to start/stop/monitor LND
"""
from __future__ import annotations

import socket
import ssl
import http.client
import time
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import subprocess
import sys
import os
import signal
import base64

import psutil


class LightningClient:
    """Minimal LND REST client for health checks."""

    def check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _load_macaroon(self, macaroon_path: Optional[Path]) -> Optional[str]:
        if not macaroon_path:
            return None
        try:
            data = macaroon_path.read_bytes()
            return data.hex()
        except Exception:
            return None

    def _build_ssl_context(self, tls_cert: Optional[Path], verify: bool = False) -> ssl.SSLContext:
        """
        Build an SSL context.
        - Default verify=False preserves previous behavior (no verification).
        - If verify=True, enable CERT_REQUIRED and hostname checking, using provided CA file if any.
        """
        context = ssl.create_default_context()
        if verify:
            if tls_cert and tls_cert.exists():
                context.load_verify_locations(cafile=str(tls_cert))
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
        else:
            # Preserve previous insecure fallback behavior but warn
            if tls_cert and tls_cert.exists():
                try:
                    context.load_verify_locations(cafile=str(tls_cert))
                except Exception:
                    pass
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            logging.getLogger(__name__).info("TLS verification enabled for Lightning REST request")
        return context

    def _request_json(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 10.0,
        retries: int = 0,
        backoff_base: float = 0.25,
        retry_on_status: tuple[int, ...] = (500, 502, 503, 504),
        pinned_cert_sha256: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers = {"Content-Type": "application/json", "User-Agent": "BLRCS/1"}
        macaroon_hex = self._load_macaroon(macaroon_path)
        if macaroon_hex:
            headers["Grpc-Metadata-macaroon"] = macaroon_hex
        context = self._build_ssl_context(tls_cert)

        attempt = 0
        last_error: Optional[str] = None
        while True:
            try:
                conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
                # Establish connection early to optionally pin certificate
                conn.connect()
                if pinned_cert_sha256:
                    try:
                        cert_bin = conn.sock.getpeercert(binary_form=True)  # type: ignore[attr-defined]
                        fp = hashlib.sha256(cert_bin).hexdigest()
                        if fp.lower() != pinned_cert_sha256.lower():
                            try:
                                conn.close()
                            finally:
                                return {"ok": False, "status": None, "data": None, "error": "TLS certificate fingerprint mismatch"}
                    except Exception as e:
                        try:
                            conn.close()
                        finally:
                            return {"ok": False, "status": None, "data": None, "error": f"TLS pinning check failed: {e}"}

                import json as _json  # local import to avoid top-level conflicts
                body_bytes = None
                if body is not None:
                    body_bytes = _json.dumps(body).encode("utf-8")
                conn.request(method.upper(), path, body=body_bytes, headers=headers)
                resp = conn.getresponse()
                status = resp.status
                raw = resp.read()
            except Exception as e:
                last_error = str(e)
                status = None
                raw = b""
            finally:
                try:
                    conn.close()  # type: ignore[has-type]
                except Exception:
                    pass

            # Decide whether to retry
            if status is None or (isinstance(status, int) and status in retry_on_status):
                if attempt < retries:
                    sleep_s = backoff_base * (2 ** attempt)
                    time.sleep(sleep_s)
                    attempt += 1
                    continue

            data: Optional[Dict[str, Any]] = None
            if raw:
                try:
                    import json as _json
                    data = _json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    data = None
            ok = status is not None and 200 <= int(status) < 300
            if not ok and last_error and status is None:
                return {"ok": False, "status": None, "data": None, "error": last_error}
            return {"ok": ok, "status": status, "data": data, "error": None if ok else (last_error or (data if isinstance(data, str) else None))}

    def get_info_rest(
        self,
        host: str,
        port: int,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """
        Call /v1/getinfo over HTTPS. Returns dict with keys:
          {"ok": bool, "status": int|None, "data": dict|None, "error": str|None}
        """
        return self._request_json(
            host=host,
            port=port,
            method="GET",
            path="/v1/getinfo",
            body=None,
            tls_cert=tls_cert,
            macaroon_path=macaroon_path,
            timeout=timeout,
        )

    def check_connectivity(
        self,
        host: str,
        port: int,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Composite check: port open + optional getinfo.
        """
        port_open = self.check_port(host, port)
        result: Dict[str, Any] = {"port_open": port_open}
        if not port_open:
            result["getinfo"] = {"ok": False, "status": None, "data": None, "error": "port closed"}
            return result
        getinfo = self.get_info_rest(host, port, tls_cert=tls_cert, macaroon_path=macaroon_path)
        result["getinfo"] = getinfo
        return result

    # Wallet lifecycle (WalletUnlocker) REST endpoints
    def genseed_rest(
        self,
        host: str,
        port: int,
        tls_cert: Optional[Path] = None,
        aezeed_passphrase: Optional[str] = None,
        seed_entropy: Optional[str] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if aezeed_passphrase:
            payload["aezeed_passphrase"] = base64.b64encode(aezeed_passphrase.encode("utf-8")).decode("ascii")
        if seed_entropy:
            payload["seed_entropy"] = base64.b64encode(seed_entropy.encode("utf-8")).decode("ascii")
        return self._request_json(
            host, port, "POST", "/v1/genseed", payload or None, tls_cert=tls_cert, macaroon_path=None, timeout=timeout
        )

    def initwallet_rest(
        self,
        host: str,
        port: int,
        wallet_password: str,
        cipher_seed_mnemonic: list[str],
        tls_cert: Optional[Path] = None,
        aezeed_passphrase: Optional[str] = None,
        recovery_window: Optional[int] = None,
        timeout: float = 20.0,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "wallet_password": base64.b64encode(wallet_password.encode("utf-8")).decode("ascii"),
            "cipher_seed_mnemonic": cipher_seed_mnemonic,
        }
        if aezeed_passphrase:
            payload["aezeed_passphrase"] = base64.b64encode(aezeed_passphrase.encode("utf-8")).decode("ascii")
        if recovery_window is not None:
            payload["recovery_window"] = int(recovery_window)
        return self._request_json(
            host, port, "POST", "/v1/initwallet", payload, tls_cert=tls_cert, macaroon_path=None, timeout=timeout
        )

    def unlockwallet_rest(
        self,
        host: str,
        port: int,
        wallet_password: str,
        tls_cert: Optional[Path] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "wallet_password": base64.b64encode(wallet_password.encode("utf-8")).decode("ascii"),
        }
        return self._request_json(
            host, port, "POST", "/v1/unlockwallet", payload, tls_cert=tls_cert, macaroon_path=None, timeout=timeout
        )

    # Invoices
    def add_invoice_rest(
        self,
        host: str,
        port: int,
        value_sat: int,
        memo: Optional[str] = None,
        expiry: Optional[int] = None,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"value": int(value_sat)}
        if memo:
            body["memo"] = memo
        if expiry is not None:
            body["expiry"] = int(expiry)
        return self._request_json(
            host, port, "POST", "/v1/invoices", body, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )

    def decode_payreq_rest(
        self,
        host: str,
        port: int,
        pay_req: str,
        tls_cert: Optional[Path] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        # URL-encode pay_req since it can contain special characters
        from urllib.parse import quote
        path = f"/v1/payreq/{quote(pay_req, safe='')}"
        return self._request_json(host, port, "GET", path, None, tls_cert=tls_cert, macaroon_path=None, timeout=timeout)

    def list_invoices_rest(
        self,
        host: str,
        port: int,
        pending_only: bool = False,
        index_offset: int = 0,
        num_max_invoices: int = 100,
        reversed: bool = False,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        qs = (
            f"?pending_only={'true' if pending_only else 'false'}"
            f"&index_offset={index_offset}"
            f"&num_max_invoices={num_max_invoices}"
            f"&reversed={'true' if reversed else 'false'}"
        )
        return self._request_json(
            host, port, "GET", f"/v1/invoices{qs}", None, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )

    def send_payment_v2_rest(
        self,
        host: str,
        port: int,
        payment_request: str,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout_seconds: int = 60,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "payment_request": payment_request,
            "timeout_seconds": int(timeout_seconds),
        }
        return self._request_json(
            host, port, "POST", "/v2/router/send", body, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )

    def send_payment_sync_rest(
        self,
        host: str,
        port: int,
        payment_request: str,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"payment_request": payment_request}
        # This maps to Lightning.SendPaymentSync over REST
        return self._request_json(
            host, port, "POST", "/v1/channels/transactions", body, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )

    # Channels and peers
    def connect_peer_rest(
        self,
        host: str,
        port: int,
        pubkey: str,
        hostport: str,
        perm: bool = False,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "addr": {"pubkey": pubkey, "host": hostport},
            "perm": bool(perm),
        }
        return self._request_json(
            host, port, "POST", "/v1/peers", body, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )

    def open_channel_rest(
        self,
        host: str,
        port: int,
        node_pubkey: str,
        local_funding_amount: int,
        private: bool = False,
        spend_unconfirmed: bool = False,
        target_conf: Optional[int] = None,
        sat_per_vbyte: Optional[int] = None,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 20.0,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "node_pubkey_string": node_pubkey,
            "local_funding_amount": int(local_funding_amount),
            "private": bool(private),
            "spend_unconfirmed": bool(spend_unconfirmed),
        }
        if target_conf is not None:
            body["target_conf"] = int(target_conf)
        if sat_per_vbyte is not None:
            body["sat_per_vbyte"] = int(sat_per_vbyte)
        return self._request_json(
            host, port, "POST", "/v1/channels", body, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )

    def close_channel_rest(
        self,
        host: str,
        port: int,
        funding_txid_str: str,
        output_index: int,
        force: bool = False,
        target_conf: Optional[int] = None,
        sat_per_vbyte: Optional[int] = None,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "channel_point": {
                "funding_txid_str": funding_txid_str,
                "output_index": int(output_index),
            },
            "force": bool(force),
        }
        if target_conf is not None:
            body["target_conf"] = int(target_conf)
        if sat_per_vbyte is not None:
            body["sat_per_vbyte"] = int(sat_per_vbyte)
        return self._request_json(
            host, port, "POST", "/v1/channels/close", body, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )

    def list_channels_rest(
        self,
        host: str,
        port: int,
        active_only: bool = False,
        inactive_only: bool = False,
        public_only: bool = False,
        private_only: bool = False,
        peer: Optional[str] = None,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        qs = (
            f"?active_only={'true' if active_only else 'false'}"
            f"&inactive_only={'true' if inactive_only else 'false'}"
            f"&public_only={'true' if public_only else 'false'}"
            f"&private_only={'true' if private_only else 'false'}"
        )
        if peer:
            from urllib.parse import quote
            qs += f"&peer={quote(peer, safe='')}"
        return self._request_json(
            host, port, "GET", f"/v1/channels{qs}", None, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )

    def pending_channels_rest(
        self,
        host: str,
        port: int,
        tls_cert: Optional[Path] = None,
        macaroon_path: Optional[Path] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        return self._request_json(
            host, port, "GET", "/v1/channels/pending", None, tls_cert=tls_cert, macaroon_path=macaroon_path, timeout=timeout
        )


class LNDProcessManager:
    """Manage an LND process lifecycle (Windows-friendly)."""

    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._pid: Optional[int] = None

    def build_args(
        self,
        exe: Path,
        lnddir: Optional[Path],
        rest_host: str,
        rest_port: int,
        network: str = "mainnet",
        backend: str = "neutrino",
        extra_args: Optional[str] = None,
    ) -> list[str]:
        args = [str(exe)]
        if lnddir:
            args.append(f"--lnddir={lnddir}")
        # Bitcoin network flags
        args.append("--bitcoin.active")
        network = network.lower()
        if network not in {"mainnet", "testnet", "signet", "regtest"}:
            network = "mainnet"
        args.append(f"--bitcoin.{network}")
        # Backend
        if backend not in {"neutrino", "bitcoind", "neutrino+bitcoind"}:  # allow simple variants
            backend = "neutrino"
        # LND expects one of: bitcoind, neutrino, etc.
        if "+" in backend:
            # take first for simplicity
            backend = backend.split("+")[0]
        args.append(f"--bitcoin.node={backend}")

        # REST interface
        args.append(f"--restlisten={rest_host}:{rest_port}")

        # Extra user-provided flags (split naive by spaces)
        if extra_args:
            args.extend(extra_args.strip().split())
        return args

    def start(
        self,
        exe: Path,
        lnddir: Optional[Path],
        rest_host: str,
        rest_port: int,
        network: str = "mainnet",
        backend: str = "neutrino",
        extra_args: Optional[str] = None,
        stdout_log: Optional[Path] = None,
        stderr_log: Optional[Path] = None,
    ) -> int:
        if self.is_running():
            return int(self._pid)  # type: ignore[arg-type]
        if not exe.exists():
            raise FileNotFoundError(f"LND executable not found: {exe}")
        if lnddir and not lnddir.exists():
            try:
                lnddir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

        args = self.build_args(exe, lnddir, rest_host, rest_port, network, backend, extra_args)

        creationflags = 0
        startupinfo = None
        if os.name == "nt":
            # Create a new process group (so we can send CTRL_BREAK for graceful shutdown)
            # while keeping the process window hidden.
            CREATE_NO_WINDOW = 0x08000000
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            creationflags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        stdout_file = open(stdout_log or logs_dir / "lnd-stdout.log", "ab", buffering=0)
        stderr_file = open(stderr_log or logs_dir / "lnd-stderr.log", "ab", buffering=0)

        self._proc = subprocess.Popen(
            args,
            stdout=stdout_file,
            stderr=stderr_file,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        self._pid = self._proc.pid
        return self._pid

    def is_running(self) -> bool:
        pid = self._pid
        if self._proc is not None:
            if self._proc.poll() is None:
                return True
        if not pid:
            return False
        try:
            p = psutil.Process(pid)
            return p.is_running() and p.status() != psutil.STATUS_ZOMBIE
        except Exception:
            return False

    def stop(self, timeout: float = 10.0) -> bool:
        ok = False
        # Prefer controlling the tracked Popen when available
        if self._proc is not None and self._proc.poll() is None:
            try:
                if os.name == "nt":
                    # Try graceful CTRL_BREAK to allow LND to shutdown cleanly
                    try:
                        self._proc.send_signal(signal.CTRL_BREAK_EVENT)
                        self._proc.wait(timeout=min(5.0, timeout))
                        ok = True
                    except Exception:
                        pass
                if not ok and self._proc.poll() is None:
                    # Terminate (on Windows this is forceful)
                    try:
                        self._proc.terminate()
                        self._proc.wait(timeout=max(0.0, timeout - 2.0))
                        ok = True
                    except Exception:
                        pass
                if not ok and self._proc.poll() is None:
                    # Last resort
                    try:
                        self._proc.kill()
                        self._proc.wait(timeout=3.0)
                        ok = True
                    except Exception:
                        ok = False
            except Exception:
                ok = False
        # Fallback by PID if Popen handle isn't available
        elif self._pid:
            try:
                p = psutil.Process(self._pid)
                if os.name == "nt":
                    try:
                        p.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[arg-type]
                        p.wait(timeout=min(5.0, timeout))
                        ok = True
                    except Exception:
                        pass
                if not ok and p.is_running():
                    try:
                        p.terminate()
                        p.wait(timeout=max(0.0, timeout - 2.0))
                        ok = True
                    except Exception:
                        pass
                if not ok and p.is_running():
                    try:
                        p.kill()
                        p.wait(timeout=3.0)
                        ok = True
                    except Exception:
                        ok = False
            except Exception:
                ok = False
        self._proc = None
        self._pid = None
        return ok
