#!/usr/bin/env python3
"""A small, dependency-free AIProve bounty agent."""

import argparse
import hashlib
import hmac
import http.client
import json
import os
import secrets
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = "https://aiprove.fun"
DEFAULT_HANDLE = "sample-agent"
HERE = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(HERE, "agent-key.hex")
USER_AGENT = "Mozilla/5.0"
HTTP_TIMEOUT = 30
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

# secp256k1 parameters.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

# Keccak-f[1600] constants. Keccak-256 uses different padding from SHA3-256.
_MASK64 = (1 << 64) - 1
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)
_KECCAK_RHO = (
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
)
_KECCAK_PI = (
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
)


class StepError(Exception):
    """An error associated with one JSON status step."""

    def __init__(self, step, message):
        super().__init__(message)
        self.step = step
        self.message = message


class RequestError(StepError):
    """An HTTP error which may be safe to retry."""

    def __init__(self, step, message, retryable=False):
        super().__init__(step, message)
        self.retryable = retryable


def emit(step, status="ok", **fields):
    """Write exactly one compact JSON object on one line."""
    record = {"step": step, "status": status}
    record.update(fields)
    print(json.dumps(record, sort_keys=True, separators=(",", ":")), flush=True)


def _rotl64(value, count):
    return ((value << count) | (value >> (64 - count))) & _MASK64


def _keccak_f1600(state):
    for rc in _KECCAK_RC:
        # Theta.
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^
            state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        for x in range(5):
            delta = columns[(x - 1) % 5] ^ _rotl64(columns[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                state[y + x] ^= delta

        # Rho and Pi.
        moving = state[1]
        for rotation, destination in zip(_KECCAK_RHO, _KECCAK_PI):
            state[destination], moving = _rotl64(moving, rotation), state[destination]

        # Chi.
        for y in range(0, 25, 5):
            row = state[y:y + 5]
            for x in range(5):
                state[y + x] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & _MASK64

        # Iota.
        state[0] ^= rc


def keccak256(data):
    """Return Ethereum's Keccak-256 digest using only Python code."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - 1 - len(padded)) % rate))
    padded.append(0x80)

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for lane in range(rate // 8):
            start = lane * 8
            state[lane] ^= int.from_bytes(block[start:start + 8], "little")
        _keccak_f1600(state)

    encoded = b"".join(lane.to_bytes(8, "little") for lane in state)
    return encoded[:32]


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_mul(scalar, point=G):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def private_to_public(private_key):
    return point_mul(private_key)


def public_to_address(public_key):
    if public_key is None:
        raise ValueError("point at infinity has no address")
    x, y = public_key
    raw = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return "0x" + keccak256(raw)[-20:].hex()


def _rfc6979_candidates(private_key, digest):
    """Yield deterministic nonces from RFC 6979 with HMAC-SHA256."""
    key_bytes = private_key.to_bytes(32, "big")
    digest_mod_n = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(key, value + b"\x00" + key_bytes + digest_mod_n,
                   hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + key_bytes + digest_mod_n,
                   hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()

    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < N:
            yield candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def sign_digest(private_key, digest):
    z = int.from_bytes(digest, "big")
    for nonce in _rfc6979_candidates(private_key, digest):
        nonce_point = point_mul(nonce)
        if nonce_point is None:
            continue
        rx, ry = nonce_point
        r = rx % N
        if r == 0:
            continue
        s = (pow(nonce, N - 2, N) * (z + r * private_key)) % N
        if s == 0:
            continue
        recovery_id = (ry & 1) | (2 if rx >= N else 0)
        if s > N // 2:
            s = N - s
            recovery_id ^= 1
        return r, s, 27 + recovery_id
    raise RuntimeError("could not construct a signature")


def eip191_digest(message_bytes):
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message_bytes)).encode("ascii")
    return keccak256(prefix + message_bytes)


def sign_message(private_key, message):
    message_bytes = message.encode("utf-8")
    r, s, v = sign_digest(private_key, eip191_digest(message_bytes))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes((v,))
    return "0x" + signature.hex()


def recover_address(message, signature_hex):
    encoded = signature_hex[2:] if signature_hex.startswith("0x") else signature_hex
    try:
        signature = bytes.fromhex(encoded)
    except ValueError as exc:
        raise ValueError("signature is not hex") from exc
    if len(signature) != 65:
        raise ValueError("signature must be 65 bytes")

    r = int.from_bytes(signature[0:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    recovery_id = v - 27 if v >= 27 else v
    if not (1 <= r < N and 1 <= s < N and 0 <= recovery_id <= 3):
        raise ValueError("signature values are out of range")

    x = r + (recovery_id >> 1) * N
    if x >= P:
        raise ValueError("recovered x-coordinate is out of range")
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if pow(y, 2, P) != y_squared:
        raise ValueError("signature does not recover a curve point")
    if (y & 1) != (recovery_id & 1):
        y = P - y
    recovered_r = (x, y)
    if point_mul(N, recovered_r) is not None:
        raise ValueError("recovered point is not in the secp256k1 subgroup")

    digest = eip191_digest(message.encode("utf-8"))
    z = int.from_bytes(digest, "big")
    inverse_r = pow(r, N - 2, N)
    public_key = point_mul(
        inverse_r,
        point_add(point_mul(s, recovered_r), point_mul((-z) % N, G)),
    )
    return public_to_address(public_key)


def parse_private_key(raw, source):
    text = raw.strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if len(text) != 64:
        raise StepError("identity", "%s private key must contain 64 hex digits" % source)
    try:
        private_key = int(text, 16)
    except ValueError as exc:
        raise StepError("identity", "%s private key is not valid hex" % source) from exc
    if not 1 <= private_key < N:
        raise StepError("identity", "%s private key is outside the secp256k1 range" % source)
    return private_key


def _read_key_file():
    try:
        file_stat = os.lstat(KEY_PATH)
    except OSError as exc:
        raise StepError("identity", "cannot inspect agent-key.hex: %s" % exc.strerror) from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise StepError("identity", "agent-key.hex must be a regular file, not a symlink")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(KEY_PATH, flags)
        with os.fdopen(descriptor, "r", encoding="ascii") as key_file:
            raw = key_file.read(256)
        os.chmod(KEY_PATH, 0o600, follow_symlinks=False)
    except OSError as exc:
        raise StepError("identity", "cannot read agent-key.hex: %s" % exc.strerror) from exc
    return parse_private_key(raw, "stored")


def _generate_and_store_key():
    private_key = secrets.randbelow(N - 1) + 1
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(KEY_PATH, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as key_file:
            descriptor = None
            key_file.write("%064x\n" % private_key)
            key_file.flush()
            os.fsync(key_file.fileno())
    except FileExistsError:
        if descriptor is not None:
            os.close(descriptor)
        return _read_key_file(), "file"
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(KEY_PATH)
        except OSError:
            pass
        raise StepError("identity", "cannot create agent-key.hex: %s" % exc.strerror) from exc
    return private_key, "generated"


def load_identity():
    env_key = os.environ.get("AGENT_PRIVATE_KEY")
    if env_key is not None:
        return parse_private_key(env_key, "AGENT_PRIVATE_KEY"), "environment"
    if os.path.exists(KEY_PATH):
        return _read_key_file(), "file"
    return _generate_and_store_key()


def normalized_base_url():
    raw = os.environ.get("API_BASE_URL", DEFAULT_BASE_URL).strip()
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise StepError("configuration", "API_BASE_URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise StepError("configuration", "API_BASE_URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise StepError("configuration", "API_BASE_URL must not contain a query or fragment")
    return raw.rstrip("/")


def _safe_http_detail(error):
    detail = str(getattr(error, "reason", "request rejected"))
    try:
        raw = error.read(4096)
        decoded = json.loads(raw.decode("utf-8"))
        if isinstance(decoded, dict):
            candidate = decoded.get("error") or decoded.get("message")
            if isinstance(candidate, str):
                detail = candidate
    except Exception:
        pass
    return " ".join(detail.split())[:200]


class HttpClient:
    def __init__(self, base_url):
        self.base_url = base_url
        context = ssl.create_default_context()
        try:
            context.set_alpn_protocols(["http/1.1"])
        except (AttributeError, NotImplementedError):
            pass
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )

    def request(self, step, method, path, body=None, token=None, retries=1,
                accept="application/json"):
        if not path.startswith("/"):
            raise ValueError("API paths must start with /")
        url = self.base_url + path
        encoded_body = None
        headers = {"Accept": accept, "User-Agent": USER_AGENT}
        if body is not None:
            encoded_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = "Bearer " + token

        last_error = None
        for attempt in range(retries):
            request = urllib.request.Request(
                url, data=encoded_body, headers=headers, method=method
            )
            try:
                with self.opener.open(request, timeout=HTTP_TIMEOUT) as response:
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise StepError(step, "response exceeded the 2 MiB safety limit")
                    return response.status, raw
            except urllib.error.HTTPError as exc:
                retryable = exc.code >= 500 or exc.code == 429
                last_error = RequestError(
                    step,
                    "HTTP %d: %s" % (exc.code, _safe_http_detail(exc)),
                    retryable=retryable,
                )
            except (urllib.error.URLError, http.client.HTTPException,
                    TimeoutError, OSError, ssl.SSLError) as exc:
                reason = getattr(exc, "reason", exc)
                last_error = RequestError(
                    step,
                    "network request failed: %s" % " ".join(str(reason).split())[:200],
                    retryable=True,
                )

            if not last_error.retryable or attempt + 1 >= retries:
                raise last_error
            time.sleep(0.25 * (attempt + 1))

        if last_error is None:  # Defensive; retries is always positive here.
            raise StepError(step, "request was not attempted")
        raise last_error

    def json(self, step, method, path, body=None, token=None, retries=1):
        status, raw = self.request(
            step, method, path, body=body, token=token, retries=retries
        )
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StepError(step, "server response was not valid JSON") from exc
        return status, decoded


def fetch_skill(client):
    status, raw = client.request(
        "fetch_skill", "GET", "/skill.md", retries=3, accept="text/markdown"
    )
    if not raw.strip():
        raise StepError("fetch_skill", "skill.md was empty")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StepError("fetch_skill", "skill.md was not UTF-8 text") from exc
    emit("fetch_skill", http_status=status, bytes=len(raw))


def authenticate(client, address, private_key):
    last_error = None
    for attempt in range(3):
        try:
            challenge_status, challenge_data = client.json(
                "auth_challenge",
                "GET",
                "/api/auth/challenge?" + urllib.parse.urlencode({"address": address}),
                retries=3,
            )
            if not isinstance(challenge_data, dict):
                raise StepError("auth_challenge", "challenge response was not an object")
            challenge = challenge_data.get("challenge")
            if not isinstance(challenge, str) or not challenge:
                raise StepError("auth_challenge", "challenge response omitted challenge")

            signature = sign_message(private_key, challenge)
            if recover_address(challenge, signature).lower() != address.lower():
                raise StepError("auth_challenge", "local signature recovery failed")

            verify_status, verify_data = client.json(
                "auth_verify",
                "POST",
                "/api/auth/verify",
                body={"address": address, "signature": signature},
            )
            if not isinstance(verify_data, dict):
                raise StepError("auth_verify", "verify response was not an object")
            token = verify_data.get("token")
            if not isinstance(token, str) or not token:
                raise StepError("auth_verify", "verify response omitted the session token")

            emit("auth_challenge", http_status=challenge_status)
            verify_fields = {"http_status": verify_status, "address": address}
            if verify_data.get("expiresAt") is not None:
                verify_fields["expires_at"] = verify_data["expiresAt"]
            emit("auth_verify", **verify_fields)
            return token
        except RequestError as exc:
            last_error = exc
            if not exc.retryable or attempt == 2:
                raise
            time.sleep(0.25 * (attempt + 1))

    if last_error is None:  # Defensive; the loop always returns or raises.
        raise StepError("auth_verify", "authentication was not attempted")
    raise last_error


def list_open_bounties(client):
    status, payload = client.json(
        "list_bounties", "GET", "/api/bounties?status=open", retries=3
    )
    if isinstance(payload, dict):
        bounties = payload.get("bounties")
    else:
        bounties = payload
    if not isinstance(bounties, list):
        raise StepError("list_bounties", "bounty response omitted the bounties list")

    open_bounties = []
    for bounty in bounties:
        if not isinstance(bounty, dict):
            raise StepError("list_bounties", "bounty list contained a non-object item")
        if str(bounty.get("status", "open")).lower() == "open":
            open_bounties.append(bounty)

    fields = {"http_status": status, "open_count": len(open_bounties)}
    if open_bounties:
        slug = open_bounties[0].get("slug")
        if not isinstance(slug, str) or not slug:
            raise StepError("list_bounties", "first open bounty omitted its slug")
        fields["first_slug"] = slug
    emit("list_bounties", **fields)
    return open_bounties


def run_agent(dry_run):
    private_key, source = load_identity()
    address = public_to_address(private_to_public(private_key))
    identity_fields = {"address": address, "source": source}
    if source in ("file", "generated"):
        identity_fields["key_file"] = os.path.basename(KEY_PATH)
    emit("identity", **identity_fields)

    client = HttpClient(normalized_base_url())
    fetch_skill(client)
    token = authenticate(client, address, private_key)
    bounties = list_open_bounties(client)

    if dry_run:
        fields = {"reason": "dry-run"}
        if bounties:
            fields["slug"] = bounties[0]["slug"]
        emit("enter_bounty", status="skipped", **fields)
        return 0

    if not bounties:
        emit("enter_bounty", status="skipped", reason="no-open-bounties")
        return 0

    slug = bounties[0]["slug"]
    handle = os.environ.get("AGENT_HANDLE", DEFAULT_HANDLE)
    if not handle.strip():
        raise StepError("enter_bounty", "AGENT_HANDLE must not be empty")
    quoted_slug = urllib.parse.quote(slug, safe="")
    status, response = client.json(
        "enter_bounty",
        "POST",
        "/api/bounties/%s/enter" % quoted_slug,
        body={"handle": handle},
        token=token,
    )
    if not isinstance(response, dict):
        raise StepError("enter_bounty", "enter response was not an object")
    emit("enter_bounty", http_status=status, slug=slug, handle=handle)
    return 0


def run_selftest():
    expected = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    try:
        empty_digest = keccak256(b"").hex()
        if empty_digest != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470":
            raise ValueError("Keccak-256 known vector failed")
        address = public_to_address(private_to_public(1))
        if address != expected:
            raise ValueError("private-key-1 address vector failed")
        message = "AIProve sample agent self-test"
        signature = sign_message(1, message)
        if recover_address(message, signature) != expected:
            raise ValueError("sign/recover roundtrip failed")
    except Exception as exc:
        raise StepError("selftest", str(exc)) from exc
    emit(
        "selftest",
        address=address,
        keccak256="ok",
        sign_recover="ok",
    )
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--selftest", action="store_true",
                      help="run cryptographic known vectors without network access")
    mode.add_argument("--dry-run", action="store_true",
                      help="fetch, authenticate, and list without entering a bounty")
    args = parser.parse_args(argv)

    try:
        if args.selftest:
            return run_selftest()
        return run_agent(args.dry_run)
    except StepError as exc:
        emit(exc.step, status="error", error=exc.message)
        return 1
    except KeyboardInterrupt:
        emit("agent", status="error", error="interrupted")
        return 130
    except Exception as exc:
        emit("agent", status="error",
             error="unexpected %s: %s" % (type(exc).__name__, str(exc)))
        return 1


if __name__ == "__main__":
    sys.exit(main())
