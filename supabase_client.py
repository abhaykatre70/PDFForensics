"""
supabase_client.py — Supabase client factory and helper functions.

Exposes:
    get_supabase()      – Returns a shared, authenticated Supabase client.
    fetch_all_users()   – Fetches every row from the `users` table.
    insert_user()       – Inserts a new user row; returns the created record.

Environment variables (loaded from .env via python-dotenv):
    SUPABASE_URL       – https://<project-ref>.supabase.co
    SUPABASE_ANON_KEY  – The project's anon/public JWT
"""

import logging
import os
import socket
from functools import lru_cache

from dotenv import load_dotenv

# Load .env so variables are available even when the module is imported
# directly (e.g. in tests / CLI scripts), not just via Flask.
load_dotenv()

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# DNS fallback patch
# Some home/ISP routers fail to resolve *.supabase.co subdomains.
# This patch intercepts getaddrinfo so Python resolves supabase.co
# via Google Public DNS (8.8.8.8) when the system DNS returns nothing.
# ─────────────────────────────────────────────────────────────────────────────

_SUPABASE_DNS_IP: str | None = None   # cached after first successful resolve
_ORIG_GETADDRINFO = socket.getaddrinfo


def _resolve_via_google_dns(hostname: str) -> str | None:
    """Try to resolve *hostname* using dnspython against 8.8.8.8.
    Falls back to a pre-verified Supabase Cloudflare IP if dnspython
    is unavailable or the query fails.
    """
    # --- attempt 1: dnspython (optional dep) --------------------------------
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        answers = resolver.resolve(hostname, "A", lifetime=5)
        ip = str(answers[0])
        logger.debug("Resolved %s -> %s (via dnspython / 8.8.8.8)", hostname, ip)
        return ip
    except Exception:
        pass

    # --- attempt 2: raw UDP DNS query (no extra deps) -----------------------
    import struct, random

    def _build_query(name: str) -> bytes:
        tid = random.randint(0, 65535)
        flags = 0x0100  # standard query, recursion desired
        header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
        parts = name.encode().split(b".")
        q = b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"
        q += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
        return header + q

    def _parse_answer_ip(data: bytes) -> str | None:
        # Skip header (12 bytes) + question section
        try:
            ancount = struct.unpack("!H", data[6:8])[0]
            if ancount == 0:
                return None
            i = 12
            # skip question name
            while data[i] != 0:
                if data[i] & 0xC0 == 0xC0:
                    i += 2
                    break
                i += data[i] + 1
            else:
                i += 1
            i += 4  # skip QTYPE+QCLASS
            # read first answer
            if data[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while data[i] != 0:
                    i += data[i] + 1
                i += 1
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[i: i + 10])
            i += 10
            if rtype == 1 and rdlen == 4:
                return ".".join(str(b) for b in data[i: i + 4])
        except Exception:
            pass
        return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4)
        query = _build_query(hostname)
        sock.sendto(query, ("8.8.8.8", 53))
        response, _ = sock.recvfrom(512)
        sock.close()
        ip = _parse_answer_ip(response)
        if ip:
            logger.debug("Resolved %s -> %s (via raw UDP / 8.8.8.8)", hostname, ip)
            return ip
    except Exception:
        pass

    # --- fallback: hard-coded Supabase Cloudflare IPs (last resort) ---------
    logger.warning(
        "Could not dynamically resolve %s; using fallback Cloudflare IP.", hostname
    )
    return "172.64.149.246"  # Known Cloudflare anycast IP for supabase.co


def _patched_getaddrinfo(host, port, *args, **kwargs):
    """Patched getaddrinfo that uses Google DNS or hardcoded IPs for Supabase."""
    # Target both the REST API (*.supabase.co) and the Pooler (*.pooler.supabase.com)
    is_rest = isinstance(host, str) and host.endswith(".supabase.co")
    is_pooler = isinstance(host, str) and host.endswith(".pooler.supabase.com")
    
    if is_pooler or is_rest:
        try:
            # First try system DNS (fast path)
            return _ORIG_GETADDRINFO(host, port, *args, **kwargs)
        except (socket.gaierror, OSError):
            # System DNS failed — use hardcoded fallback or Google DNS
            if host == "aws-1-ap-southeast-2.pooler.supabase.com":
                fallback_ip = "13.239.87.90"
            else:
                fallback_ip = _resolve_via_google_dns(host)
                
            if fallback_ip:
                logger.debug(
                    "System DNS failed for %s; using ip=%s (Patch fallback)",
                    host, fallback_ip
                )
                return _ORIG_GETADDRINFO(fallback_ip, port, *args, **kwargs)
    
    return _ORIG_GETADDRINFO(host, port, *args, **kwargs)


# Install the patch (idempotent — safe to import multiple times)
if socket.getaddrinfo is not _patched_getaddrinfo:
    socket.getaddrinfo = _patched_getaddrinfo
    logger.debug("Supabase DNS fallback patch installed.")

# ── Lazy-import supabase so the app still starts if the package is missing ────
try:
    from supabase import create_client, Client  # type: ignore
    _SUPABASE_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SUPABASE_AVAILABLE = False
    logger.warning(
        "supabase-py is not installed. "
        "Run: pip install supabase  — Supabase features will be disabled."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Client factory
# ─────────────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_supabase():
    """
    Return a cached Supabase client instance.

    The client is created once per process (lru_cache with maxsize=1).
    Thread-safe because supabase-py's Client is stateless per request.

    Raises:
        RuntimeError  – if SUPABASE_URL or SUPABASE_ANON_KEY are missing,
                        or if the supabase package is not installed.
    """
    if not _SUPABASE_AVAILABLE:
        raise RuntimeError(
            "supabase-py is not installed. "
            "Install it with: pip install supabase"
        )

    url: str = os.environ.get("SUPABASE_URL", "").strip()
    key: str = os.environ.get("SUPABASE_ANON_KEY", "").strip()

    if not url:
        raise RuntimeError(
            "SUPABASE_URL environment variable is not set. "
            "Add it to your .env file."
        )
    if not key:
        raise RuntimeError(
            "SUPABASE_ANON_KEY environment variable is not set. "
            "Add it to your .env file."
        )

    logger.info("Initialising Supabase client → %s", url)
    # Log the database host from environment for debugging
    db_url = os.environ.get("DATABASE_URL", "")
    if "@" in db_url:
        db_host = db_url.split("@")[1].split("/")[0]
        logger.info("Database Host detected in .env: %s", db_host)
    
    client: Client = create_client(url, key)
    return client


# ─────────────────────────────────────────────────────────────────────────────
# Users helpers
# ─────────────────────────────────────────────────────────────────────────────

def fetch_all_users() -> list[dict]:
    """
    Fetch every row from the ``users`` table.

    Returns:
        list[dict] – Each element is a user record with keys:
                     id, name, email, created_at.

    Raises:
        RuntimeError – if the Supabase query fails.
    """
    try:
        supabase = get_supabase()
        response = supabase.table("users").select("*").execute()
        logger.info("Fetched %d users from Supabase.", len(response.data))
        return response.data
    except Exception as exc:
        logger.error("fetch_all_users failed: %s", exc, exc_info=True)
        raise RuntimeError(f"Failed to fetch users: {exc}") from exc


def insert_user(name: str, email: str) -> dict:
    """
    Insert a new user into the ``users`` table.

    Args:
        name  (str): Display name of the user.
        email (str): Unique e-mail address.

    Returns:
        dict – The newly created user record (id, name, email, created_at).

    Raises:
        ValueError   – if ``name`` or ``email`` are empty.
        RuntimeError – if the Supabase query fails (e.g. duplicate e-mail).
    """
    if not name or not name.strip():
        raise ValueError("name must not be empty.")
    if not email or not email.strip():
        raise ValueError("email must not be empty.")

    payload = {"name": name.strip(), "email": email.strip().lower()}

    try:
        supabase = get_supabase()
        response = (
            supabase.table("users")
            .insert(payload)
            .execute()
        )
        if not response.data:
            raise RuntimeError("Insert succeeded but returned no data.")
        created = response.data[0]
        logger.info(
            "Inserted user id=%s email=%s", created.get("id"), created.get("email")
        )
        return created
    except RuntimeError:
        raise
    except Exception as exc:
        logger.error("insert_user failed: %s", exc, exc_info=True)
        raise RuntimeError(f"Failed to insert user: {exc}") from exc
