"""Named operator accounts for the Ops UI: roles, MFA, sessions, lockout.

Design (security first, standard library only):

* Passwords: ``hashlib.scrypt`` (N=2^15, r=8, p=1, 16-byte salt), compared
  in constant time. Minimum length 12. Plaintext is never stored or logged.
* MFA: RFC 6238 TOTP (30 s, 6 digits, SHA-1 — what every authenticator app
  speaks), +-1 step drift, and a code can be used only once (replay guard).
* Sessions: 256-bit random id in an HttpOnly + SameSite=Strict cookie; only
  its SHA-256 is stored, so a stolen database cannot be replayed. Idle
  timeout 30 min, absolute lifetime 12 h, and a per-session CSRF token.
* Lockout: 5 bad attempts lock the account for 15 minutes.
* Roles: viewer < analyst < admin.

This database is deliberately SEPARATE from the append-only audit store:
accounts must be mutable (password change, disable). Every change is still
written to the audit store by the caller, with the acting user's name.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

ROLES = ("viewer", "analyst", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}

MIN_PASSWORD_LEN = 12
MAX_FAILED = 5
LOCK_SECONDS = 15 * 60
IDLE_SECONDS = 30 * 60
ABSOLUTE_SECONDS = 12 * 3600
SETUP_SECONDS = 15 * 60
TOTP_STEP = 30
TOTP_DIGITS = 6
_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
_USERNAME_OK = set("abcdefghijklmnopqrstuvwxyz0123456789._-")


class AccountError(ValueError):
    """A refused account operation; the message is safe to show the operator."""


def role_at_least(role: str, needed: str) -> bool:
    return _RANK.get(role, -1) >= _RANK[needed]


# -- passwords ---------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            maxmem=64 * 1024 * 1024, dklen=32, **_SCRYPT)
    return "scrypt$%d$%d$%d$%s$%s" % (
        _SCRYPT["n"], _SCRYPT["r"], _SCRYPT["p"],
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        got = hashlib.scrypt(password.encode("utf-8"),
                             salt=base64.b64decode(salt), n=int(n), r=int(r),
                             p=int(p), maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(got, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


def check_password_policy(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise AccountError(f"كلمة المرور يجب ألا تقل عن {MIN_PASSWORD_LEN} حرفًا")
    if username and username.lower() in password.lower():
        raise AccountError("كلمة المرور لا يجب أن تحتوي على اسم المستخدم")
    if len(set(password)) < 6:
        raise AccountError("كلمة المرور ضعيفة جدًا (حروف مكررة)")


# -- TOTP (RFC 6238) ---------------------------------------------------------
def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** TOTP_DIGITS
    return str(code).zfill(TOTP_DIGITS)


def totp_now(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((at or time.time()) // TOTP_STEP))


def totp_match_step(secret: str, code: str, at: float | None = None) -> int | None:
    """The matching time step (for replay protection), or None."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == TOTP_DIGITS):
        return None
    step = int((at or time.time()) // TOTP_STEP)
    for s in (step - 1, step, step + 1):
        if hmac.compare_digest(_hotp(secret, s), code):
            return s
    return None


def otpauth_uri(secret: str, username: str, issuer: str = "Sentinel") -> str:
    return "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30" % (
        quote(issuer), quote(username), secret, quote(issuer))


# -- storage -----------------------------------------------------------------
@dataclass(frozen=True)
class User:
    username: str
    role: str
    mfa_enabled: bool
    must_change: bool
    disabled: bool
    locked_until: float
    last_login: str | None
    created: str


@dataclass(frozen=True)
class Session:
    username: str
    role: str
    csrf: str
    stage: str          # "full" or "setup" (first login: password + MFA enrolment)
    created: float
    ip: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY, role TEXT NOT NULL, pw_hash TEXT NOT NULL,
  totp_secret TEXT, mfa_enabled INTEGER NOT NULL DEFAULT 0,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  must_change INTEGER NOT NULL DEFAULT 1, disabled INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0,
  last_login TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  sid_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL,
  stage TEXT NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL,
  ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '');
"""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()


class AccountStore:
    """SQLite-backed users + sessions. Thread-safe (one lock, short calls)."""

    def __init__(self, path: str | Path, *, clock=time.time) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.executescript(_SCHEMA)
        self._db.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        self._db.close()

    # -- users ----------------------------------------------------------------
    def _row_user(self, row) -> User:
        return User(username=row[0], role=row[1], mfa_enabled=bool(row[2]),
                    must_change=bool(row[3]), disabled=bool(row[4]),
                    locked_until=float(row[5]), last_login=row[6], created=row[7])

    _USER_COLS = ("username, role, mfa_enabled, must_change, disabled, "
                  "locked_until, last_login, created")

    def get(self, username: str) -> User | None:
        with self._lock:
            row = self._db.execute(
                f"SELECT {self._USER_COLS} FROM users WHERE username = ?",
                (username,)).fetchone()
        return self._row_user(row) if row else None

    def list(self) -> list[User]:
        with self._lock:
            rows = self._db.execute(
                f"SELECT {self._USER_COLS} FROM users ORDER BY username").fetchall()
        return [self._row_user(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def create(self, username: str, role: str, password: str) -> User:
        username = (username or "").strip().lower()
        if not (3 <= len(username) <= 32) or not set(username) <= _USERNAME_OK:
            raise AccountError("اسم المستخدم: 3-32 حرفًا (a-z 0-9 . _ -)")
        if role not in ROLES:
            raise AccountError(f"الدور يجب أن يكون واحدًا من {', '.join(ROLES)}")
        check_password_policy(password, username)
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (username, role, pw_hash, totp_secret,"
                    " must_change, created) VALUES (?,?,?,?,1,?)",
                    (username, role, hash_password(password), new_totp_secret(),
                     _now_iso()))
                self._db.commit()
            except sqlite3.IntegrityError:
                raise AccountError("اسم المستخدم موجود بالفعل") from None
        return self.get(username)  # type: ignore[return-value]

    def _update(self, username: str, sql: str, args: tuple) -> None:
        with self._lock:
            cur = self._db.execute(sql + " WHERE username = ?", (*args, username))
            self._db.commit()
        if cur.rowcount == 0:
            raise AccountError("المستخدم غير موجود")

    def set_role(self, username: str, role: str) -> None:
        if role not in ROLES:
            raise AccountError("دور غير صالح")
        if role != "admin":
            self._guard_last_admin(username)
        self._update(username, "UPDATE users SET role = ?", (role,))

    def set_disabled(self, username: str, disabled: bool) -> None:
        if disabled:
            self._guard_last_admin(username)
        self._update(username, "UPDATE users SET disabled = ?", (1 if disabled else 0,))
        if disabled:
            self.revoke_user_sessions(username)

    def reset_password(self, username: str, password: str) -> None:
        """Admin reset: temporary password, must be changed at next login."""
        check_password_policy(password, username)
        self._update(username, "UPDATE users SET pw_hash = ?, must_change = 1,"
                     " failed = 0, locked_until = 0", (hash_password(password),))
        self.revoke_user_sessions(username)

    def reset_mfa(self, username: str) -> None:
        self._update(username, "UPDATE users SET totp_secret = ?, mfa_enabled = 0,"
                     " totp_last_step = 0", (new_totp_secret(),))
        self.revoke_user_sessions(username)

    def _guard_last_admin(self, username: str) -> None:
        with self._lock:
            admins = [r[0] for r in self._db.execute(
                "SELECT username FROM users WHERE role = 'admin' AND disabled = 0")]
        if admins == [username]:
            raise AccountError("لا يمكن تعطيل أو تخفيض آخر مدير في النظام")

    def totp_secret(self, username: str) -> str:
        with self._lock:
            row = self._db.execute("SELECT totp_secret FROM users WHERE username = ?",
                                   (username,)).fetchone()
        if not row:
            raise AccountError("المستخدم غير موجود")
        return row[0]

    # -- authentication -------------------------------------------------------
    def authenticate(self, username: str, password: str, code: str = "") -> tuple[str, User | None]:
        """Returns (result, user). result in: ok, setup, mfa_required,
        bad_credentials, bad_code, locked, disabled."""
        username = (username or "").strip().lower()
        now = self._clock()
        with self._lock:
            row = self._db.execute(
                "SELECT pw_hash, totp_secret, mfa_enabled, totp_last_step, disabled,"
                " failed, locked_until FROM users WHERE username = ?",
                (username,)).fetchone()
        if row is None:
            verify_password(password, hash_password("timing-equaliser"))
            return "bad_credentials", None
        pw_hash, secret, mfa, last_step, disabled, failed, locked_until = row
        if disabled:
            return "disabled", None
        if locked_until > now:
            return "locked", None
        if not verify_password(password, pw_hash):
            self._fail(username, failed)
            return "bad_credentials", None
        user = self.get(username)
        if not mfa:
            return "setup", user               # first login: enrol MFA
        if not code:
            return "mfa_required", None
        step = totp_match_step(secret, code, now)
        if step is None or step <= last_step:
            self._fail(username, failed)
            return "bad_code", None
        with self._lock:
            self._db.execute("UPDATE users SET failed = 0, locked_until = 0,"
                             " totp_last_step = ?, last_login = ? WHERE username = ?",
                             (step, _now_iso(), username))
            self._db.commit()
        return ("setup" if user and user.must_change else "ok"), self.get(username)

    def _fail(self, username: str, failed: int) -> None:
        failed += 1
        locked = self._clock() + LOCK_SECONDS if failed >= MAX_FAILED else 0
        with self._lock:
            self._db.execute("UPDATE users SET failed = ?, locked_until = ?"
                             " WHERE username = ?",
                             (0 if locked else failed, locked, username))
            self._db.commit()

    def complete_setup(self, username: str, new_password: str | None, code: str) -> None:
        """First login: (optionally) set own password, then prove the MFA app works."""
        user = self.get(username)
        if user is None:
            raise AccountError("المستخدم غير موجود")
        if user.must_change:
            if not new_password:
                raise AccountError("يجب تعيين كلمة مرور جديدة")
            check_password_policy(new_password, username)
        secret = self.totp_secret(username)
        step = totp_match_step(secret, code, self._clock())
        if step is None:
            raise AccountError("رمز التحقق غير صحيح — تأكد من ساعة الهاتف")
        sets = ["mfa_enabled = 1", "totp_last_step = ?", "last_login = ?",
                "failed = 0", "locked_until = 0"]
        args: list = [step, _now_iso()]
        if user.must_change:
            sets += ["pw_hash = ?", "must_change = 0"]
            args.append(hash_password(new_password))  # type: ignore[arg-type]
        self._update(username, "UPDATE users SET " + ", ".join(sets), tuple(args))

    # -- sessions -------------------------------------------------------------
    def new_session(self, username: str, *, stage: str = "full", ip: str = "",
                    user_agent: str = "") -> str:
        sid = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._db.execute(
                "INSERT INTO sessions (sid_hash, username, csrf, stage, created,"
                " last_seen, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
                (_sid_hash(sid), username, secrets.token_urlsafe(24), stage,
                 now, now, ip[:64], user_agent[:200]))
            self._db.commit()
        return sid

    def session(self, sid: str | None, *, touch: bool = True) -> Session | None:
        if not sid:
            return None
        now = self._clock()
        h = _sid_hash(sid)
        with self._lock:
            row = self._db.execute(
                "SELECT s.username, u.role, s.csrf, s.stage, s.created, s.last_seen,"
                " s.ip, u.disabled FROM sessions s JOIN users u ON u.username ="
                " s.username WHERE s.sid_hash = ?", (h,)).fetchone()
            if row is None:
                return None
            username, role, csrf, stage, created, last_seen, ip, disabled = row
            limit = SETUP_SECONDS if stage == "setup" else ABSOLUTE_SECONDS
            if disabled or now - last_seen > IDLE_SECONDS or now - created > limit:
                self._db.execute("DELETE FROM sessions WHERE sid_hash = ?", (h,))
                self._db.commit()
                return None
            if touch:
                self._db.execute("UPDATE sessions SET last_seen = ? WHERE sid_hash = ?",
                                 (now, h))
                self._db.commit()
        return Session(username=username, role=role, csrf=csrf, stage=stage,
                       created=created, ip=ip)

    def revoke(self, sid: str | None) -> None:
        if sid:
            with self._lock:
                self._db.execute("DELETE FROM sessions WHERE sid_hash = ?", (_sid_hash(sid),))
                self._db.commit()

    def revoke_user_sessions(self, username: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE username = ?", (username,))
            self._db.commit()

    def active_sessions(self) -> list[dict]:
        now = self._clock()
        with self._lock:
            rows = self._db.execute(
                "SELECT username, stage, created, last_seen, ip, user_agent"
                " FROM sessions ORDER BY last_seen DESC").fetchall()
        return [{"username": r[0], "stage": r[1], "created": r[2], "last_seen": r[3],
                 "ip": r[4], "user_agent": r[5]}
                for r in rows if now - r[3] <= IDLE_SECONDS]
