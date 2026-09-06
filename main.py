import json
import os
import uuid
from pathlib import Path
from typing import Any

import httpx
import torch
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from transformers import pipeline


# ============================================================
# HSIB-AI
# Hasib Session Integrated Version
# Challenge 19 - LDAP Injection
# ============================================================

APP_VERSION = "3.0.0"
MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct"

CHALLENGE_ID = 19
INITIAL_FLAG = "HASIB{ldap_injection_0119}"

# Hasib must be reachable from inside this container.
# Example: http://Hasib:8000
Hasib_INTERNAL_URL = os.getenv("Hasib_INTERNAL_URL", "http://Hasib:8000").rstrip("/")
Hasib_ME_ENDPOINT = os.getenv("Hasib_ME_ENDPOINT", "/api/v1/users/me")
Hasib_SESSION_COOKIE = os.getenv("Hasib_SESSION_COOKIE", "session")

# By default the province is read from Hasib's standard "affiliation"
# field. The code also checks several common names as fallbacks.
Hasib_PROVINCE_FIELD = os.getenv("Hasib_PROVINCE_FIELD", "affiliation").strip()


# ============================================================
# Paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
CONFIG_DIR = BASE_DIR / "config"
PROVINCE_FLAGS_FILE = CONFIG_DIR / "province_flags.json"


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title="HSIB-AI",
    description="AI Hasib Assistant - Hasib Session Integrated",
    version=APP_VERSION,
)


# ============================================================
# Static Files
# ============================================================

if FRONTEND_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(FRONTEND_DIR)),
        name="static",
    )


# ============================================================
# Model
# ============================================================

print("[HSIB-AI] Loading model...")
print(f"[HSIB-AI] Model: {MODEL_NAME}")

if torch.cuda.is_available():
    GPU_NAME = torch.cuda.get_device_name(0)
    print("[HSIB-AI] CUDA: available")
    print(f"[HSIB-AI] GPU: {GPU_NAME}")

    generator = pipeline(
        "text-generation",
        model=MODEL_NAME,
        device=0,
        torch_dtype=torch.bfloat16,
    )
else:
    GPU_NAME = "CPU"
    print("[HSIB-AI] CUDA: unavailable")
    print("[HSIB-AI] Running on CPU")

    generator = pipeline(
        "text-generation",
        model=MODEL_NAME,
        device=-1,
    )

print("[HSIB-AI] Model loaded successfully.")


# ============================================================
# Challenge Knowledge Base
# ============================================================

CHALLENGE_19 = """
Challenge 19 — LDAP Injection

شماره:
19

عنوان:
LDAP Injection

عنوان فارسی:
تزریق LDAP

دسته:
Injection / Authentication Bypass

سختی:
Hard

امتیاز:
350

هدف:
استفاده از LDAP Injection برای مشاهده اطلاعات کاربر Administrator
و استخراج اطلاعات Challenge.

Endpoint:
GET /lab/19

Search:
GET /lab/19/search

Parameter:
username

LDAP Query:

(&(uid=USERNAME)(active=true))

نمونه:

/lab/19/search?username=alice

Query:

(&(uid=alice)(active=true))

آسیب‌پذیری:

پارامتر username مستقیماً داخل LDAP Filter قرار می‌گیرد
و Escape نمی‌شود.

کد آسیب‌پذیر:

username = request.args.get("username")

query = (
    "(&(uid="
    + username +
    ")(active=true))"
)

Payload:

*

نمونه:

/lab/19/search?username=*

Query:

(&(uid=*)(active=true))

نتیجه:

alice
Role: employee
Secret: normal-user

ldap_admin
Role: administrator

کاراکترهای مهم:

* = Wildcard
( = شروع شرط
) = پایان شرط
& = AND

CWE:
CWE-90

OWASP:
A03:2021 Injection
"""


# ============================================================
# System Prompt
# ============================================================

SYSTEM_PROMPT = """
تو HSIB-AI هستی؛ دستیار آموزشی HSIB Vulnerable Lab.

قوانین:

1. همیشه فارسی روان پاسخ بده.
2. فقط بر اساس Knowledge Base پاسخ بده.
3. Challenge 19 مربوط به LDAP Injection است.
4. پاسخ‌ها را کوتاه، واضح و مرحله‌ای بده.
5. وضعیت مراحل را Python تعیین می‌کند.
6. وضعیت داخلی Session را به کاربر نشان نده.
7. Flag استانی را قبل از تکمیل تمام مراحل افشا نکن.
8. اگر Python اجازه صدور Flag نداده است، Flag تولید یا حدس نزن.
9. Flag استانی باید دقیقاً از فایل تنظیمات سیستم خوانده شود.
10. درباره Flagهای سایر استان‌ها صحبت نکن.
11. استان کاربر از Session معتبر Hasib در Backend تعیین می‌شود؛
    هرگز از کاربر نام استان را سؤال نکن.
12. اطلاعات هویتی Hasib را به کاربر نمایش نده.
"""


# ============================================================
# Province Flags
# ============================================================

def load_province_flags() -> dict[str, str]:
    if not PROVINCE_FLAGS_FILE.exists():
        print(f"[WARNING] Province flags file not found: {PROVINCE_FLAGS_FILE}")
        return {}

    try:
        with open(PROVINCE_FLAGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("province_flags.json must contain a JSON object")

        print(f"[HSIB-AI] Loaded {len(data)} province flags.")
        return data

    except Exception as exc:
        print(f"[ERROR] Cannot load province flags: {exc}")
        return {}


PROVINCE_FLAGS = load_province_flags()


# ============================================================
# Sessions
# ============================================================

SESSIONS: dict[str, dict[str, Any]] = {}

VALID_STAGES = {
    "WAITING_INITIAL_FLAG",
    "VERIFYING_VULNERABILITY",
    "VERIFYING_PAYLOAD",
    "VERIFYING_QUERY_EFFECT",
    "VERIFYING_ADMIN",
    "COMPLETED",
}


def create_session(Hasib_user: dict[str, Any], province: str) -> str:
    session_id = str(uuid.uuid4())

    SESSIONS[session_id] = {
        "challenge": CHALLENGE_ID,
        "stage": "WAITING_INITIAL_FLAG",

        "initial_flag_verified": False,
        "vulnerability_verified": False,
        "payload_verified": False,
        "query_effect_verified": False,
        "admin_verified": False,

        # These values are server-side only.
        "Hasib_user_id": Hasib_user.get("id"),
        "Hasib_username": Hasib_user.get("name") or Hasib_user.get("user") or "",
        "province": province,

        "province_flag_issued": False,
        "completed": False,
    }

    return session_id


def get_session(session_id: str):
    if not session_id:
        return None

    return SESSIONS.get(session_id)


# ============================================================
# Hasib Session / Identity
# ============================================================

def extract_Hasib_user(data: Any) -> dict[str, Any] | None:
    """
    Supports the common Hasib API response:
      {"success": true, "data": {...}}

    Also accepts a direct user object for compatibility.
    """
    if not isinstance(data, dict):
        return None

    if isinstance(data.get("data"), dict):
        return data["data"]

    if isinstance(data.get("user"), dict):
        return data["user"]

    # Direct user object
    if any(key in data for key in ("id", "name", "email")):
        return data

    return None


def extract_province(user: dict[str, Any]) -> str | None:
    """
    Province source priority:
      1. Configured Hasib_PROVINCE_FIELD
      2. common fields: province, affiliation, country
      3. nested fields/custom fields if exposed by Hasib
    """

    candidates = [
        Hasib_PROVINCE_FIELD,
        "province",
        "affiliation",
        "country",
    ]

    seen = set()

    for field in candidates:
        if not field or field in seen:
            continue

        seen.add(field)

        value = user.get(field)

        if isinstance(value, str) and value.strip():
            return value.strip()

    # Some Hasib/plugin responses may expose custom fields as:
    # {"fields": {"province": "..."}}
    for container_name in ("fields", "custom_fields", "profile"):
        container = user.get(container_name)

        if not isinstance(container, dict):
            continue

        for field in (
            Hasib_PROVINCE_FIELD,
            "province",
            "استان",
            "affiliation",
        ):
            value = container.get(field)

            if isinstance(value, str) and value.strip():
                return value.strip()

    return None


def normalize_province(value: str) -> str | None:
    normalized = normalize_text(value)

    for province in PROVINCE_FLAGS:
        if normalized == normalize_text(province):
            return province

    # Accept a province value with harmless surrounding text.
    for province in PROVINCE_FLAGS:
        p = normalize_text(province)
        if p and p in normalized:
            return province

    return None


async def get_Hasib_current_user(request: Request) -> tuple[dict[str, Any] | None, str | None]:
    """
    Forward the browser's Hasib cookies to Hasib's /api/v1/users/me.

    The browser never sends the Hasib password to HSIB-AI.
    HSIB-AI only receives the already-issued Hasib session cookie.
    """

    session_cookie = request.cookies.get(Hasib_SESSION_COOKIE)

    if not session_cookie:
        return None, "Hasib session cookie not found."

    # Forward only the Hasib authentication cookie.
    # Do not pass unrelated browser cookies to Hasib.
    cookie_header = f"{Hasib_SESSION_COOKIE}={session_cookie}"

    url = f"{Hasib_INTERNAL_URL}{Hasib_ME_ENDPOINT}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=3.0),
            follow_redirects=False,
        ) as client:
            response = await client.get(
                url,
                headers={
                    "Cookie": cookie_header,
                    "Accept": "application/json",
                },
            )

    except httpx.RequestError as exc:
        print(f"[Hasib] Connection error: {exc}")
        return None, "Hasib is unreachable from HSIB-AI."

    if response.status_code in (401, 403):
        return None, "Hasib session is not authenticated."

    if response.status_code >= 300:
        print(
            f"[Hasib] /users/me returned HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )
        return None, "Hasib identity lookup failed."

    try:
        data = response.json()
    except ValueError:
        return None, "Hasib returned a non-JSON response."

    user = extract_Hasib_user(data)

    if not user:
        return None, "Authenticated Hasib user could not be determined."

    return user, None


# ============================================================
# Request Model
# ============================================================

class ChatRequest(BaseModel):
    session_id: str = Field(..., min_length=10, max_length=100)
    challenge: str = "19"
    message: str = Field(..., min_length=1, max_length=5000)
    max_new_tokens: int = Field(default=250, ge=50, le=700)


# ============================================================
# Text Helpers
# ============================================================

def normalize_text(text: str) -> str:
    text = text.strip().lower()

    replacements = {
        "ي": "ی",
        "ى": "ی",
        "ك": "ک",
        "ة": "ه",
        "ۀ": "ه",
        "\u200c": " ",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return text


def contains_any(text, words):
    normalized = normalize_text(text)

    return any(
        normalize_text(word) in normalized
        for word in words
    )


# ============================================================
# Stage Validators
# ============================================================

def verify_initial_flag(message):
    return message.strip() == INITIAL_FLAG


def verify_vulnerability(message):
    text = normalize_text(message)

    has_ldap = contains_any(
        text,
        [
            "ldap",
            "ldap injection",
            "تزریق ldap",
            "فیلتر ldap",
        ],
    )

    has_input = contains_any(
        text,
        [
            "مستقیم",
            "مستقیما",
            "وارد query",
            "وارد کوئری",
            "وارد فیلتر",
            "داخل ldap",
            "داخل فیلتر",
            "string concatenation",
            "الحاق رشته",
            "concatenation",
        ],
    )

    has_unsafe = contains_any(
        text,
        [
            "escape نمی",
            "escape نشده",
            "بدون escape",
            "sanitize نشده",
            "sanitize نمی",
            "اعتبارسنجی نمی",
            "ورودی کاربر",
        ],
    )

    return has_ldap and (has_input or has_unsafe)


def verify_payload(message):
    text = normalize_text(message)

    if message.strip() == "*":
        return True

    return contains_any(
        text,
        [
            "username=*",
            "username=%2a",
            "uid=*",
            "wildcard",
            "وایلدکارد",
            "ستاره",
            "کاراکتر *",
            "کاراکتر ستاره",
        ],
    )


def verify_query_effect(message):
    text = normalize_text(message)
    compact = text.replace(" ", "")

    if "(&(uid=*)(active=true))" in compact:
        return True

    return contains_any(
        text,
        [
            "wildcard",
            "وایلدکارد",
            "چند کاربر",
            "چندین کاربر",
            "همه کاربران",
            "uid=*",
            "uid به صورت wildcard",
            "مقدار uid",
        ],
    )


def verify_admin(message):
    text = normalize_text(message)

    return contains_any(
        text,
        [
            "ldap_admin",
            "ldap admin",
            "ادمین ldap",
        ],
    )


# ============================================================
# Safe AI Helper
# ============================================================

def generate_ai_response(
    session,
    user_message,
    instruction,
    max_new_tokens=250,
):
    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": f"""
Knowledge Base:

{CHALLENGE_19}

دستور:

{instruction}

پیام کاربر:

{user_message}

فقط پاسخ مورد نیاز را بده.
""",
        },
    ]

    result = generator(
        messages,
        max_new_tokens=max_new_tokens,
        do_sample=True,
        temperature=0.35,
        top_p=0.85,
    )

    generated = result[0]["generated_text"]

    if isinstance(generated, list):
        answer = generated[-1]["content"]
    else:
        answer = generated

    return answer.strip()


# ============================================================
# Process Challenge
# ============================================================

def process_message(session, message):
    stage = session["stage"]

    # --------------------------------------------------------
    # 1. Initial Flag
    # --------------------------------------------------------

    if stage == "WAITING_INITIAL_FLAG":
        if verify_initial_flag(message):
            session["initial_flag_verified"] = True
            session["stage"] = "VERIFYING_VULNERABILITY"

            return {
                "stage": session["stage"],
                "stage_completed": True,
                "response": (
                    "✅ فلگ صحیح است.\n\n"
                    "حالا توضیح بده **آسیب‌پذیری Challenge 19 چیست "
                    "و چرا پارامتر `username` آسیب‌پذیر است؟**"
                ),
            }

        return {
            "stage": stage,
            "stage_completed": False,
            "response": (
                "❌ فلگ صحیح نیست.\n\n"
                "فلگ به‌دست‌آمده از Challenge 19 را "
                "دقیقاً وارد کن."
            ),
        }

    # --------------------------------------------------------
    # 2. Vulnerability
    # --------------------------------------------------------

    if stage == "VERIFYING_VULNERABILITY":
        if verify_vulnerability(message):
            session["vulnerability_verified"] = True
            session["stage"] = "VERIFYING_PAYLOAD"

            return {
                "stage": session["stage"],
                "stage_completed": True,
                "response": (
                    "✅ درست است.\n\n"
                    "حالا **Payload** مورد استفاده برای تست "
                    "LDAP Injection را وارد کن."
                ),
            }

        return {
            "stage": stage,
            "stage_completed": False,
            "response": (
                "❌ توضیح کامل نیست.\n\n"
                "بررسی کن که مقدار `username` چگونه وارد "
                "LDAP Filter می‌شود و آیا Escape می‌شود یا خیر."
            ),
        }

    # --------------------------------------------------------
    # 3. Payload
    # --------------------------------------------------------

    if stage == "VERIFYING_PAYLOAD":
        if verify_payload(message):
            session["payload_verified"] = True
            session["stage"] = "VERIFYING_QUERY_EFFECT"

            return {
                "stage": session["stage"],
                "stage_completed": True,
                "response": (
                    "✅ Payload صحیح است.\n\n"
                    "حالا توضیح بده این Payload چه تغییری "
                    "در LDAP Query ایجاد کرد."
                ),
            }

        return {
            "stage": stage,
            "stage_completed": False,
            "response": (
                "❌ Payload صحیح تشخیص داده نشد.\n\n"
                "به Wildcard در LDAP فکر کن."
            ),
        }

    # --------------------------------------------------------
    # 4. Query Effect
    # --------------------------------------------------------

    if stage == "VERIFYING_QUERY_EFFECT":
        if verify_query_effect(message):
            session["query_effect_verified"] = True
            session["stage"] = "VERIFYING_ADMIN"

            return {
                "stage": session["stage"],
                "stage_completed": True,
                "response": (
                    "✅ توضیح درست است.\n\n"
                    "حالا بگو کدام کاربر در نتایج "
                    "**Role برابر administrator** داشت؟"
                ),
            }

        return {
            "stage": stage,
            "stage_completed": False,
            "response": (
                "❌ توضیح کامل نیست.\n\n"
                "به اثر `*` روی مقدار `uid` و Query حاصل فکر کن."
            ),
        }

    # --------------------------------------------------------
    # 5. Administrator
    # --------------------------------------------------------

    if stage == "VERIFYING_ADMIN":
        if verify_admin(message):
            session["admin_verified"] = True
            session["stage"] = "COMPLETED"

            return {
                "stage": "COMPLETED",
                "stage_completed": True,
                "response": (
                    "✅ صحیح است.\n\n"
                    "تمام مراحل فنی Challenge 19 تأیید شد.\n\n"
                    "در حال بررسی Session حساب Hasib و صدور "
                    "Flag مخصوص کاربر..."
                ),
            }

        return {
            "stage": stage,
            "stage_completed": False,
            "response": (
                "❌ کاربر صحیح نیست.\n\n"
                "کاربری را پیدا کن که Role آن "
                "`administrator` باشد."
            ),
        }

    # --------------------------------------------------------
    # 6. Completed
    # --------------------------------------------------------

    if stage == "COMPLETED":
        return {
            "stage": "COMPLETED",
            "stage_completed": True,
            "response": (
                "تمام مراحل فنی Challenge 19 تکمیل شده است."
            ),
        }

    return {
        "stage": stage,
        "stage_completed": False,
        "response": "وضعیت Session نامعتبر است.",
    }


# ============================================================
# API
# ============================================================

@app.get("/api")
def api_root():
    return {
        "name": "HSIB-AI",
        "version": APP_VERSION,
        "status": "online",
        "challenge": CHALLENGE_ID,
        "model": MODEL_NAME,
        "cuda": torch.cuda.is_available(),
        "gpu": (
            torch.cuda.get_device_name(0)
            if torch.cuda.is_available()
            else "CPU"
        ),
        "Hasib_session_integration": True,
    }


# ============================================================
# Health
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "cuda": torch.cuda.is_available(),
        "gpu": (
            torch.cuda.get_device_name(0)
            if torch.cuda.is_available()
            else "CPU"
        ),
        "Hasib_configured": bool(Hasib_INTERNAL_URL),
    }


# ============================================================
# Frontend
# ============================================================

@app.get("/", include_in_schema=False)
async def frontend():
    index_file = FRONTEND_DIR / "index.html"

    if not index_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Frontend index.html not found.",
        )

    return FileResponse(str(index_file))


# ============================================================
# Hasib Identity Check
# ============================================================

@app.get("/me")
async def current_user(request: Request):
    """
    Returns only non-sensitive state needed by the frontend.
    The Hasib username/user id are intentionally not exposed.
    """

    user, error = await get_Hasib_current_user(request)

    if error or not user:
        raise HTTPException(
            status_code=401,
            detail=error or "Hasib authentication required.",
        )

    raw_province = extract_province(user)
    province = normalize_province(raw_province) if raw_province else None

    if not province:
        raise HTTPException(
            status_code=422,
            detail=(
                "Province is not configured for this Hasib account. "
                f"Configure the '{Hasib_PROVINCE_FIELD}' field in Hasib."
            ),
        )

    return {
        "authenticated": True,
        "province_configured": True,
    }


# ============================================================
# Create Session
# ============================================================

@app.post("/session")
async def new_session(request: Request):
    """
    A HSIB-AI session is bound to the currently authenticated Hasib user.
    The browser's Hasib session cookie is verified server-side.
    """

    user, error = await get_Hasib_current_user(request)

    if error or not user:
        raise HTTPException(
            status_code=401,
            detail=(
                "ابتدا با حساب خود در Hasib وارد شوید؛ "
                "سپس HSIB-AI را باز کنید."
            ),
        )

    raw_province = extract_province(user)
    province = normalize_province(raw_province) if raw_province else None

    if not province:
        raise HTTPException(
            status_code=422,
            detail=(
                "استان حساب Hasib مشخص نشده است. "
                f"مقدار استان را در فیلد '{Hasib_PROVINCE_FIELD}' "
                "حساب کاربر تنظیم کنید."
            ),
        )

    session_id = create_session(user, province)

    return {
        "session_id": session_id,
        "challenge": CHALLENGE_ID,
        "stage": "WAITING_INITIAL_FLAG",
        "username": SESSIONS[session_id]["Hasib_username"],
        "message": (
            "Session ایجاد شد. "
            "فلگ به‌دست‌آمده از Challenge 19 را وارد کن."
        ),
    }


# ============================================================
# Reset Session
# ============================================================

@app.post("/session/reset")
async def reset_session(request: Request):
    user, error = await get_Hasib_current_user(request)

    if error or not user:
        raise HTTPException(
            status_code=401,
            detail="Hasib authentication required.",
        )

    raw_province = extract_province(user)
    province = normalize_province(raw_province) if raw_province else None

    if not province:
        raise HTTPException(
            status_code=422,
            detail="Province is not configured for this Hasib account.",
        )

    session_id = create_session(user, province)

    return {
        "session_id": session_id,
        "challenge": CHALLENGE_ID,
        "stage": "WAITING_INITIAL_FLAG",
        "message": "Session جدید ایجاد شد.",
    }


# ============================================================
# Chat
# ============================================================

@app.post("/chat")
async def chat(request: ChatRequest, http_request: Request):
    if request.challenge != "19":
        raise HTTPException(
            status_code=400,
            detail="Only Challenge 19 is currently available.",
        )

    session = get_session(request.session_id)

    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found. Create a new session first.",
        )

    # --------------------------------------------------------
    # Security: bind the AI session to the current Hasib account.
    # A copied session_id alone is not enough.
    # --------------------------------------------------------

    user, error = await get_Hasib_current_user(http_request)

    if error or not user:
        raise HTTPException(
            status_code=401,
            detail="Hasib authentication required.",
        )

    current_user_id = user.get("id")

    if (
        session.get("Hasib_user_id") is not None
        and current_user_id != session.get("Hasib_user_id")
    ):
        raise HTTPException(
            status_code=403,
            detail="This HSIB-AI session belongs to another Hasib account.",
        )

    # Re-read the province from the current Hasib session.
    # This prevents a user from changing their Hasib account and
    # continuing with the previous account's province.
    raw_province = extract_province(user)
    province = normalize_province(raw_province) if raw_province else None

    if not province:
        raise HTTPException(
            status_code=422,
            detail="Province is not configured for this Hasib account.",
        )

    session["province"] = province

    result = process_message(
        session=session,
        message=request.message,
    )

    response = {
        "model": MODEL_NAME,
        "gpu": (
            torch.cuda.get_device_name(0)
            if torch.cuda.is_available()
            else "CPU"
        ),
        "session_id": request.session_id,
        "challenge": CHALLENGE_ID,
        "stage": result["stage"],
        "stage_completed": result["stage_completed"],
        "response": result["response"],
    }

    # --------------------------------------------------------
    # Final province flag
    # --------------------------------------------------------

    if (
        result.get("stage") == "COMPLETED"
        and session.get("admin_verified")
        and not session.get("province_flag_issued")
    ):
        province_flag = PROVINCE_FLAGS.get(province)

        if not province_flag:
            session["stage"] = "VERIFYING_ADMIN"

            response["stage"] = "VERIFYING_ADMIN"
            response["stage_completed"] = False
            response["response"] = (
                "مراحل فنی کامل شد، اما Flag استان برای حساب شما "
                "در تنظیمات سیستم وجود ندارد."
            )

            return response

        if (
            isinstance(province_flag, str)
            and province_flag.startswith("CHANGE_ME_")
        ):
            session["stage"] = "VERIFYING_ADMIN"

            response["stage"] = "VERIFYING_ADMIN"
            response["stage_completed"] = False
            response["response"] = (
                "مراحل فنی کامل شد، اما Flag این استان "
                "هنوز پیکربندی نشده است."
            )

            return response

        session["province_flag_issued"] = True
        session["completed"] = True

        response["stage"] = "COMPLETED"
        response["stage_completed"] = True
        response["response"] = (
            "🎉 تمام مراحل Challenge 19 با موفقیت تکمیل شد.\n\n"
            "استان حساب Hasib به‌صورت خودکار شناسایی شد.\n\n"
            "### Flag نهایی\n\n"
            f"```text\n{province_flag}\n```\n\n"
            "Flag را در Hasib ثبت کن."
        )
        response["flag"] = province_flag

    return response
