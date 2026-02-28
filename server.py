from fastapi import FastAPI, APIRouter, HTTPException, Request, Response
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import uuid
import httpx
import csv
import io
import json
import re
import asyncio
from pathlib import Path
from bs4 import BeautifulSoup
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

# Google Sheets config
SPREADSHEET_ID = "1QiaI7s5GitbvyVCNw_uzdcJ5TTAVSuUVWARRvJFLQwA"
SHEET_NAMES = {
    "raw_leads": "RawLeads",
    "analysis": "Analysis",
    "outreach_queue": "OutreachQueue"
}

# Cache
_cache = {}
CACHE_TTL = 300

# Models
@api_router.get("/")
async def root():
    return {"message": "Growth System API", "status": "ok"}


class SessionExchange(BaseModel):
    """Exchange Google ID token for a session. Set id_token from Google Sign-In."""
    id_token: str

class StatusUpdate(BaseModel):
    status: str


class DiscoverRequest(BaseModel):
    niche: str
    city: str
    state: str = "FL"


class IGLoginRequest(BaseModel):
    username: str
    password: str


class IGVerify2FARequest(BaseModel):
    code: str


class IGSendDMRequest(BaseModel):
    target_username: str
    message: str
    lead_id: str = ""


class IGSearchUserRequest(BaseModel):
    query: str


class IGMessageTemplateRequest(BaseModel):
    template: str


# --- Google Sheets Fetching ---
async def fetch_sheet_data(sheet_name: str) -> List[Dict[str, Any]]:
    cache_key = f"sheet_{sheet_name}"
    now = datetime.now(timezone.utc).timestamp()

    if cache_key in _cache:
        cached_data, cached_time = _cache[cache_key]
        if now - cached_time < CACHE_TTL:
            return cached_data

    url = f"https://docs.google.com/spreadsheets/d/{SPREADSHEET_ID}/gviz/tq?tqx=out:csv&sheet={quote(sheet_name)}"

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as http_client:
            response = await http_client.get(url)
            if response.status_code != 200:
                logger.error(f"Failed to fetch sheet {sheet_name}: {response.status_code}")
                return []

            text = response.text
            # Check if response is actually CSV (not an HTML error page)
            if text.strip().startswith('<!') or text.strip().startswith('<html'):
                logger.error(f"Sheet {sheet_name} returned HTML â€” likely not shared publicly")
                return []

            reader = csv.reader(io.StringIO(text))
            headers = next(reader, [])
            if not headers:
                return []

            rows = []
            for i, row in enumerate(reader):
                row_dict = {"_row_index": i}
                for j, header in enumerate(headers):
                    if header:
                        row_dict[header] = row[j] if j < len(row) else ""
                rows.append(row_dict)

            _cache[cache_key] = (rows, now)
            return rows
    except Exception as e:
        logger.error(f"Error fetching sheet {sheet_name}: {e}")
        return []


def _find_col(row: dict, patterns: list) -> str:
    for key in row:
        if key.startswith("_"):
            continue
        kl = key.lower()
        for p in patterns:
            if p in kl:
                return row[key]
    return ""


def _find_status(row: dict) -> str:
    return _find_col(row, ["status", "estado"])


# --- Auth (Google OAuth, no third-party auth) ---
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")


def _verify_google_id_token(id_token: str) -> dict:
    """Verify Google ID token and return payload (email, name, picture, sub)."""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GOOGLE_CLIENT_ID not configured")
    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests
        id_info = id_token.verify_oauth2_token(
            id_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )
        return {
            "email": id_info.get("email") or "",
            "name": id_info.get("name") or id_info.get("email", ""),
            "picture": id_info.get("picture") or "",
            "sub": id_info.get("sub", ""),
        }
    except Exception as e:
        logging.getLogger(__name__).warning(f"Google token verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired Google token")


@api_router.post("/auth/session")
async def exchange_session(data: SessionExchange, response: Response):
    user_data = _verify_google_id_token(data.id_token)
    email = user_data["email"]
    name = user_data["name"]
    picture = user_data["picture"]
    session_token = str(uuid.uuid4())

    existing = await db.users.find_one({"email": email}, {"_id": 0})
    if not existing:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        await db.users.insert_one({
            "user_id": user_id,
            "email": email,
            "name": name,
            "picture": picture,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
    else:
        user_id = existing["user_id"]
        await db.users.update_one(
            {"email": email},
            {"$set": {"name": name, "picture": picture}}
        )

    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    await db.user_sessions.insert_one({
        "user_id": user_id,
        "session_token": session_token,
        "expires_at": expires_at.isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
        max_age=7 * 24 * 60 * 60
    )

    return {"user_id": user_id, "email": email, "name": name, "picture": picture}


async def get_current_user(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    expires_at = session["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
  2     expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired")

    user = await db.users.find_one({"user_id": session["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@api_router.get("/auth/me")
async def auth_me(request: Request):
    return await get_current_user(request)


@api_router.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token:
        await db.user_sessions.delete_one({"session_token": token})
    response.delete_cookie("session_token", path="/", secure=True, samesite="none")
    return {"ok": True}


# --- Sheets Data ---
@api_router.get("/sheets/raw-leads")
async def get_raw_leads(request: Request):
    await get_current_user(request)
    data = await fetch_sheet_data(SHEET_NAMES["raw_leads"])
    return {"data": data, "count": len(data)}


@api_router.get("/sheets/analysis")
async def get_analysis(request: Request):
    await get_current_user(request)
    data = await fetch_sheet_data(SHEET_NAMES["analysis"])
    return {"data": data, "count": len(data)}


@api_router.get("/sheets/outreach-queue")
async def get_outreach_queue(request: Request):
    await get_current_user(request)
    data = await fetch_sheet_data(SHEET_NAMES["outreach_queue"])

    overrides = {}
    cursor = db.status_overrides.find({}, {"_id": 0})
    async for doc in cursor:
        overrides[doc["row_key"]] = doc

    for row in data:
        row_key = str(row.get("_row_index", ""))
        if row_key in overrides:
            row["_local_status"] = overrides[row_key].get("status", "")
            row["_status_updated_at"] = overrides[row_key].get("updated_at", "")

    return {"data": data, "count": len(data)}


# --- Merged Leads ---
@api_router.get("/leads")
async def get_leads(request: Request):
    await get_current_user(request)

    raw_leads = await fetch_sheet_data(SHEET_NAMES["raw_leads"])
    analysis = await fetch_sheet_data(SHEET_NAMES["analysis"])

    # Build analysis lookup by business name
    analysis_map = {}
    for row in analysis:
        name = _find_col(row, ["business", "name", "company", "nombre"])
        if name:
            analysis_map[name.lower().strip()] = row

    merged = []
    for row in raw_leads:
        name = _find_col(row, ["business", "name", "company", "nombre"])
        merged_row = {k: v for k, v in row.items()}
        if name and name.lower().strip() in analysis_map:
            a_row = analysis_map[name.lower().strip()]
            for k, v in a_row.items():
                if k.startswith("_"):
                    continue
                if k not in merged_row or not merged_row[k]:
                    merged_row[k] = v
        merged.append(merged_row)

    return {"data": merged, "count": len(merged)}


# --- Status Management ---
@api_router.put("/outreach/{row_index}/status")
async def update_outreach_status(row_index: int, update: StatusUpdate, request: Request):
    await get_current_user(request)

    row_key = str(row_index)
    now = datetime.now(timezone.utc).isoformat()

    await db.status_overrides.update_one(
        {"row_key": row_key},
        {"$set": {"row_key": row_key, "status": update.status, "updated_at": now}},
        upsert=True
    )

    return {"ok": True, "row_key": row_key, "status": update.status}


# --- Dashboard Stats ---
@api_router.get("/dashboard/stats")
async def get_dashboard_stats(request: Request):
    await get_current_user(request)

    raw_leads = await fetch_sheet_data(SHEET_NAMES["raw_leads"])
    outreach = await fetch_sheet_data(SHEET_NAMES["outreach_queue"])

    overrides = {}
    cursor = db.status_overrides.find({}, {"_id": 0})
    async for doc in cursor:
        overrides[doc["row_key"]] = doc.get("status", "")

    total_leads = len(raw_leads)

    pending_count = 0
    sent_count = 0
    replied_count = 0

    for i, row in enumerate(outreach):
        local_status = overrides.get(str(i), "")
        status = (local_status or _find_status(row) or "pending").lower().strip()
        if status in ("pending", "new", ""):
            pending_count += 1
        elif status in ("sent", "contacted"):
            sent_count += 1
        elif status == "replied":
            replied_count += 1

    total_contacted = sent_count + replied_count
    response_rate = (replied_count / total_contacted * 100) if total_contacted > 0 else 0

    return {
        "total_leads": total_leads,
        "messages_pending": pending_count,
        "response_rate": round(response_rate, 1),
      2 "leads_this_week": total_leads,
        "total_outreach": len(outreach),
        "sent_count": sent_count,
        "replied_count": replied_count
    }


# --- Analytics ---
@api_router.get("/dashboard/analytics")
async def get_analytics(request: Request):
    await get_current_user(request)

    raw_leads = await fetch_sheet_data(SHEET_NAMES["raw_leads"])
    analysis = await fetch_sheet_data(SHEET_NAMES["analysis"])
    outreach = await fetch_sheet_data(SHEET_NAMES["outreach_queue"])

    overrides = {}
    cursor = db.status_overrides.find({}, {"_id": 0})
    async for doc in cursor:
        overrides[doc["row_key"]] = doc.get("status", "")

    # Industry breakdown
    industry_counts = {}
    for row in raw_leads:
        industry = _find_col(row, ["industry", "sector", "niche", "nicho", "industria"])
        if industry:
            industry_counts[industry] = industry_counts.get(industry, 0) + 1

    # Status distribution
    status_counts = {"pending": 0, "sent": 0, "replied": 0, "closed": 0}
    for i, row in enumerate(outreach):
        local_status = overrides.get(str(i), "")
        status = (local_status or _find_status(row) or "pending").lower().strip()
        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts["pending"] += 1

    # Score distribution
    score_dist = {}
    for row in analysis:
        score = _find_col(row, ["score", "overall", "rating", "puntuacion", "puntaje"])
        if score:
            try:
                s = int(float(score))
                score_dist[str(s)] = score_dist.get(str(s), 0) + 1
            except ValueError:
                pass

    return {
        "industry_breakdown": [{"name": k, "value": v} for k, v in sorted(industry_counts.items(), key=lambda x: -x[1])[:10]],
        "status_distribution": [{"name": k, "value": v} for k, v in status_counts.items()],
        "score_distribution": [{"name": k, "value": v} for k, v in sorted(score_dist.items())]
    }


# --- Follow-ups ---
@api_router.get("/followups")
async def get_followups(request: Request):
    await get_current_user(request)

    outreach = await fetch_sheet_data(SHEET_NAMES["outreach_queue"])

    overrides = {}
    cursor = db.status_overrides.find({}, {"_id": 0})
    async for doc in cursor:
        overrides[doc["row_key"]] = doc

    followups = []
    now = datetime.now(timezone.utc)

    for i, row in enumerate(outreach):
        row_key = str(i)
    2   override = overrides.get(row_key, {})
        local_status = override.get("status", "")
        status = (local_status or _find_status(row) or "pending").lower().strip()

        if status == "sent":
            updated_at = override.get("updated_at", "")
            needs_followup = True
            days_since = 0

            if updated_at:
                try:
                    dt = datetime.fromisoformat(updated_at)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    days_since = (now - dt).days
                    needs_followup = days_since >= 3
                except Exception:
                    pass

            if needs_followup:
                row["_days_since_sent"] = days_since
                row["_row_index"] = i
                followups.append(row)

    return {"data": followups, "count": len(followups)}


# --- CSV Export ---
@api_router.get("/export/leads-csv")
async def export_leads_csv(request: Request):
    await get_current_user(request)

    raw_leads = await fetch_sheet_data(SHEET_NAMES["raw_leads"])

    if not raw_leads:
        return Response(content="No data available", media_type="text/csv")

    output = io.StringIO()
    headers = [k for k in raw_leads[0].keys() if not k.startswith("_")]
    writer = csv.DictWriter(output, fieldnames=headers, extrasaction='ignore')
    writer.writeheader()
    for row in raw_leads:
        filtered = {k: v for k, v in row.items() if not k.startswith("_")}
        writer.writerow(filtered)

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=leads_export.csv"}
    )


# --- Force Refresh Cache ---
@api_router.post("/sheets/refresh")
async def refresh_sheets(request: Request):
    await get_current_user(request)
    global _cache
    _cache = {}
    return {"ok": True, "message": "Cache cleared"}


# --- Lead Discovery ---

NICHE_TAG_MAP = {
    "restaurant": [("amenity", "restaurant"), ("amenity", "fast_food")],
    "restaurants": [("amenity", "restaurant"), ("amenity", "fast_food")],
    "dentist": [("amenity", "dentist"), ("healthcare", "dentist")],
    "dentists": [("amenity", "dentist"), ("healthcare", "dentist")],
    "gym": [("leisure", "fitness_centre")],
    "gyms": [("leisure", "fitness_centre")],
    "fitness": [("leisure", "fitness_centre")],
    "salon": [("shop", "hairdresser"), ("shop", "beauty")],
    "salons": [("shop", "hairdresser"), ("shop", "beauty")],
    "hair": [("shop", "hairdresser")],
    "bar": [("amenity", "bar"), ("amenity", "pub")],
    "bars": [("amenity", "bar"), ("amenity", "pub")],
    "cafe": [("amenity", "cafe")],
    "cafes": [("amenity", "cafe")],
    "coffee": [("amenity", "cafe")],
    "doctor": [("amenity", "doctors"), ("healthcare", "doctor")],
    "doctors": [("amenity", "doctors"), ("healthcare", "doctor")],
    "clinic": [("amenity", "clinic"), ("healthcare", "clinic")],
    "hotel": [("tourism", "hotel"), ("tourism", "motel")],
    "hotels": [("tourism", "hotel"), ("tourism", "motel")],
    "spa": [("leisure", "spa"), ("shop", "beauty")],
    "mechanic": [("shop", "car_repair")],
    "auto": [("shop", "car_repair")],
    "bakery": [("shop", "bakery")],
    "pharmacy": [("amenity", "pharmacy")],
    "lawyer": [("office", "lawyer")],
    "attorney": [("office", "lawyer")],
    "plumber": [("craft", "plumber")],
    "electrician": [("craft", "electrician")],
    "pet": [("shop", "pet"), ("amenity", "veterinary")],
    "vet": [("amenity", "veterinary")],
 2   "real estate": [("office", "estate_agent")],
    "insurance": [("office", "insurance")],
    "laundry": [("shop", "laundry")],
    "florist": [("shop", "florist")],
    "clothing": [("shop", "clothes")],
    "jewelry": [("q¡½Àˆ°€‰©•Ý•±Éäˆ¥t°(€€€€‰Ñ…ÑÑ½¼ˆèl ‰Í¡½Àˆ°€‰Ñ…ÑÑ½¼ˆ¥t°)ô(()…Íå¹Œ‘•˜}Í•…É¡}‰ÕÍ¥¹•ÍÍ•Ì¡¹¥¡”°¥Ñä°ÍÑ…Ñ”°µ…á}É•ÍÕ±ÑÌôÌÀ¤è(€€€€ˆˆ‰M•…É ™½È‰ÕÍ¥¹•ÍÍ•ÌÕÍ¥¹œ=Á•¹MÑÉ••Ñ5…À=Ù•ÉÁ…ÍÌA$€¡™É•”°¹¼­•ä¹••‘•¤¸ˆˆˆ(€€€ÑÉäè(€€È€€€€€€ŒMÑ•À€Äè•½½‘”¥Ñä(€€€€€€€•½}ÕÉ°€ô˜‰¡ÑÑÁÌè¼½¹½µ¥¹…Ñ¥´¹½Á•¹ÍÑÉ••Ñµ…À¹½Éœ½Í•…É ýÄõíÅÕ½Ñ”¡˜í¥Ñåô±íÍÑ…Ñ•ô±UM…ì¥ô™™½Éµ…Ðõ©Í½¸™±¥µ¥ÐôÄˆ(€€€€€€€…Íå¹ŒÝ¥Ñ ¡ÑÑÁà¹Íå¹±¥•¹Ð¡Ñ¥µ•½ÕÐôÄÔ¤…Ì±¥•¹Ðè(€€€€€€€€€€€•½}É•Ì€= await client.get(geo_url, headers={"User-Agent": "Clawdbot/1.0"})
            geo_data = geo_res.json()
            if not geo_data:
                logger.error(f"Could not geocode {city}, {state}")
                return []
            lat = float(geo_data[0]['lat'])
            lon = float(geo_data[0]['lon'])

        # Step 2: Map niche to OSM tags
        niche_lower = niche.lower().strip()
        tags = []
        for key in NICHE_TAG_MAP:
            if key in niche_lower or niche_lower in key:
                tags = NICHE_TAG_MAP[key]
                break

        name_filter = ""
        if not tags:
            # Generic fallback: search amenity + shop by name
            tags = [("amenity", None), ("shop", None)]
            escaped = re.escape(niche)
            name_filter = f'["name"~"{escaped}",i]'

        # Step 3: Build Overpass query
        radius = 5000
        parts = []
        for osm_key, osm_val in tags:
            if osm_val:
                tag_str = f'["{osm_key}"="{osm_val}"]'
            else:
                tag_str = f'["{osm_key}"]'
            parts.append(f'node{tag_str}{name_filter}(around:{radius},{lat},{lon});')
            parts.append(f'way{tag_str}{name_filter}(around:{radius},{lat},{lon});')

        overpass_query = f"""[out:json][timeout:25];
({chr(10).join(parts)});
out center {min(max_results * 2, 60)};"""

        async with httpx.AsyncClient(timeout=30) as client:
            res = await client.post(
                "https://overpass-api.de/api/interpreter",
                data={"data": overpass_query}
            )
            if res.status_code != 200:
                logger.error(f"Overpass API error: {res.status_code}")
                return []
            data = res.json()

        # Step 4: Parse results
       results = []
        seen = set()
        for el in data.get("elements", []):
            t = el.get("tags", {})
            name = t.get("name", "")
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())

            phone = t.get("phone", t.get("contact:phone", ""))
            website = t.get("website", t.get("contact:website", ""))
            addr_parts = [t.get("addr:housenumber", ""), t.get("addr:street", "")]
            address = " ".join(p for p in addr_parts if p) or t.get("addr:full", "")
            city_tag = t.get("addr:city", city)

            results.append({
                "title": name,
 2              "phone": phone,
                "url": website,
                "address": address,
                "city_tag": city_tag,
                "rating": 0,
                "ratingCount": 0,
                "category": t.get("cuisine", t.get("shop", t.get("amenity", niche))),
            })

        return results[:max_results]
    except Exception as e:
        logger.error(f"Business search failed: {e}")
        return []


async def _quick_analyze_website(url):
    """Quick website analysis â€” checks SSL, speed, mobile, SEO basics."""
    result = {
        "has_ssl": False, "response_time": 0, "has_viewport": False,
        "has_title": False, "has_description": False, "has_h1": False,
        "content_length": 0, "score": 0, "weaknesses": []
    }
    try:
        if not url.startswith("http"):
            url = f"https://{url}"
        import time
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            start = time.time()
            response = await client.get(url)
            elapsed = time.time() - start

            result["response_time"] = round(elapsed, 2)
            result["has_ssl"] = str(response.url).startswith("https")
            html = response.text
            result["content_length"] = len(html)

            soup = BeautifulSoup(html, "html.parser")
        2    result["has_viewport"] = soup.find("meta", attrs={"name": "viewport"}) is not None
            title_tag = soup.find("title")
            result["has_title"] = title_tag is not None and len(title_tag.text.strip()) > 0
             result["has_description"] = soup.find("meta", attrs={"name": "description"}) is not None
            result["has_h1"] = soup.find("h1") is not None

            score = 2
            if result["has_ssl"]: score += 1
            if result["response_time"] < 3: score += 1
            if result["has_viewport"]: score += 1.5
            if result["has_title"]: score += 1
            if result["has_description"]: score += 1
            if result["has_h1"]: score += 0.5
            if result["content_length"] > 2000: score += 1
            if result["response_time"] < 1.5: score += 1
            result["score"] = min(round(score), 10)

            if not result["has_ssl"]:
                result["weaknesses"].append("No SSL security (no HTTPS)")
            if result["response_time"] >= 3:
                result["weaknesses"].append(f"Slow loading ({result['response_time']}s)")
            if not result["has_viewport"]:
                result["weaknesses"].append("Not mobile-friendly (no viewport)")
            if not result["has_title"]:
                result["weaknesses"].append("Missing page title")
            if not result["has_description"]:
                result["weaknesses"].append("Missing meta description (bad for SEO)")
            if not result["has_h1"]:
                result["weaknesses"].append("Missing H1 heading")
            if result["content_length"] < 2000:
                result["weaknesses"].append("Very little content on the page")
    except Exception:
        result["score"] = 1
        result["weaknesses"] = ["Website could not be reached or has errors"]
    return result


def _generate_template_message(lead):
    """Generate template outreach message based on weaknesses."""
    name = lead.get("business_name", "your business")
    city = lead.get("city", "your area")
    website = lead.get("website", "")
    weaknesses = lead.get("weaknesses", [])
    score = lead.get("website_score", 0)

    if not website:
        return (
            f"Hi! I came across {name} and noticed you don't seem to have a website yet. "
            f"In 2026, over 80% of customers search online before visiting a local business. "
            f"I build professional websites for businesses in {city}. "
            f"Would you like to see some examples?"
        )
    if score >= 8:
        return (
            f"Hi! I checked out {name}'s website and it looks solid. "
            f"I noticed a couple of small tweaks that could help drive even more traffic from Google. "
            f"Would you be interested in hearing about them?"
        )
    weakness_lines = "\n".join([f"  - {w}" for w in weaknesses[:3]])
    return (
        f"Hi! I was checking out {name}'s website and noticed a few things that could help you get more customers:\n\n"
        f"{weakness_lines}\n\n"
        f"I help businesses in {city} improve their online presence. "
        f"Would you be open to a quick chat about how to fix these?"
    )


@api_router.post("/discover")
async def discover_leads(data: DiscoverRequest, request: Request):
    user = await get_current_user(request)
    results = await _search_businesses(data.niche, data.city, data.state)

    leads = []
    for r in results:
        lead = {
            "lead_id": f"lead_{uuid.uuid4().hex[:12]}",
            "business_name": r.get("title", ""),
            "address": r.get("address", ""),
            "city": r.get("city_tag", data.city),
            "state": data.state,
            "phone": r.get("phone", ""),
            "website": r.get("url", ""),
            "email": "",
            "industry": r.get("category", data.niche),
            "rating": r.get("rating", 0),
            "rating_count": r.get("ratingCount", 0),
            "analysis_done": False,
            "website_score": 0,
            "weaknesses": [],
            "message": "",
            "status": "new",
            "discovered_by": user["user_id"],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        leads.append(lead)

    if leads:
        await db.discovered_leads.insert_many([{k: v for k, v in l.items()} for l in leads])
    return {"data": leads, "count": len(leads)}


@api_router.get("/discovered-leads")
async def get_discovered_leads(request: Request):
    user = await get_current_user(request)
    leads = await db.discovered_leads.find(
        {"discovered_by": user["user_id"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(500)
    return {"data": leads, "count": len(leads)}


@api_router.post("/discover/analyze/{lead_id}")
async def analyze_lead(lead_id: str, request: Request):
    user = await get_current_user(request)
    lead = await db.discovered_leads.find_one(
        {"lead_id": lead_id, "discovered_by": user["user_id"]}, {"_id": 0}
    )
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")

    website = lead.get("website", "")
    if not website:
        analysis = {"score": 1, "weaknesses": ["No website found"]}
    else:
        analysis = await _quick_analyze_website(website)

    lead_updated = {**lead, "website_score": analysis["score"], "weaknesses": analysis["weaknesses"]}
    message = _generate_template_message(lead_updated)

    await db.discovered_leads.update_one(
        {"lead_id": lead_id},
        {"$set": {
            "analysis_done": True,
            "website_score": analysis["score"],
            "weaknesses": analysis["weaknesses"],
            "message": message
        }}
    )
    return {"lead_id": lead_id, "score": analysis["score"], "weaknesses": analysis["weaknesses"], "message": message}


@api_router.post("/discover/analyze-all")
async def analyze_all_leads(request: Request):
    user = await get_current_user(request)
    leads = await db.discovered_leads.find(
        {"discovered_by": user["user_id"], "analysis_done": False}, {"_id": 0}
    ).to_list(500)

    analyzed = 0
    for lead in leads:
        website = lead.get("website", "")
        if not website:
            analysis = {"score": 1, "weaknesses": ["No website found"]}
        else:
            analysis = await _quick_analyze_website(website)

        lead_updated = {**lead, "website_score": analysis["score"], "weaknesses": analysis["weaknesses"]}
        message = _generate_template_message(lead_updated)

        await db.discovered_leads.update_one(
            {"lead_id": lead["lead_id"]},
            {"$set": {
                "analysis_done": True,
                "website_score": analysis["score"],
  2            "weaknesses": analysis["weaknesses"],
                "message": message
            }}
        )
        analyzed += 1
    return {"analyzed": analyzed, "total": len(leads)}


@api_router.get("/discovered-leads/export-csv")
async def export_discovered_csv(request: Request):
    user = await get_current_user(request)
    leads = await db.discovered_leads.find(
        {"discovered_by": user["user_id"]}, {"_id": 0}
    ).to_list(500)


    if not leads:
        return Response(content="No data", media_type="text/csv")

    output = io.StringIO()
    fields = ["business_name", "address", "city", "state", "phone", "website", "email",
              "industry", "rating", "website_score", "weaknesses", "message", "status"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for lead in leads:
        row = {**lead}
        row["weaknesses"] = "; ".join(row.get("weaknesses", []))
        writer.writerow(row)

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=discovered_leads.csv"}
    )


@api_router.delete("/discovered-leads/{lead_id}")
async def delete_discovered_lead(lead_id: str, request: Request):
    user = await get_current_user(request)
    result = await db.discovered_leads.delete_one(
        {"lead_id": lead_id, "discovered_by": user["user_id"]}
    )
    return {"ok": result.deleted_count > 0}


@api_router.delete("/discovered-leads")
async def clear_discovered_leads(request: Request):
    user = await get_current_user(request)
    result = await db.discovered_leads.delete_many(
        {"discovered_by": user["user_id"]}
    )
    return {"ok": True, "deleted": result.deleted_count}


# --- Instagram Integration ---

_ig_clients = {}  # user_id -> instagrapi.Client
_ig_2fa_pending = {}  # user_id -> Client (waiting for 2FA code)

DAILY_DM_LIMIT = 25


async def _get_ig_client(user_id: str):
    """Get or restore Instagram client for a user."""
    if user_id in _ig_clients:
        return _ig_clients[user_id]

    # Try to restore from saved session
    session_doc = await db.ig_sessions.find_one({"user_id": user_id}, {"_id": 0})
    if session_doc and session_doc.get("session_json"):
        from instagrapi import Client
        cl = Client()
        try:
            cl.set_settings(json.loads(session_doc["session_json"]))
            cl.get_timeline_feed()  # Test if session is valid
            _ig_clients[user_id] = cl
            return cl
        except Exception:
            pass
    return None


@api_router.get("/instagram/status")
async def ig_status(request: Request):
    user = await get_current_user(request)
    cl = await _get_ig_client(user["user_id"])
    if cl:
        try:
            ig_user = await asyncio.to_thread(lambda: cl.account_info())
            return {
                "connected": True,
                "username": ig_user.username,
                "full_name": ig_user.full_name,
                "profile_pic": str(ig_user.profile_pic_url) if ig_user.profile_pic_url else ""
            }
        except Exception:
            _ig_clients.pop(user["user_id"], None)
    return {"connected": False}


@api_router.post("/instagram/login")
async def ig_login(data: IGLoginRequest, request: Request):
    user = await get_current_user(request)
    from instagrapi import Client
    from instagrapi.exceptions import (
        TwoFactorRequired, ChallengeRequired, BadPassword, 
        PleaseWaitFewMinutes, LoginRequired, RecaptchaChallengeForm,
        SelectContactPointRecoveryForm, ReloginAttemptExceeded
    )

    cl = Client()
    cl.delay_range = [2, 5]
    # Set user agent to look more like a real device
    cl.set_locale("en_US")
    cl.set_timezone_offset(-5 * 3600)  # EST

    def _do_login():
        try:
            cl.login(data.username, data.password)
            return {"status": "logged_in"}
        except TwoFactorRequired:
            return {"status": "2fa_required", "message": "Enter the 2FA code from your authenticator app or SMS"}
        except ChallengeRequired as e:
            try:
                # Try to get challenge info
                cl.challenge_resolve(cl.last_json)
                return {"status": "challenge_sent", "message": "Instagram sent a verification code to your phone/email. Enter it below."}
            except SelectContactPointRecoveryForm:
                return {"status": "challenge_select", "message": "Instagram requires verification. Open Instagram app, complete the verification, then try again."}
            except RecaptchaChallengeForm:
                return {"status": "captcha_required", "message": "Instagram requires captcha. Open Instagram app, login there first, then try again here."}
            except Exception as ce:
                logger.warning(f"Challenge resolve failed: {ce}")
                return {"status": "challenge_required", "message": "Instagram needs verification. Open the Instagram app on your phone, approve any security prompts, then try logging in again."}
        except BadPassword:
            return {"status": "error", "message": "Incorrect password. Please check and try again."}
        except PleaseWaitFewMinutes:
            return {"status": "rate_limited", "message": "Too many attempts. Please wait a few minutes and try again."}
        except ReloginAttemptExceeded:
            return {"status": "error", "message": "Too many login attempts. Wait 24 hours or login via Instagram app first."}
        except LoginRequired:
            return {"status": "error", "message": "Login required - session expired. Please try again."}
        except Exception as e:
            error_msg = str(e).lower()
            if "password" in error_msg:
                return {"status": "error", "message": "Incorrect password. Please check and try again."}
            elif "challenge" in error_msg:
                return {"status": "challenge_required", "message": "Instagram needs verification. Open the Instagram app, complete any security check, then try again."}
            elif "wait" in error_msg or "limit" in error_msg:
                return {"status": "rate_limited", "message": "Rate limited by Instagram. Wait a few minutes and try again."}
            logger.error(f"Instagram login error: {e}")
            return {"status": "error", "message": f"Login failed: {str(e)[:100]}"}

    result = await asyncio.to_thread(_do_login)

    if result["status"] == "logged_in":
        _ig_clients[user["user_id"]] = cl
        session_json = json.dumps(cl.get_settings())
        await db.ig_sessions.update_one(
            {"user_id": user["user_id"]},
            {"$set": {
      2         "user_id": user["user_id"],
                "username": data.username,
                "session_json": session_json,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }},
            upsert=True
        )
        return {**result, "username": data.username}
    elif result["status"] == "2fa_required" or result["status"] == "challenge_sent":
        _ig_2fa_pending[user["user_id"]] = {"client": cl, "username": data.username, "password": data.password}
        return result
    else:
        return result


@api_router.post("/instagram/verify-2fa")
async def ig_verify_2fa(data: IGVerify2FARequest, request: Request):
    user = await get_current_user(request)
    pending = _ig_2fa_pending.get(user["user_id"])
    if not pending:
        raise HTTPException(status_code=400, detail="No pending 2FA login")

    cl = pending["client"]

    def _verify():
        try:
            cl.login(pending["username"], pending["password"], verification_code=data.code)
            return {"status": "logged_in"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    result = await asyncio.to_thread(_verify)

    if result["status"] == "logged_in":
        _ig_clients[user["user_id"]] = cl
        _ig_2fa_pending.pop(user["user_id"], None)
        session_json = json.dumps(cl.get_settings())
        await db.ig_sessions.update_one(
            {"user_id": user["user_id"]},
            {"$set": {
                "user_id": user["user_id"],
                "username": pending["username"],
    2           "session_json": session_json,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }},
            upsert=True
        )
        return {**result, "username": pending["username"]}
    return result


@api_router.post("/instagram/logout")
async def ig_logout(request: Request):
    user = await get_current_user(request)
    cl = _ig_clients.pop(user["user_id"], None)
    if cl:
        try:
            await asyncio.to_thread(cl.logout)
        except Exception:
            pass
    await db.ig_sessions.delete_one({"user_id": user["user_id"]})
    return {"ok": True}


@api_router.post("/instagram/search-user")
async def ig_search_user(data: IGSearchUserRequest, request: Request):
    user = await get_current_user(request)
    cl = await _get_ig_client(user["user_id"])
    if not cl:
        raise HTTPException(status_code=400, detail="Not connected to Instagram")

    def _search():
        results = cl.search_users(data.query)
        return [{
            "pk": str(u.pk),
            "username": u.username,
            "full_name": u.full_name,
            "profile_pic": str(u.profile_pic_url) if u.profile_pic_url else "",
            "is_verified": u.is_verified,
        } for u in results[:8]]

    results = await asyncio.to_thread(_search)
    return {"results": results}


@api_router.get("/instagram/profile/{username}")
async def ig_get_profile(username: str, request: Request):
    user = await get_current_user(request)
    cl = await _get_ig_client(user["user_id"])
    if not cl:
        raise HTTPException(status_code=400, detail="Not connected to Instagram")

    def _get_profile():
        try:
            u = cl.user_info_by_username(username)
            return {
                "pk": str(u.pk),
                "username": u.username,
                "full_name": u.full_name,
                "biography": u.biography,
                "follower_count": u.follower_count,
                "following_count": u.following_count,
                "media_count": u.media_count,
                "external_url": u.external_url or "",
                "public_email": u.public_email or "",
                "contact_phone": u.contact_phone_number or "",
                "category": u.category or "",
                "is_business": u.is_business,
                "is_verified": u.is_verified,
                "profile_pic": str(u.profile_pic_url_hd) if u.profile_pic_url_hd else "",
            }
        except Exception as e:
            return {"error": str(e)}

    return await asyncio.to_thread(_get_profile)


@api_router.post("/instagram/send-dm")
async def ig_send_dm(data: IGSendDMRequest, request: Request):
    user = await get_current_user(request)
    cl = await _get_ig_client(user["user_id"])
    if not cl:
        raise HTTPException(status_code=400, detail="Not connected to Instagram")

    # Check daily limit
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    today_count = await db.dm_log.count_documents({
        "sender_user_id": user["user_id"],
        "sent_at": {"$gte": today_start}
    })
    if today_count >= DAILY_DM_LIMIT:
        raise HTTPException(status_code=429, detail=f"Daily DM limit reached ({DAILY_DM_LIMIT}). Try again tomorrow.")

    def _send():
        try:
            user_id_ig = cl.user_id_from_username(data.target_username)
            cl.direct_send(data.message, [user_id_ig])

            # Extract profile data
            try:
                u = cl.user_info(user_id_ig)
                profile = {
         2          "full_name": u.full_name,
                    "biography": u.biography,
                    "follower_count": u.follower_count,
                    "following_count": u.following_count,
                    "media_count": u.media_count,
                    "external_url": u.external_url or "",
                    "public_email": u.public_email or "",
                    "contact_phone": u.contact_phone_number or "",
                    "category": u.category or "",
                    "is_business": u.is_business,
                    "profile_pic": str(u.profile_pic_url_hd) if u.profile_pic_url_hd else "",
                }
            except Exception:
   2            profile = {}

            return {"status": "sent", "profile": profile}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    result = await asyncio.to_thread(_send)

    if result["status"] == "sent":
        # Log the DM
        await db.dm_log.insert_one({
            "sender_user_id": user["user_id"],
            "target_username": data.target_username,
            "message": data.message,
            "lead_id": data.lead_id,
            "profile_data": result.get("profile", {}),
            "sent_at": datetime.now(timezone.utc).isoformat()
        })

        # Update lead if lead_id provided
        if data.lead_id:
            update_fields = {"status": "sent", "ig_handle": data.target_username}
            if result.get("profile"):
                update_fields["ig_profile"] = result["profile"]
            await db.discovered_leads.update_one(
                {"lead_id": data.lead_id},
                {"$set": update_fields}
            )

    return result


@api_router.get("/instagram/dm-count-today")
async def ig_dm_count_today(request: Request):
    user = await get_current_user(request)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    count = await db.dm_log.count_documents({
        "sender_user_id": user["user_id"],
        "sent_at": {"$gte": today_start}
    })
    return {"count": count, "limit": DAILY_DM_LIMIT}


@api_router.get("/instagram/dm-log")
async def ig_dm_log(request: Request):
    user = await get_current_user(request)
    logs = await db.dm_log.find(
        {"sender_user_id": user["user_id"]}, {"_id": 0}
    ).sort("sent_at", -1).to_list(100)
    return {"data": logs, "count": len(logs)}


@api_router.post("/instagram/set-default-template")
async def ig_set_default_template(data: IGMessageTemplateRequest, request: Request):
    user = await get_current_user(request)
    await db.ig_settings.update_one(
        {"user_id": user["user_id"]},
     2   {"$set": {"user_id": user["user_id"], "default_template": data.template}},
        upsert=True
    )
    return {"ok": True}


@api_router.get("/instagram/default-template")
async def ig_get_default_template(request: Request"t):
    user = await get_current_user(request)
    doc = await db.ig_settings.find_one({"user_id": user["user_id"]}, {"_id": 0})
    return {"template": doc.get("default_template", "") if doc else ""}


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


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
