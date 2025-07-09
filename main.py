from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
import httpx
import os
from dotenv import load_dotenv
from typing import List, Literal
from bs4 import BeautifulSoup

load_dotenv()

def _strip_html(raw: str | None) -> str:
    """Remove all HTML tags and unescape entities."""
    if not raw:
        return ""
    return BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)

class Exposure(BaseModel):
    site: str
    status: Literal["found", "not_found", "error"]
    url: str | None = None
    matched_on: List[str] = []
    extra: dict | None = None

class ScanResponse(BaseModel):
    exposures: List[Exposure]

app = FastAPI(title="DataDrain /osint-free-scan v0.1")

HIBP_API_KEY = os.getenv("HIBP_API_KEY")
USER_AGENT = os.getenv("USER_AGENT")

class ScanRequest(BaseModel):
    email: EmailStr

@app.post("/free-scan", response_model=ScanResponse)
async def free_scan(data: ScanRequest):
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": USER_AGENT
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{data.email}?truncateResponse=false"

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

    # Build the exposures list
    exposures: List[Exposure] = []

    if response.status_code == 404:
        exposures.append(
            Exposure(
                site="HaveIBeenPwned",
                status="not_found",
                matched_on=["email"]
            )
        )
    elif response.status_code == 200:
        for breach in response.json():  # list of breach dicts
            exposures.append(
                Exposure(
                    site=breach.get("Name") or breach.get("Domain") or "Unknown",
                    status="found",
                    url=f"https://haveibeenpwned.com/Account/{data.email}",
                    matched_on=["email"],
                    extra={
                        "breach_date": breach.get("BreachDate"),
                        "description": _strip_html(breach.get("Description"))
                    }
                )
            )
    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    return ScanResponse(exposures=exposures)
