import os, html, httpx
from typing import List
from bs4 import BeautifulSoup
from schemas import Exposure

API_KEY = os.getenv("HIBP_API_KEY")
USER_AGENT = os.getenv("USER_AGENT", "DataDrain/0.1")
URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

def _strip_html(raw: str | None) -> str:
    """Unescape entities then remove all HTML tags."""
    if not raw:
        return ""
    return BeautifulSoup(html.unescape(raw), "html.parser").get_text(" ", strip=True)

async def check_email_breach(email: str) -> List[Exposure]:
    """Return a list of Exposure objects for the given e-mail."""
    headers = {"hibp-api-key": API_KEY, "User-Agent": USER_AGENT}

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{URL}{email}?truncateResponse=false", headers=headers)

    exposures: List[Exposure] = []

    if resp.status_code == 404:
        exposures.append(Exposure(site="HaveIBeenPwned",
                                  status="not_found",
                                  matched_on=["email"]))
        return exposures

    if resp.status_code != 200:
        exposures.append(Exposure(site="HaveIBeenPwned",
                                  status="error",
                                  matched_on=["email"],
                                  extra={"detail": resp.text}))
        return exposures

    for b in resp.json():
        exposures.append(
            Exposure(
                site=b.get("Name") or b.get("Domain") or "Unknown",
                status="found",
                url=f"https://haveibeenpwned.com/Account/{email}",
                matched_on=["email"],
                extra={
                    "breach_date": b.get("BreachDate"),
                    "description": _strip_html(b.get("Description"))
                },
            )
        )
    return exposures