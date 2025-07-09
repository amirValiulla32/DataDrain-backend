import os, httpx, re, html
from typing import List
from schemas import Exposure
import html, re
from bs4 import BeautifulSoup


API_KEY = os.getenv("HIBP_API_KEY")
HEADERS = {
    "hibp-api-key": API_KEY,
    "user-agent": "DataDrain/0.1"
}
URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"


def _strip_html(raw: str | None) -> str:
    """Robustly remove all HTML while unescaping entities."""
    if not raw:
        return ""
    # BeautifulSoup automatically unescapes &lt; &gt; &quot;
    return BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)

def check_email_breach(email: str) -> List[Exposure]:
    """
    Returns one Exposure per breach *or* a single 'not_found' record.
    """
    try:
        r = httpx.get(URL + email, headers=HEADERS, timeout=10)
        if r.status_code == 404:            # no breaches
            return [Exposure(site="HaveIBeenPwned",
                             status="not_found",
                             matched_on=["email"])]
        if r.status_code != 200:
            raise RuntimeError(f"HIBP error {r.status_code}")

        breaches = r.json()                 # list[dict]
        exposures: list[Exposure] = []
        for b in breaches:
            exposures.append(
                Exposure(
                    site=b.get("Name") or b.get("Domain") or "Unknown",
                    status="found",
                    url=f"https://haveibeenpwned.com/Account/{email}",
                    matched_on=["email"],
                    # optional extra field you can show in a tooltip
                    extra={"breach_date": b.get("BreachDate"),
                           "description": _strip_html(b.get("Description", ""))}
                )
            )
        return exposures or [Exposure(site="HaveIBeenPwned", status="error")]

    except Exception as exc:
        # log the exception here if you’re using structlog
        return [Exposure(site="HaveIBeenPwned", status="error")]