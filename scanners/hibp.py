import os, httpx
from schemas import Exposure

API_KEY = os.getenv("HIBP_API_KEY")
HEADERS = {
    "hibp-api-key": API_KEY,
    "user-agent": "DataDrain/0.1"
}
URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

def check_email_breach(email: str) -> Exposure:
    try:
        r = httpx.get(URL + email, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            status = "found"
        elif r.status_code == 404:
            status = "not_found"
        else:
            status = "error"
        return Exposure(site="HaveIBeenPwned", status=status,
                        url=None, matched_on=["email"] if status=="found" else [])
    except Exception:
        return Exposure(site="HaveIBeenPwned", status="error")