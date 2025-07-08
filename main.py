from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="DataDrain /osint-free-scan v0.1")

HIBP_API_KEY = os.getenv("HIBP_API_KEY")
USER_AGENT = os.getenv("USER_AGENT")

class ScanRequest(BaseModel):
    email: EmailStr

@app.post("/free-scan")
async def free_scan(data: ScanRequest):
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": USER_AGENT
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{data.email}?truncateResponse=false"

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

        if response.status_code == 404:
            return {"email": data.email, "breaches": []}  # Not breached
        elif response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        return {
            "email": data.email,
            "breaches": response.json()
        }


