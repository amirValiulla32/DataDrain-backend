from fastapi import FastAPI
from pydantic import BaseModel, EmailStr
from typing import List

from schemas import ScanResponse, Exposure
from scanners.hibp import check_email_breach     # <- only one import!

app = FastAPI(title="DataDrain /osint-free-scan v0.1")

class ScanRequest(BaseModel):
    email: EmailStr

@app.post("/free-scan", response_model=ScanResponse)
async def free_scan(data: ScanRequest):
    exposures: List[Exposure] = await check_email_breach(data.email)
    return ScanResponse(exposures=exposures)