from fastapi import FastAPI, HTTPException
from schemas import ScanRequest, ScanResponse
from scanners.hibp import check_email_breach

app = FastAPI(title="DataDrain /osint-free-scan v0.1")

@app.post("/osint-free-scan", response_model=ScanResponse)
def osint_free_scan(req: ScanRequest):
    exposure = check_email_breach(req.email)
    return ScanResponse(exposures=[exposure])