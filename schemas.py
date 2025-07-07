from pydantic import BaseModel, EmailStr, Field
from typing import List, Literal

class ScanRequest(BaseModel):
    name: str
    email: EmailStr
    partial_phone: str | None = Field(None, max_length=6)
    address: str | None = None

class Exposure(BaseModel):
    site: str
    status: Literal["found", "not_found", "error"]
    url: str | None = None
    matched_on: List[str] = []

class ScanResponse(BaseModel):
    exposures: List[Exposure]