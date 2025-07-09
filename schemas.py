from pydantic import BaseModel
from typing import List, Literal

class Exposure(BaseModel):
    site: str
    status: Literal["found", "not_found", "error"]
    url: str | None = None
    matched_on: List[str] = []
    extra: dict | None = None

class ScanResponse(BaseModel):
    exposures: List[Exposure]