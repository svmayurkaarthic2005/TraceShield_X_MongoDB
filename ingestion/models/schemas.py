"""
schemas.py — Pydantic models for the ingestion API.
"""

from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field
from datetime import datetime


class IngestPayload(BaseModel):
    ip: str = Field(..., description="Source IP address")
    device: str = Field(..., description="Device or protocol identifier")
    request_count: int = Field(..., ge=0, description="Number of requests observed")
    timestamp: Optional[datetime] = Field(default=None)
    scenario: Optional[str] = Field(
        default=None,
        description="Dataset-derived scenario/source label (e.g. 'Brute Force'), "
                    "distinct from the live detector's attack_type classification.",
    )


class ResponseDetail(BaseModel):
    actions_taken:          List[str]
    blocked:                bool
    redirected_to_honeypot: bool
    flag_count:             int
    reason:                 str


class IngestResponse(BaseModel):
    status:       str
    risk_score:   float
    message:      str
    ip:           str
    device:       str
    request_count: int
    timestamp:    datetime
    graph_stored: bool
    components:   Dict[str, Any]
    response:     ResponseDetail
    attack_type:  str = "NORMAL_ACTIVITY"
    scenario:     Optional[str] = None
