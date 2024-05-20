from __future__ import annotations

from pydantic import BaseModel


class ResponseData(BaseModel):
    status: int
    message: str
    data: str


class RequestData(BaseModel):
    key: str
    data: str
