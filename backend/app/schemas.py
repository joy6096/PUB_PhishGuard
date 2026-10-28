from typing import Literal
from pydantic import BaseModel, Field, field_validator

class UrlScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

    @field_validator("url")
    @classmethod
    def url_must_have_scheme(cls, value: str) -> str:
        value = value.strip()
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return value

class MessageScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=12000)
    language_hint: Literal["bn", "en", "auto"] = "auto"
    
class EmailScanRequest(BaseModel):
    email_text: str = Field(min_length=1, max_length=30000)

    @field_validator("email_text")
    @classmethod
    def email_text_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Email text cannot be blank")
        return value


class Indicator(BaseModel):
    code: str
    category: str
    severity: Literal["info", "low", "medium", "high"]
    weight: int
    evidence: str
    explanation: str
    source: Literal["rule", "ml"] = "rule"

class ScanResult(BaseModel):
    input_type: Literal["url", "email", "message"]
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high"]
    verdict: str
    indicators: list[Indicator]
    recommended_actions: list[str]
    disclaimer: str
