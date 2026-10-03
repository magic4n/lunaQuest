"""Pydantic v2 request/response schemas.

Kept intentionally thin — survey/question payloads are free-form JSON blobs
validated by dedicated rules (question types, logic ops) rather than dozens of
nested models, which keeps both code and per-request memory small.
"""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

# The 25 supported question types (spec list).
QUESTION_TYPES = [
    "short_text", "long_text", "choice_single", "choice_multi", "dropdown",
    "linear_scale", "rating", "date", "time", "datetime", "file",
    "grid_single", "grid_multi", "ranking", "yes_no", "number",
    "email", "url", "phone", "section", "page_break", "image", "video",
    "slider", "matrix",
]
QuestionType = Literal[tuple(QUESTION_TYPES)]  # type: ignore[valid-type]

LOGIC_ACTIONS = ("skip_to", "show", "hide")
LOGIC_OPS = ("eq", "neq", "contains", "gt", "lt", "any_of", "answered", "unanswered")


def _slugify(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:64]


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(default="", max_length=80)

    @field_validator("password")
    @classmethod
    def _policy(cls, v: str) -> str:
        if not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
            raise ValueError("Password needs at least one letter and one digit.")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=128)


class ForgotIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str = Field(min_length=16, max_length=128)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def _policy(cls, v: str) -> str:
        if not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
            raise ValueError("Password needs at least one letter and one digit.")
        return v


class ProfileIn(BaseModel):
    name: str = Field(default="", max_length=80)
    avatar_url: str = Field(default="", max_length=512)


class QuestionIn(BaseModel):
    id: int | None = None                     # present => update existing row
    type: QuestionType
    title: str = Field(default="", max_length=500)
    description: str = Field(default="", max_length=2000)
    required: bool = False
    config: dict[str, Any] = Field(default_factory=dict)   # choices/rows/scale/validation...
    logic: list[dict[str, Any]] = Field(default_factory=list)
    points: float = Field(default=0, ge=0, le=1000)
    correct: Any = None                        # quiz answer payload

    @field_validator("logic")
    @classmethod
    def _logic(cls, v: list[dict]) -> list[dict]:
        for rule in v:
            if rule.get("action") not in LOGIC_ACTIONS:
                raise ValueError(f"Unknown logic action: {rule.get('action')}")
            if rule.get("op", "eq") not in LOGIC_OPS:
                raise ValueError(f"Unknown logic operator: {rule.get('op')}")
        return v


class SurveyIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    slug: str = Field(default="", max_length=64)
    cover_image: str = Field(default="", max_length=512)
    logo: str = Field(default="", max_length=512)
    settings: dict[str, Any] = Field(default_factory=dict)
    theme: dict[str, Any] = Field(default_factory=dict)
    quiz_mode: bool = False
    questions: list[QuestionIn] = Field(default_factory=list, max_length=500)

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str) -> str:
        return _slugify(v)


class ShareIn(BaseModel):
    email: EmailStr
    perm: Literal["view", "edit", "results"] = "view"


class AnswerPayload(BaseModel):
    """One answer inside a submit/draft payload."""
    question_id: int
    value: Any = None                          # shape depends on question type


class SubmitIn(BaseModel):
    started_at: str | None = None              # ISO string from client clock
    answers: list[AnswerPayload] = Field(max_length=500)
    submit: bool = True                        # False => save-as-draft
    page_password: str | None = None           # for password-protected surveys


class ApiKeyIn(BaseModel):
    label: str = Field(default="", max_length=80)


class AdminSettingsIn(BaseModel):
    site_name: str = Field(default="lunaQuest", max_length=80)
    registration_open: bool = True
    require_email_verification: bool = False
    smtp_host: str = Field(default="", max_length=200)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = Field(default="", max_length=200)
    smtp_pass: str = Field(default="", max_length=200)
    smtp_from: str = Field(default="", max_length=200)
    session_hours: int = Field(default=72, ge=1, le=8760)
    max_upload_mb: int = Field(default=10, ge=1, le=100)
