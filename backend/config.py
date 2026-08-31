"""Central configuration. All secrets and environment-specific values load here."""

import os
from dotenv import load_dotenv

load_dotenv()


def _required(key: str) -> str:
    """Fetch a required env var, or refuse to start if it's missing."""
    value = os.getenv(key)
    if not value:
        raise RuntimeError(
            f"Required environment variable {key!r} is not set. "
            f"Copy .env.example to .env and fill it in."
        )
    return value


SECRET_KEY = _required("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./compliance.db")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

EVIDENCE_FRESHNESS_DAYS = int(os.getenv("EVIDENCE_FRESHNESS_DAYS", "90"))


AI_PROVIDER = os.getenv("AI_PROVIDER", "nvidia")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
AI_BASE_URL = os.getenv("AI_BASE_URL", "https://integrate.api.nvidia.com/v1")
AI_MODEL = os.getenv("AI_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")