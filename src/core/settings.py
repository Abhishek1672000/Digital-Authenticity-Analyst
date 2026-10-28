"""
Application settings loaded from environment variables / .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")

    # AI detection
    hive_api_key: str = Field(default="", alias="HIVE_API_KEY")
    sightengine_user: str = Field(default="", alias="SIGHTENGINE_USER")
    sightengine_secret: str = Field(default="", alias="SIGHTENGINE_SECRET")

    # OSINT
    serpapi_key: str = Field(default="", alias="SERPAPI_KEY")
    google_vision_api_key: str = Field(default="", alias="GOOGLE_VISION_API_KEY")
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")

    # App
    max_file_size_mb: int = Field(default=50, alias="MAX_FILE_SIZE_MB")
    upload_dir: str = Field(default="/tmp/daa_uploads", alias="UPLOAD_DIR")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")


settings = Settings()
