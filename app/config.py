from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # MongoDB
    mongodb_url: str = "mongodb://localhost:27017/"
    database_name: str = "icann_tlds_db"
    
    # Default days back
    default_days_back: int = 1
    
    # Search settings
    max_variations: int = 10000
    batch_size: int = 1000
    
    # Logging
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
