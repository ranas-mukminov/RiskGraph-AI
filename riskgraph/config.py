"""
Application configuration and scoring defaults.
"""
from functools import lru_cache
from typing import Dict

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScoringConfig(BaseModel):
    criticality_base: Dict[str, float] = Field(
        default_factory=lambda: {
            "low": 1.0,
            "medium": 3.0,
            "high": 6.0,
            "crown_jewel": 10.0,
        }
    )
    control_reduction: Dict[str, float] = Field(
        default_factory=lambda: {
            "edr": 2.0,
            "segmentation": 1.5,
            "fw": 1.0,
            "logging": 0.5,
        }
    )
    relation_costs: Dict[str, float] = Field(
        default_factory=lambda: {
            "can_reach": 3.0,
            "has_credential": 2.0,
            "has_privilege": 2.5,
            "has_admin": 1.0,
            "exploits": 2.0,
            "protected_by": -1.0,
            "depends_on": 1.0,
        }
    )
    path_node_factor: float = 0.2
    exploit_available_bonus: float = 1.0
    max_control_reduction: float = 5.0


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RISKGRAPH_", env_nested_delimiter="__")
    database_url: str = "sqlite:///./riskgraph.db"
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    llm_endpoint: str | None = None
    llm_api_key: str | None = None
    offline_mode: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
