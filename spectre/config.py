from pathlib import Path

import yaml
from pydantic import BaseModel


class Config(BaseModel):
    scan_threads: int = 50
    scan_timeout: int = 30
    scan_retries: int = 3
    scan_proxy: str = ""
    scan_rate_limit: int = 0  # requests per second, 0 = unlimited
    ai_enabled: bool = False
    ai_provider: str = "openai"
    ai_model: str = "gpt-4"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    output_dir: str = "./reports"
    user_agent: str = "Spectre/0.1.0"


class ConfigManager:
    """Manage Spectre configuration."""

    def __init__(self):
        self.config_dir = Path.home() / ".spectre"
        self.config_file = self.config_dir / "config.yaml"
        self.config_dir.mkdir(exist_ok=True)
        self._load()

    def _load(self):
        if self.config_file.exists():
            data = yaml.safe_load(self.config_file.read_text())
            self.config = Config(**data) if data else Config()
        else:
            self.config = Config()

    def _save(self):
        self.config_file.write_text(yaml.dump(self.config.model_dump(), default_flow_style=False))

    def get(self, key: str) -> str:
        return str(getattr(self.config, key, ""))

    def set(self, key: str, value: str):
        if hasattr(self.config, key):
            current_type = type(getattr(self.config, key))
            if current_type == bool:
                setattr(self.config, key, value.lower() in ("true", "1", "yes"))
            elif current_type == int:
                setattr(self.config, key, int(value))
            else:
                setattr(self.config, key, value)
            self._save()
