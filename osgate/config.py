"""Environment-owned settings. Database-owned settings are managed separately."""
from pathlib import Path
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_name: str = 'OSGate'
    app_env: str = 'production'
    web_host: str = '127.0.0.1'
    web_port: int = Field(default=5812, ge=1, le=65535)
    web_secure_cookies: bool = False  # set true behind TLS reverse proxy
    web_allowed_cidrs: str = '127.0.0.1/32,::1/128'
    session_secret: str = ''
    socks_host: str = '127.0.0.1'
    socks_port: int = Field(default=1080, ge=1, le=65535)
    socks_max_connections: int = Field(default=1000, ge=1, le=200000)
    socks_connect_timeout: float = Field(default=15.0, gt=0, le=300)
    socks_idle_timeout: float = Field(default=600.0, gt=0)
    ssh_connect_timeout: float = Field(default=10, gt=0)
    ssh_keepalive_interval: float = Field(default=15, gt=0)
    ssh_keepalive_count_max: int = Field(default=3, ge=1)
    ssh_reconnect_initial_delay: float = Field(default=2, gt=0)
    ssh_reconnect_max_delay: float = Field(default=60, gt=0)
    health_check_interval: float = Field(default=15, gt=0)
    health_check_timeout: float = Field(default=5, gt=0)
    health_failure_threshold: int = Field(default=3, ge=1)
    health_success_threshold: int = Field(default=2, ge=1)
    health_dns_enabled: bool = False
    health_dns_test_host: str = 'example.com'
    traffic_retention_days: int = Field(default=7, ge=1, le=365)
    health_test_host: str = '1.1.1.1'
    health_test_port: int = Field(default=443, ge=1, le=65535)
    database_url: str = 'sqlite:////data/osgate.db'
    ssh_directory: Path = Path('/ssh')
    ssh_hostkeys_directory: Path = Path('/data/ssh-hostkeys')
    telegram_enabled: bool = False
    telegram_bot_token: str = ''
    telegram_chat_id: str = ''
    log_level: str = 'INFO'
    tz: str = 'Europe/Moscow'

    @field_validator('database_url')
    @classmethod
    def sqlite_only(cls, value: str) -> str:
        if not value.startswith('sqlite:///'):
            raise ValueError('Only synchronous sqlite:/// URLs are supported')
        return value

    def validate_runtime(self) -> None:
        if len(self.session_secret) < 32:
            raise ValueError('SESSION_SECRET must contain at least 32 characters')
        if self.web_host in ('0.0.0.0', '::') and self.web_allowed_cidrs.strip() == '':
            raise ValueError('WEB_ALLOWED_CIDRS is mandatory for externally bound admin interface')
