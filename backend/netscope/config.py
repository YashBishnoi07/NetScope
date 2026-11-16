from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="NETSCOPE_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: str = "http://localhost:5173,http://localhost:5174,http://localhost:5175,http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:5175"
    default_interface: str = ""
    packet_buffer_size: int = 20000
    queue_size: int = 50000
    broadcast_interval_ms: int = 250
    stats_window_seconds: int = 300
    database_url: str = "sqlite+aiosqlite:///./netscope.db"
    geoip_db_path: str = ""
    enable_reverse_dns: bool = True
    log_level: str = "INFO"
    detector_port_scan_threshold: int = 3
    detector_syn_flood_threshold: int = 20
    detector_arp_spoof_threshold: int = 2
    detector_icmp_flood_threshold: int = 15
    detector_dns_tunnel_threshold: float = 0.7
    alert_severity_filter: str = "all"
    alert_retention_hours: int = 24
    capture_queue_limit: int = 500


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
