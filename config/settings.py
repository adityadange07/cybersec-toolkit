import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class ToolkitConfig:
    """Global configuration for the cybersecurity toolkit."""

    # Directories
    BASE_DIR: Path = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    OUTPUT_DIR: Path = BASE_DIR / "output"
    WORDLIST_DIR: Path = BASE_DIR / "wordlists"
    LOG_DIR: Path = BASE_DIR / "logs"

    # Network Settings
    DEFAULT_TIMEOUT: int = 10
    MAX_THREADS: int = 50
    MAX_RETRIES: int = 3
    USER_AGENT: str = "CyberSecToolkit/1.0 (Ethical Security Scanner)"

    # API Keys (set via environment variables)
    SHODAN_API_KEY: Optional[str] = os.getenv("SHODAN_API_KEY")
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    HUNTER_API_KEY: Optional[str] = os.getenv("HUNTER_API_KEY")

    # Scanner Settings
    SCAN_DELAY: float = 0.5  # Delay between requests (rate limiting)
    MAX_SCAN_DEPTH: int = 3

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Legal Disclaimer
    DISCLAIMER: str = """
    ⚠️  LEGAL DISCLAIMER ⚠️
    This tool is designed for ETHICAL and AUTHORIZED security testing only.
    - Only use on systems you own or have explicit written permission to test.
    - Unauthorized access to computer systems is illegal.
    - The developers assume no liability for misuse of this tool.
    - Always follow responsible disclosure practices.
    """

    # Scope enforcement
    SCOPE_ENFORCEMENT: bool = True
    AUTHORIZED_TARGETS: list = field(default_factory=list)

    def __post_init__(self):
        """Create necessary directories."""
        self.OUTPUT_DIR.mkdir(exist_ok=True)
        self.LOG_DIR.mkdir(exist_ok=True)


config = ToolkitConfig()