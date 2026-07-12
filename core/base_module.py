import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from datetime import datetime
from core.logger import setup_logger
from config.settings import config


class BaseModule(ABC):
    """Base class for all toolkit modules."""

    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logger(name)
        self.results: Dict[str, Any] = {}
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    def check_authorization(self, target: str) -> bool:
        """Verify target is within authorized scope."""
        if not config.SCOPE_ENFORCEMENT:
            return True

        if config.AUTHORIZED_TARGETS and target not in config.AUTHORIZED_TARGETS:
            self.logger.warning(f"⚠️  Target {target} is NOT in authorized scope!")
            confirm = input(f"Do you have authorization to test {target}? (yes/no): ")
            if confirm.lower() != 'yes':
                self.logger.error("Operation cancelled - No authorization confirmed.")
                return False
        return True

    def pre_run(self, target: str):
        """Pre-execution checks."""
        self.start_time = time.time()
        self.logger.info(f"🚀 Starting {self.name} against {target}")
        self.logger.info(f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def post_run(self):
        """Post-execution summary."""
        self.end_time = time.time()
        elapsed = self.end_time - self.start_time
        self.logger.info(f"✅ {self.name} completed in {elapsed:.2f} seconds")

    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Main execution wrapper with safety checks."""
        if not self.check_authorization(target):
            return {"error": "Not authorized"}

        self.pre_run(target)
        try:
            self.results = self.run(target, **kwargs)
        except Exception as e:
            self.logger.error(f"❌ Error in {self.name}: {str(e)}")
            self.results = {"error": str(e)}
        finally:
            self.post_run()

        return self.results

    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Override this method in each module."""
        pass