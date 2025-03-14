from dataclasses import dataclass
from typing import Optional
from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@dataclass
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    FAIL = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

@dataclass
class ScanConfig:
    target: str
    scan_type: str
    output: bool
    custom_subscan_file: Optional[Path] = None
    
    @property
    def output_dir(self) -> Optional[Path]:
        if self.output:
            return Path('output') / self.target
        return None

class APIConfig:
    BASE_URL = 'https://prettyrecon.com'
    JOBS_URL = f'{BASE_URL}/tasks/'
    LOGIN_URL = f'{BASE_URL}/login/'
    
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": BASE_URL
    }
    
    REQUEST_TIMEOUT = 30  # seconds
    MAX_RETRIES = 3
    RETRY_DELAY = 5  # seconds
    
    @classmethod
    def get_credentials(cls) -> tuple[str, str]:
        email = os.getenv('PRETTYRECON_EMAIL')
        password = os.getenv('PRETTYRECON_PASSWORD')
        
        if not email or not password:
            raise ValueError("Missing PRETTYRECON_EMAIL or PRETTYRECON_PASSWORD in environment variables")
            
        return email, password

class CustomScanConfig:
    CHUNK_SIZE = 300  # lines per file
    SPLITS_DIR = Path('Splits')