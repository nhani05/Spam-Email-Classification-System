import logging
import sys
from pathlib import Path
from datetime import datetime

# Global variable to store the log file path for the current run
_LOG_FILE = None
_FORMAT = "[%(asctime)s] %(levelname)s %(name)s:%(lineno)d - %(message)s"
_DATE_FORMAT = "%H:%M:%S"

def get_logger(name: str):
    global _LOG_FILE
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    # Create log file path only once for the entire pipeline run
    if _LOG_FILE is None:
        date_dir = datetime.now().strftime("%Y-%m-%d")
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = Path("logs") / date_dir
        log_dir.mkdir(parents=True, exist_ok=True)
        _LOG_FILE = log_dir / f"{timestamp}.log"

    formatter = logging.Formatter(_FORMAT, datefmt=_DATE_FORMAT)

    file_handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logger.propagate = False
    return logger
