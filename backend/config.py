import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Base Directory Paths
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
BACKEND_ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(ENV_PATH)               # Primary: project root .env
load_dotenv(BACKEND_ENV_PATH)       # Secondary: backend/.env (user can place NVIDIA key here)


# Automatic Java Home Discovery for Apache Spark
def _discover_java_home() -> str:
    candidate_paths = [
        os.getenv("JAVA_HOME", ""),
        r"C:\Program Files\Java\jdk-21",
        r"C:\Program Files\Java\jdk-17",
        r"C:\Program Files\Java\jdk-11",
    ]
    for p in candidate_paths:
        if p and Path(p).exists():
            return p
    return ""

JAVA_HOME = _discover_java_home()
if JAVA_HOME and not os.environ.get("JAVA_HOME"):
    os.environ["JAVA_HOME"] = JAVA_HOME
    java_bin = str(Path(JAVA_HOME) / "bin")
    if java_bin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{java_bin};{os.environ.get('PATH', '')}"


class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "SOC_CHESS")
    BACKEND_HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0" if (os.getenv("PORT") or os.getenv("RENDER")) else "127.0.0.1")
    BACKEND_PORT: int = int(os.getenv("PORT") or os.getenv("BACKEND_PORT", "8001"))
    FRONTEND_PORT: int = int(os.getenv("FRONTEND_PORT", "5173"))

    # Database Configuration (MySQL with SQLite automatic fallback)
    USE_SQLITE: bool = os.getenv("USE_SQLITE", "false").lower() in ("true", "1", "yes")
    SQLITE_DB_PATH: Path = BASE_DIR / os.getenv("SQLITE_DB_PATH", "soc_chess.db")

    # MySQL Configuration
    MYSQL_HOST: str = os.getenv("MYSQL_HOST", "127.0.0.1")
    MYSQL_PORT: int = int(os.getenv("MYSQL_PORT", "3306"))
    MYSQL_DATABASE: str = os.getenv("MYSQL_DATABASE", "soc_chess")
    MYSQL_USERNAME: str = os.getenv("MYSQL_USERNAME", "root")
    MYSQL_PASSWORD: str = os.getenv("MYSQL_PASSWORD", "")

    # Wireshark & TShark Host Paths
    WIRESHARK_PATH: str = os.getenv("WIRESHARK_PATH", r"C:\Program Files\Wireshark\Wireshark.exe")
    TSHARK_PATH: str = os.getenv("TSHARK_PATH", r"C:\Program Files\Wireshark\tshark.exe")
    DEFAULT_INTERFACE: str = os.getenv("DEFAULT_INTERFACE", "Ethernet 7")

    # Splunk Enterprise Configuration
    SPLUNK_HOST: str = os.getenv("SPLUNK_HOST", "127.0.0.1")
    SPLUNK_PORT: int = int(os.getenv("SPLUNK_PORT", "8089"))
    SPLUNK_WEB_URL: str = os.getenv("SPLUNK_WEB_URL", "http://127.0.0.1:8000")
    SPLUNK_USERNAME: str = os.getenv("SPLUNK_USERNAME", "sai")
    SPLUNK_PASSWORD: str = os.getenv("SPLUNK_PASSWORD", "Sai@8501")
    SPLUNK_INDEX: str = os.getenv("SPLUNK_INDEX", "main")

    # Directories
    BASE_DIR: Path = BASE_DIR
    raw_dataset_root = os.getenv("DATASET_ROOT") or os.getenv("DATASET_DIR", "datasets")
    if raw_dataset_root and (Path(raw_dataset_root).is_absolute() or (len(raw_dataset_root) > 1 and raw_dataset_root[1] == ':')):
        DATASET_DIR: Path = Path(raw_dataset_root).resolve()
    else:
        DATASET_DIR: Path = (BASE_DIR / (raw_dataset_root or "datasets")).resolve()
    DATASET_ROOT: Path = DATASET_DIR
    MODEL_DIR: Path = BASE_DIR / os.getenv("MODEL_DIR", "ml/models")

    # Apache Spark Big Data Configuration
    SPARK_APP_NAME: str = os.getenv("SPARK_APP_NAME", "SOC_Chess_BigData_Pipeline")
    SPARK_MASTER: str = os.getenv("SPARK_MASTER", "local[*]")
    SPARK_DRIVER_MEMORY: str = os.getenv("SPARK_DRIVER_MEMORY", "2g")
    SPARK_EXECUTOR_MEMORY: str = os.getenv("SPARK_EXECUTOR_MEMORY", "2g")
    SPARK_PARTITIONS: int = int(os.getenv("SPARK_PARTITIONS", "8"))
    JAVA_HOME: str = JAVA_HOME
    PYSPARK_PYTHON: str = os.getenv("PYSPARK_PYTHON", sys.executable)
    PYSPARK_DRIVER_PYTHON: str = os.getenv("PYSPARK_DRIVER_PYTHON", sys.executable)

    # Multi-Layer Perceptron (MLP) Neural Network Config
    MLP_HIDDEN_LAYERS: tuple = (128, 64, 32)
    MLP_ACTIVATION: str = "relu"
    MLP_SOLVER: str = "adam"
    MLP_MAX_ITER: int = int(os.getenv("MLP_MAX_ITER", "200"))
    MLP_LEARNING_RATE_INIT: float = float(os.getenv("MLP_LEARNING_RATE", "0.001"))
    MLP_EARLY_STOPPING: bool = True

    # Risk Score Engine Thresholds
    RISK_THRESHOLD_LOW_MAX: int = int(os.getenv("RISK_LOW_MAX", "24"))
    RISK_THRESHOLD_MED_MAX: int = int(os.getenv("RISK_MED_MAX", "49"))
    RISK_THRESHOLD_HIGH_MAX: int = int(os.getenv("RISK_HIGH_MAX", "74"))
    RISK_THRESHOLD_CRITICAL_MIN: int = int(os.getenv("RISK_CRITICAL_MIN", "75"))

    # Threat Intelligence Configuration
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    TI_CACHE_TTL_SECONDS: int = int(os.getenv("TI_CACHE_TTL_SECONDS", "3600"))

    # NVIDIA NIM LLM SOC Analyst Gateway Configuration
    NVIDIA_API_KEY: str = os.getenv("NVIDIA_API_KEY", "")
    NVIDIA_BASE_URL: str = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
    NEMOTRON_MODEL: str = os.getenv("NEMOTRON_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
    DEEPSEEK_MODEL: str = os.getenv("DEEPSEEK_MODEL", "deepseek-ai/deepseek-v4-pro-0813")
    KIMI_MODEL: str = os.getenv("KIMI_MODEL", "moonshotai/kimi-k3")
    LLM_ENABLED: bool = os.getenv("LLM_ENABLED", "true").lower() in ("true", "1", "yes")
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "4000"))
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")

    # Security
    AUTH_ENABLED: bool = os.getenv("AUTH_ENABLED", "true").lower() in ("true", "1", "yes")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    ACCESS_TOKEN_TTL_MINUTES: int = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "480"))

settings = Settings()

# Ensure Model and Processed Directories Exist
settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)
(settings.DATASET_DIR / "processed").mkdir(parents=True, exist_ok=True)
