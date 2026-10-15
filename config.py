"""
Configuration file for AIORI-3 PS-011: Authorised Attack-Surface Inventory and Change Monitor.
Defines application constants, scope boundaries, default ports, and timeouts.
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
DATABASE_PATH = DATA_DIR / "asm_database.sqlite"

# Ensure data and reports directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Application Metadata
APP_NAME = "Authorised Attack-Surface Inventory & Change Monitor"
APP_CODE = "AIORI-3 PS-011"
VERSION = "1.0.0"
SECRET_KEY = os.environ.get("ASM_SECRET_KEY", "ps011-cybersecurity-aiori3-2026-secret-key")

# Strict Scope Limits (Mandated by PS-011)
MAX_APPROVED_DOMAINS = 20
MAX_APPROVED_HOSTS = 10

# Network & Probe Defaults (Conservative non-intrusive timeouts)
DEFAULT_SOCKET_TIMEOUT = 3.0    # seconds
DEFAULT_DNS_TIMEOUT = 3.0       # seconds
DEFAULT_HTTP_TIMEOUT = 4.0      # seconds
DEFAULT_USER_AGENT = "AIORI-ASM-Monitor/1.0 (Authorised Security Research Probe; +https://github.com/aiori-hackathon)"

# Approved Default Port Allowlist for Lab Hosts
# (Only these explicitly documented ports are inspected)
DEFAULT_APPROVED_PORTS = [22, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 8888, 9090]

# Baseline Approved Services Matrix
# If an open port is not in this map for a given host, it is flagged as an UNEXPECTED SERVICE
DEFAULT_BASELINE_SERVICES = {
    "127.0.0.1": [80, 443],
    "10.0.1.10": [80, 443],
    "10.0.1.11": [22, 443],
    "10.0.1.12": [80, 443],
    "10.0.1.15": [443, 8443],
    "10.0.2.20": [80, 443],
    "10.0.2.25": [22, 443],
    "10.0.3.30": [80],
    "10.0.3.35": [443],
    "10.0.4.50": [443]
}

# Certificate Warning Threshold (days before expiry to trigger warning)
CERT_EXPIRY_WARNING_DAYS = 14

# Cloud Provider Dangling DNS Patterns & Signatures
DANGLING_DNS_PROVIDERS = {
    "AWS S3": {
        "domains": [r"s3[\w-]*\.amazonaws\.com", r"s3-website[\w-]*\.amazonaws\.com"],
        "signatures": ["NoSuchBucket", "The specified bucket does not exist"]
    },
    "AWS Elastic Beanstalk": {
        "domains": [r"elasticbeanstalk\.com"],
        "signatures": ["NXDOMAIN"]
    },
    "AWS CloudFront": {
        "domains": [r"cloudfront\.net"],
        "signatures": ["Bad request", "CloudFront", "NoSuchDistribution"]
    },
    "GitHub Pages": {
        "domains": [r"github\.io"],
        "signatures": ["There isn't a GitHub Pages site here", "For root URLs"]
    },
    "Azure App Service": {
        "domains": [r"azurewebsites\.net", r"trafficmanager\.net", r"cloudapp\.azure\.com"],
        "signatures": ["404 Web Site not found", "app service not found"]
    },
    "Heroku": {
        "domains": [r"herokuapp\.com", r"herokussl\.com"],
        "signatures": ["No such app", "herokucdn.com/error-pages/no-such-app.html"]
    },
    "Shopify": {
        "domains": [r"myshopify\.com"],
        "signatures": ["Sorry, this shop is currently unavailable"]
    },
    "Fastly": {
        "domains": [r"fastly\.net"],
        "signatures": ["Fastly error: unknown domain"]
    },
    "Pantheon": {
        "domains": [r"pantheonsite\.io"],
        "signatures": ["The gods are wise, but do not know of the site you are looking for"]
    }
}
