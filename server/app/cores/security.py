# import dependencies
from dotenv import load_dotenv
from guard import SecurityConfig
import os




# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



# Load credentials
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

# safeguard check
if not all([REDIS_HOST, REDIS_PORT, REDIS_PASSWORD]):
    raise ValueError("CRITICAL: Redis Cloud credentials missing from environment.")



# redis url
redis_cloud_url = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"



# instantiate security configs
security_config = SecurityConfig(
    # redis stateful storage engine
    enable_redis=True,
    redis_url=redis_cloud_url,
    redis_prefix="mezue-db:security:",

    # consolidated penetration engine
    enable_penetration_detection=True,

    # active automated ip banning
    auto_ban_threshold=5,
    auto_ban_duration=86400,

    # explicitly deactivate rate-limiting features
    enable_rate_limiting=False,

    # core threat intelligence & scanner blocking
    blocked_user_agents=[
        "sqlmap",
        "nikto",
        "masscan",
        "nmap",
        "zgrab",
        "wpscan",
        "acunetix"
    ],
    
    # environment gates & infrastructure constraints
    enforce_https=False,
    block_cloud_providers=set(),

    # network proxies & reverse proxy identity trust
    trust_x_forwarded_for=True,
    trusted_proxies=[
        "127.0.0.1",
        "10.0.0.0/8"
    ],
    
    # global middleware bypass routes
    excluded_paths=[
        "/health",
        "/docs",
        "/openapi.json"
    ]
)
