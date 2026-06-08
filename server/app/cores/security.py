# import dependencies
from guard import SecurityConfig



# instantiate security configs
security_config = SecurityConfig(
    # redis stateful storage engine
    enable_redis=True,
    redis_url="redis://localhost:6379/0",
    redis_prefix="myapp:security:",

    # consolidated penetration engine
    enable_penetration_detection=True,

    # active automated ip banning
    auto_ban_threshold=5,
    auto_ban_duration=86400,  # 1 day

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
        "acunetix",
    ],
    
    # environment gates & infrastructure constraints
    enforce_https=False,
    block_cloud_providers=False,

    # network proxies & reverse proxy identity trust
    trust_x_forwarded_for=True,
    trusted_proxies=[
        "127.0.0.1",
        "10.0.0.0/8",
    ],
    
    # global middleware bypass routes
    excluded_paths=[
        "/health",
        "/docs",
        "/openapi.json",
    ]
)