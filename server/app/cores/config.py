BAN_THRESHOLD = 10
BAN_DURATION = 3600

ATTACK_SCORES = {
    "SQLI": 5,
    "XSS": 4,
    "SSRF": 6,
    "PATH_TRAVERSAL": 5,
    "RECON": 2,
    "BAD_UA": 3,
}

BLOCKED_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan",
    "zgrab", "wpscan", "acunetix",
    "curl", "wget"
]

TRUSTED_PROXIES = ["127.0.0.1", "10.0.0.0/8"]