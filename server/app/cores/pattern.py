RECON_PATTERNS = [
    r"\.env",
    r"\.git",
    r"wp-admin",
    r"phpmyadmin",
    r"server-status",
]

SQLI_PATTERNS = [
    r"(\%27)|(')|(--)|(%23)|(#)",
    r"union.*select",
    r"drop\s+table",
]

XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"javascript:"
]

SSRF_PATTERNS = [
    r"localhost",
    r"127\.0\.0\.1",
    r"169\.254\.169\.254"
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\"
]