# import dependencies
import re
from app.cores.config import *
from app.cores.pattern import *
from app.cores.store import SecurityStore




# initialize store
store = SecurityStore()



# brain-detection logic
def match(patterns, text: str):
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False


class SecurityEngine:

    async def analyze(self, request):
        ip = request.client.host
        ua = request.headers.get("user-agent", "").lower()
        path = request.url.path

        body = await request.body()
        body = body.decode("utf-8", errors="ignore")

        score = 0

        # user agent
        if any(bad in ua for bad in BLOCKED_USER_AGENTS):
            score += ATTACK_SCORES["BAD_UA"]

        # recon
        if match(RECON_PATTERNS, path):
            score += ATTACK_SCORES["RECON"]

        # sqli
        if match(SQLI_PATTERNS, body + path):
            score += ATTACK_SCORES["SQLI"]

        # xss
        if match(XSS_PATTERNS, body):
            score += ATTACK_SCORES["XSS"]

        # ssrf
        if match(SSRF_PATTERNS, body):
            score += ATTACK_SCORES["SSRF"]

        # path travasal
        if match(PATH_TRAVERSAL_PATTERNS, body + path):
            score += ATTACK_SCORES["PATH_TRAVERSAL"]

        return ip, score

    async def evaluate(self, ip: str, score: int):
        if score <= 0:
            return

        total = await store.add_score(ip, score)

        if total >= BAN_THRESHOLD:
            await store.ban(ip, BAN_DURATION)