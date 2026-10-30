from cachetools import TTLCache


safe_cache = TTLCache(maxsize=1000, ttl=900)
critical_cache = TTLCache(maxsize=1000, ttl=86400)
suspicious_cache = TTLCache(maxsize=500, ttl=180)


def get_cached_result(key: str):
    for cache in (critical_cache, suspicious_cache, safe_cache):
        if key in cache:
            return cache[key]

    return None


def store_result(key: str, result: dict):
    verdict = result.get("verdict")

    if verdict == "SAFE":
        safe_cache[key] = result
    elif verdict == "CRITICAL":
        critical_cache[key] = result
    elif verdict == "SUSPICIOUS":
        suspicious_cache[key] = result