import json
import logging
import os
from typing import Optional

import redis

logger = logging.getLogger(__name__)

REDIS_HOST     = os.getenv("REDIS_HOST", "redis")
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
CACHE_TTL_SEC  = int(os.getenv("CACHE_TTL_SECONDS", str(24 * 60 * 60)))
_NS = "enrichment:ioc:"

def _make_key(ioc_type, ioc_value):
    return f"{_NS}{ioc_type}:{ioc_value.lower()}"

_client = None

def _get_client():
    global _client
    if _client is None:
        _client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD or None,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
        )
        logger.info("Redis client initialised (%s:%s)", REDIS_HOST, REDIS_PORT)
    return _client

def get(ioc_type, ioc_value):
    key = _make_key(ioc_type, ioc_value)
    try:
        raw = _get_client().get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.warning("Cache GET error (key=%s): %s", key, exc)
        return None

def set(ioc_type, ioc_value, data, ttl=CACHE_TTL_SEC):
    key = _make_key(ioc_type, ioc_value)
    try:
        _get_client().setex(key, ttl, json.dumps(data))
        return True
    except Exception as exc:
        logger.warning("Cache SET error (key=%s): %s", key, exc)
        return False

def exists(ioc_type, ioc_value):
    key = _make_key(ioc_type, ioc_value)
    try:
        return bool(_get_client().exists(key))
    except Exception:
        return False
