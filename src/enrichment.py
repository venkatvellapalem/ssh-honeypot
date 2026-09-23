"""
Threat Intelligence Enrichment Engine.
Queries ip-api.com for Geolocation and AbuseIPDB for Reputation Scoring,
with SQLite caching and rate-limiting protections.
"""

import ipaddress
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
import requests
from dotenv import load_dotenv

from src.db import get_cached_ip, init_db, set_cached_ip

load_dotenv()
logger = logging.getLogger("honeypot.enrichment")


def is_private_ip(ip_str: str) -> bool:
    """Checks if an IP address is private, loopback, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return True


class ThreatEnricher:
    def __init__(self, db_path: str = "data/honeypot.db", api_key: Optional[str] = None):
        self.db_path = db_path
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.ttl_hours = int(os.getenv("GEOIP_CACHE_TTL_HOURS", "24"))
        init_db(self.db_path)

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        Enriches an IP with Geolocation and AbuseIPDB reputation.
        Utilizes local database caching to minimize API consumption.
        """
        if is_private_ip(ip):
            return {
                "ip": ip,
                "country": "Private Network",
                "country_code": "LAN",
                "city": "Internal",
                "asn": "AS0 (Private)",
                "isp": "Localhost/LAN",
                "latitude": 0.0,
                "longitude": 0.0,
                "abuse_score": 0,
                "total_reports": 0
            }

        # 1. Check local cache
        cached = get_cached_ip(self.db_path, ip)
        if cached and cached.get("cached_at"):
            try:
                cached_time = datetime.fromisoformat(cached["cached_at"])
                if datetime.utcnow() - cached_time < timedelta(hours=self.ttl_hours):
                    return cached
            except Exception:
                pass

        # 2. Perform Geolocation Lookup (ip-api.com free tier)
        geo_data = self._fetch_geoip(ip)

        # 3. Perform AbuseIPDB Lookup (if API key available)
        abuse_data = self._fetch_abuseipdb(ip)

        # Combine results
        combined = {
            "ip": ip,
            "country": geo_data.get("country", "Unknown"),
            "country_code": geo_data.get("countryCode", "XX"),
            "city": geo_data.get("city", "Unknown"),
            "asn": geo_data.get("as", "Unknown"),
            "isp": geo_data.get("isp", "Unknown"),
            "latitude": geo_data.get("lat", 0.0),
            "longitude": geo_data.get("lon", 0.0),
            "abuse_score": abuse_data.get("abuseConfidenceScore", 0),
            "total_reports": abuse_data.get("totalReports", 0),
            "usage_type": abuse_data.get("usageType", "Data Center/Web Hosting/Transit"),
            "domain": abuse_data.get("domain", ""),
            "last_reported": abuse_data.get("lastReportedAt", "")
        }

        # 4. Save to persistent cache
        try:
            set_cached_ip(self.db_path, combined)
        except Exception as e:
            logger.error(f"Failed to cache IP {ip}: {e}")

        return combined

    def _fetch_geoip(self, ip: str) -> Dict[str, Any]:
        """Queries ip-api.com for location details."""
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as,isp", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")
        return {}

    def _fetch_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Queries AbuseIPDB check API."""
        if not self.api_key:
            return {}

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=5
            )
            if resp.status_code == 200:
                return resp.json().get("data", {})
            elif resp.status_code == 429:
                logger.warning(f"AbuseIPDB rate limit reached. Returning score 0.")
            else:
                logger.warning(f"AbuseIPDB API error {resp.status_code} for {ip}: {resp.text}")
        except Exception as e:
            logger.warning(f"AbuseIPDB connection failed for {ip}: {e}")
        return {}
