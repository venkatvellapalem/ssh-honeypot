"""
Threat Intelligence Enrichment Engine.
Queries ip-api.com for Geolocation and AbuseIPDB for Reputation Scoring,
with SQLite caching and rate-limiting protections.
"""

import ipaddress
import logging
import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
import requests
from dotenv import load_dotenv

# Ensure project root is in sys.path
_cur_dir = Path(__file__).resolve().parent
_root_dir = _cur_dir.parent if _cur_dir.name in ("src", "pages") else _cur_dir
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

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
    def __init__(self, db_path: str = "data/honeypot.db", api_key: Optional[str] = None, vt_api_key: Optional[str] = None):
        self.db_path = db_path
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.vt_api_key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
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
                if datetime.now(timezone.utc) - cached_time < timedelta(hours=self.ttl_hours):
                    return cached
            except Exception:
                pass

        # 2. Perform Geolocation Lookup (ip-api.com free tier)
        geo_data = self._fetch_geoip(ip)

        # 3. Perform AbuseIPDB Lookup (if API key available)
        abuse_data = self._fetch_abuseipdb(ip)

        # 4. Perform VirusTotal IP Reputation Lookup (if API key available)
        vt_data = self._fetch_virustotal_ip(ip)

        # Combine results
        combined = {
            "ip": ip,
            "country": geo_data.get("country", "Unknown"),
            "country_code": geo_data.get("countryCode", "XX"),
            "city": geo_data.get("city", "Unknown"),
            "asn": geo_data.get("as", vt_data.get("vt_as_owner", "Unknown")),
            "isp": geo_data.get("isp", "Unknown"),
            "latitude": geo_data.get("lat", 0.0),
            "longitude": geo_data.get("lon", 0.0),
            "abuse_score": abuse_data.get("abuseConfidenceScore", 0),
            "total_reports": abuse_data.get("totalReports", 0),
            "usage_type": abuse_data.get("usageType", "Data Center/Web Hosting/Transit"),
            "domain": abuse_data.get("domain", ""),
            "last_reported": abuse_data.get("lastReportedAt", ""),
            "vt_malicious": vt_data.get("vt_malicious", 0),
            "vt_suspicious": vt_data.get("vt_suspicious", 0),
            "vt_reputation": vt_data.get("vt_reputation", 0),
            "vt_total": vt_data.get("vt_total", 0)
        }

        # 5. Save to persistent cache
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

    def _fetch_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Queries VirusTotal API v3 for IP threat score and detections."""
        if not self.vt_api_key:
            return {}

        headers = {
            "x-apikey": self.vt_api_key,
            "Accept": "application/json"
        }
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers,
                timeout=8
            )
            if resp.status_code == 200:
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                reputation = attr.get("reputation", 0)
                as_owner = attr.get("as_owner", "")
                return {
                    "vt_malicious": malicious,
                    "vt_suspicious": suspicious,
                    "vt_reputation": reputation,
                    "vt_total": total,
                    "vt_as_owner": as_owner
                }
            elif resp.status_code == 429:
                logger.warning(f"VirusTotal rate limit reached for {ip}.")
            else:
                logger.warning(f"VirusTotal API {resp.status_code} for {ip}: {resp.text[:100]}")
        except Exception as e:
            logger.warning(f"VirusTotal connection error for {ip}: {e}")
        return {}

    def fetch_virustotal_hash(self, sha256: str) -> Dict[str, Any]:
        """Queries VirusTotal API v3 for malware dropper hash analysis."""
        if not self.vt_api_key or not sha256:
            return {}

        headers = {
            "x-apikey": self.vt_api_key,
            "Accept": "application/json"
        }
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers=headers,
                timeout=8
            )
            if resp.status_code == 200:
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                threat_class = attr.get("popular_threat_classification", {})
                return {
                    "vt_malicious": stats.get("malicious", 0),
                    "vt_suspicious": stats.get("suspicious", 0),
                    "vt_threat_label": threat_class.get("suggested_threat_label", "Malware")
                }
        except Exception as e:
            logger.warning(f"VirusTotal hash lookup failed for {sha256}: {e}")
        return {}
