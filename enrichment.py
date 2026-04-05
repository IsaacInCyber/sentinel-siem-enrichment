#!/usr/bin/env python3
"""
Microsoft Sentinel SIEM Data Enrichment Script
Enriches security events with threat intelligence and contextual data
Functional implementation (no classes)
"""

import requests
import json
import ipaddress
from datetime import datetime
from typing import Dict, Optional
import logging

# Configure logging
logging.basicConfig(
      level=logging.INFO,
      format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration - replace with your credentials
CONFIG = {
      "workspace_id": "YOUR_WORKSPACE_ID",
      "shared_key": "YOUR_SHARED_KEY",
      "abuseipdb_key": "YOUR_ABUSEIPDB_KEY",
      "virustotal_key": "YOUR_VIRUSTOTAL_KEY"
}


def get_geolocation(ip: str) -> Optional[Dict]:
      """Get geolocation data for IP address"""
      try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if response.status_code == 200:
                              return response.json()
      except Exception as e:
                logger.warning(f"Geolocation lookup failed for {ip}: {e}")
            return None


def check_ip_reputation(ip: str, api_key: Optional[str] = None) -> Optional[Dict]:
      """Check IP reputation using AbuseIPDB"""
    if not api_key:
              logger.warning("No AbuseIPDB API key provided")
              return None

    try:
              headers = {'Key': api_key, 'Accept': 'application/json'}
              params = {'ipAddress': ip, 'maxAgeInDays': 90}

        response = requests.get(
                      'https://api.abuseipdb.com/api/v2/check',
                      headers=headers,
                      params=params,
                      timeout=5
        )

        if response.status_code == 200:
                      data = response.json().get('data', {})
                      abuse_score = data.get('abuseConfidenceScore', 0)

            return {
                              "is_suspicious": abuse_score > 50,
                              "threat_level": "high" if abuse_score > 75 else "medium" if abuse_score > 25 else "low",
                              "abuse_score": abuse_score,
                              "usage_type": data.get('usageType'),
                              "total_reports": data.get('totalReports', 0)
            }
except Exception as e:
        logger.warning(f"IP reputation check failed for {ip}: {e}")
    return None


def check_virustotal(file_hash: str, api_key: Optional[str] = None) -> Optional[Dict]:
      """Check file hash against VirusTotal"""
    if not api_key:
              logger.warning("No VirusTotal API key provided")
              return None

    try:
              headers = {'x-apikey': api_key}
              response = requests.get(
                  f'https://www.virustotal.com/api/v3/files/{file_hash}',
                  headers=headers,
                  timeout=10
              )

        if response.status_code == 200:
                      data = response.json().get('data', {})
                      attributes = data.get('attributes', {})
                      stats = attributes.get('last_analysis_stats', {})

            malicious = stats.get('malicious', 0)
            total = sum(stats.values())

            return {
                              "is_malicious": malicious > 5,
                              "detection_ratio": f"{malicious}/{total}",
                              "malware_family": attributes.get('popular_threat_classification', {}).get('suggested_threat_label'),
                              "first_seen": attributes.get('first_submission_date')
            }
except Exception as e:
        logger.warning(f"VirusTotal check failed for {file_hash}: {e}")
    return None


def enrich_ip(ip: str, api_key: Optional[str] = None) -> Dict:
      """Enrich IP address with geolocation and threat intelligence"""
    enrichment = {
              "ip_address": ip,
              "enrichment_time": datetime.utcnow().isoformat(),
              "is_private": False,
              "is_suspicious": False,
              "threat_level": "unknown"
    }

    try:
              ip_obj = ipaddress.ip_address(ip)
              enrichment["is_private"] = ip_obj.is_private

        if not ip_obj.is_private:
                      # Geolocation
                      geo = get_geolocation(ip)
                      if geo:
                                        enrichment.update({
                                                              "country": geo.get("country"),
                                                              "country_code": geo.get("countryCode"),
                                                              "region": geo.get("regionName"),
                                                              "city": geo.get("city"),
                                                              "isp": geo.get("isp"),
                                                              "organization": geo.get("org")
                                        })

                      # Threat intel
                      threat = check_ip_reputation(ip, api_key)
                      if threat:
                                        enrichment.update({
                                                              "is_suspicious": threat.get("is_suspicious", False),
                                                              "threat_level": threat.get("threat_level", "unknown"),
                                                              "abuse_confidence_score": threat.get("abuse_score", 0),
                                                              "total_abuse_reports": threat.get("total_reports", 0)
                                        })

except Exception as e:
        logger.error(f"Error enriching IP {ip}: {e}")
        enrichment["error"] = str(e)

    return enrichment

"""
Microsoft Sentinel SIEM Data Enrichment Script
Enriches security events with threat intelligence and contextual data
Functional implementation (no classes)
"""

import requests
import json
import ipaddress
from datetime import datetime
from typing import Dict, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration - replace with your credentials
CONFIG = {
    "workspace_id": "YOUR_WORKSPACE_ID",
    "shared_key": "YOUR_SHARED_KEY",
    "abuseipdb_key": "YOUR_ABUSEIPDB_KEY",
    "virustotal_key": "YOUR_VIRUSTOTAL_KEY"
}


def get_geolocation(ip: str) -> Optional[Dict]:
    """Get geolocation data for IP address"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.warning(f"Geolocation lookup failed for {ip}: {e}")
    return None


def check_ip_reputation(ip: str, api_key: Optional[str] = None) -> Optional[Dict]:
    """Check IP reputation using AbuseIPDB"""
    if not api_key:
        logger.warning("No AbuseIPDB API key provided")
        return None
    
    try:
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            abuse_score = data.get('abuseConfidenceScore', 0)
            
            return {
                "is_suspicious": abuse_score > 50,
                "threat_level": "high" if abuse_score > 75 else "medium" if abuse_score > 25 else "low",
                "abuse_score": abuse_score,
                "usage_type": data.get('usageType'),
                "total_reports": data.get('totalReports', 0)
            }
    except Exception as e:
        logger.warning(f"IP reputation check failed for {ip}: {e}")
    return None


def check_virustotal(file_hash: str, api_key: Optional[str] = None) -> Optional[Dict]:
    """Check file hash against VirusTotal"""
    if not api_key:
        logger.warning("No VirusTotal API key provided")
        return None
    
    try:
        headers = {'x-apikey': api_key}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{file_hash}',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            
            return {
                "is_malicious": malicious > 5,
                "detection_ratio": f"{malicious}/{total}",
                "malware_family": attributes.get('popular_threat_classification', {}).get('suggested_threat_label'),
                "first_seen": attributes.get('first_submission_date')
            }
    except Exception as e:
        logger.warning(f"VirusTotal check failed for {file_hash}: {e}")
    return None


def enrich_ip(ip: str, api_key: Optional[str] = None) -> Dict:
    """Enrich IP address with geolocation and threat intelligence"""
    enrichment = {
        "ip_address": ip,
        "enrichment_time": datetime.utcnow().isoformat(),
        "is_private": False,
        "is_suspicious": False,
        "threat_level": "unknown"
    }
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        enrichment["is_private"] = ip_obj.is_private
        
        if not ip_obj.is_private:
            # Geolocation
            geo = get_geolocation(ip)
            if geo:
                enrichment.update({
                    "country": geo.get("country"),
                    "country_code": geo.get("countryCode"),
                    "region": geo.get("regionName"),
                    "city": geo.get("city"),
                    "isp": geo.get("isp"),
                    "organization": geo.get("org")
                })
            
            # Threat intel
            threat = check_ip_reputation(ip, api_key)
            if threat:
                enrichment.update({
                    "is_suspicious": threat.get("is_suspicious", False),
                    "threat_level": threat.get("threat_level", "unknown"),
                    "abuse_confidence_score": threat.get("abuse_score", 0),
                    "total_abuse_reports": threat.get("total_reports", 0)
                })
    
    except Exception as e:
        logger.error(f"Error enriching IP {ip}: {e}")
        enrichment["error"] = str(e)
    
    return enrichment


def enrich_domain(domain: str) -> Dict:
    """Enrich domain with reputation data"""
    suspicious_tlds = ('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz')
    
    enrichment = {
        "domain": domain,
        "enrichment_time": datetime.utcnow().isoformat(),
        "domain_length": len(domain),
        "subdomain_count": domain.count('.'),
        "has_suspicious_tld": domain.endswith(suspicious_tlds),
        "is_suspicious": False
    }
    
    # Flag short random-looking domains with suspicious TLDs
    if enrichment["has_suspicious_tld"] and len(domain.split('.')[0]) < 6:
        enrichment["is_suspicious"] = True
    
    return enrichment


def enrich_file_hash(file_hash: str, hash_type: str = "sha256", api_key: Optional[str] = None) -> Dict:
    """Enrich file hash with malware intelligence"""
    enrichment = {
        "file_hash": file_hash,
        "hash_type": hash_type,
        "enrichment_time": datetime.utcnow().isoformat(),
        "is_malicious": False
    }
    
    try:
        vt_data = check_virustotal(file_hash, api_key)
        if vt_data:
            enrichment.update({
                "is_malicious": vt_data.get("is_malicious", False),
                "malware_family": vt_data.get("malware_family"),
                "detection_ratio": vt_data.get("detection_ratio"),
                "first_seen": vt_data.get("first_seen")
            })
    except Exception as e:
        logger.error(f"Error enriching hash {file_hash}: {e}")
        enrichment["error"] = str(e)
    
    return enrichment


def enrich_user(username: str, ad_data: Optional[Dict] = None) -> Dict:
    """Enrich user with AD/Azure AD context"""
    enrichment = {
        "username": username,
        "enrichment_time": datetime.utcnow().isoformat()
    }
    
    if ad_data:
        enrichment.update({
            "department": ad_data.get("department"),
            "title": ad_data.get("title"),
            "manager": ad_data.get("manager"),
            "is_privileged": ad_data.get("is_admin", False),
            "account_created": ad_data.get("created_date"),
            "last_password_change": ad_data.get("last_pwd_change")
        })
    
    return enrichment


def calculate_risk_score(enrichments: Dict) -> int:
    """Calculate overall risk score based on enrichments"""
    score = 0
    
    # IP reputation scoring
    for key in ["source_ip", "destination_ip"]:
        if key in enrichments:
            ip_data = enrichments[key]
            if ip_data.get("is_suspicious"):
                score += 30
            abuse_score = ip_data.get("abuse_confidence_score", 0)
            if abuse_score > 75:
                score += 20
            elif abuse_score > 50:
                score += 10
    
    # Domain scoring
    if "domain" in enrichments:
        if enrichments["domain"].get("is_suspicious"):
            score += 20
        elif enrichments["domain"].get("has_suspicious_tld"):
            score += 10
    
    # File hash scoring
    if "file_hash" in enrichments:
        if enrichments["file_hash"].get("is_malicious"):
            score += 50
    
    return min(score, 100)


def enrich_event(event: Dict) -> Dict:
    """Enrich a complete security event with all available data"""
    enriched = event.copy()
    enriched["enrichments"] = {}
    
    # Enrich IPs
    if "source_ip" in event:
        enriched["enrichments"]["source_ip"] = enrich_ip(
            event["source_ip"], 
            CONFIG.get("abuseipdb_key")
        )
    
    if "destination_ip" in event:
        enriched["enrichments"]["destination_ip"] = enrich_ip(
            event["destination_ip"],
            CONFIG.get("abuseipdb_key")
        )
    
    # Enrich domain
    if "domain" in event:
        enriched["enrichments"]["domain"] = enrich_domain(event["domain"])
    
    # Enrich file hash
    if "file_hash" in event:
        enriched["enrichments"]["file_hash"] = enrich_file_hash(
            event["file_hash"],
            event.get("hash_type", "sha256"),
            CONFIG.get("virustotal_key")
        )
    
    # Enrich user
    if "username" in event:
        enriched["enrichments"]["user"] = enrich_user(event["username"])
    
    # Calculate risk
    enriched["risk_score"] = calculate_risk_score(enriched["enrichments"])
    
    return enriched


def process_events(events: list) -> list:
    """Process multiple security events"""
    enriched_events = []
    
    for event in events:
        try:
            enriched = enrich_event(event)
            enriched_events.append(enriched)
            logger.info(f"Enriched event with risk score: {enriched['risk_score']}")
        except Exception as e:
            logger.error(f"Failed to enrich event: {e}")
            event["enrichment_error"] = str(e)
            enriched_events.append(event)
    
    return enriched_events


def main():
    """Example usage"""
    # Sample security events
    events = [
        {
            "event_type": "suspicious_login",
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "185.220.101.1",
            "destination_ip": "10.0.0.50",
            "username": "john.doe",
            "domain": "malicious-site.tk"
        },
        {
            "event_type": "file_download",
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "8.8.8.8",
            "username": "jane.smith",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    ]
    
    # Process all events
    enriched_events = process_events(events)
    
    # Output results
    print(json.dumps(enriched_events, indent=2))
    
    # Summary
    high_risk = [e for e in enriched_events if e.get("risk_score", 0) >= 50]
    logger.info(f"Processed {len(enriched_events)} events, {len(high_risk)} high risk")


if __name__ == "__main__":
    main()       if enrichments["domain"].get("is_suspicious"):
            score += 20
elif enrichments["domain"].get("has_suspicious_tld"):
            score += 10

    if "file_hash" in enrichments:
              if enrichments["file_hash"].get("is_malicious"):
                            score += 50

          return min(score, 100)


def enrich_event(event: Dict) -> Dict:
      """Enrich a complete security event with all available data"""
    enriched = event.copy()
    enriched["enrichments"] = {}

    if "source_ip" in event:
              enriched["enrichments"]["source_ip"] = enrich_ip(
                            event["source_ip"], 
                            CONFIG.get("abuseipdb_key")
              )

    if "destination_ip" in event:
              enriched["enrichments"]["destination_ip"] = enrich_ip(
                            event["destination_ip"],
                            CONFIG.get("abuseipdb_key")
              )

    if "domain" in event:
              enriched["enrichments"]["domain"] = enrich_domain(event["domain"])

    if "file_hash" in event:
              enriched["enrichments"]["file_hash"] = enrich_file_hash(
                            event["file_hash"],
                            event.get("hash_type", "sha256"),
                            CONFIG.get("virustotal_key")
              )

    if "username" in event:
              enriched["enrichments"]["user"] = enrich_user(event["username"])

    enriched["risk_score"] = calculate_risk_score(enriched["enrichments"])

    return enriched


def process_events(events: list) -> list:
      """Process multiple security events"""
    enriched_events = []

    for event in events:
              try:
                            enriched = enrich_event(event)
                            enriched_events.append(enriched)
                            logger.info(f"Enriched event with risk score: {enriched['risk_score']}")
except Exception as e:
            logger.error(f"Failed to enrich event: {e}")
            event["enrichment_error"] = str(e)
            enriched_events.append(event)

    return enriched_events


def main():
      """Example usage"""
    events = [
              {
                            "event_type": "suspicious_login",
                            "timestamp": datetime.utcnow().isoformat(),
                            "source_ip": "185.220.101.1",
                            "destination_ip": "10.0.0.50",
                            "username": "john.doe",
                            "domain": "malicious-site.tk"
              },
              {
                            "event_type": "file_download",
                            "timestamp": datetime.utcnow().isoformat(),
                            "source_ip": "8.8.8.8",
                            "username": "jane.smith",
                            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
              }
    ]

    enriched_events = process_events(events)
    print(json.dumps(enriched_events, indent=2))

    high_risk = [e for e in enriched_events if e.get("risk_score", 0) >= 50]
    logger.info(f"Processed {len(enriched_events)} events, {len(high_risk)} high risk")


if __name__ == "__main__":
      main()
