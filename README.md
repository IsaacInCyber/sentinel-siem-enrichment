# Sentinel SIEM Data Enrichment

Python scripts for enriching Microsoft Sentinel SIEM data with threat intelligence, geolocation, and contextual data.

## Overview

This tool automates the enrichment of security events with external threat intelligence and contextual data, enabling faster triage and more informed incident response decisions.

## Features

- **IP Address Enrichment**: Geolocation data, ISP information, and threat reputation scoring via AbuseIPDB
- - **Domain Enrichment**: Suspicious TLD detection, domain characteristics analysis
  - - **File Hash Enrichment**: VirusTotal integration for malware detection and classification
    - - **User Context Enrichment**: Integration points for Active Directory/Azure AD data
      - - **Risk Score Calculation**: Automated scoring based on aggregated enrichment signals
       
        - ## Prerequisites
       
        - - Python 3.8+
          - - Microsoft Sentinel workspace (Log Analytics Workspace ID and Key)
            - - API keys (optional but recommended):
              -   - [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation checks
                  -   - [VirusTotal](https://www.virustotal.com/) - File hash analysis
                   
                      - ## Installation
                   
                      - ```bash
                        git clone https://github.com/IsaacInCyber/sentinel-siem-enrichment.git
                        cd sentinel-siem-enrichment
                        pip install requests
                        ```

                        ## Configuration

                        Update the `CONFIG` dictionary in `enrichment.py` with your credentials:

                        ```python
                        CONFIG = {
                            "workspace_id": "YOUR_WORKSPACE_ID",
                            "shared_key": "YOUR_SHARED_KEY",
                            "abuseipdb_key": "YOUR_ABUSEIPDB_KEY",
                            "virustotal_key": "YOUR_VIRUSTOTAL_KEY"
                        }
                        ```

                        ## Usage

                        ### Single Event Enrichment

                        ```python
                        from enrichment import enrich_event

                        event = {
                            "event_type": "suspicious_login",
                            "source_ip": "185.220.101.1",
                            "username": "john.doe",
                            "domain": "suspicious-site.tk"
                        }

                        enriched = enrich_event(event)
                        print(f"Risk Score: {enriched['risk_score']}")
                        ```

                        ### Batch Processing

                        ```python
                        from enrichment import process_events

                        events = [event1, event2, event3]
                        enriched_events = process_events(events)
                        ```

                        ### Individual Enrichment Functions

                        ```python
                        from enrichment import enrich_ip, enrich_domain, enrich_file_hash

                        # IP enrichment with threat intel
                        ip_data = enrich_ip("8.8.8.8", api_key="YOUR_ABUSEIPDB_KEY")

                        # Domain analysis
                        domain_data = enrich_domain("example.tk")

                        # File hash lookup
                        hash_data = enrich_file_hash("e3b0c44298fc1c14...", api_key="YOUR_VT_KEY")
                        ```

                        ## Output Format

                        Enriched events include an `enrichments` object and calculated `risk_score`:

                        ```json
                        {
                          "event_type": "suspicious_login",
                          "source_ip": "185.220.101.1",
                          "enrichments": {
                            "source_ip": {
                              "country": "Germany",
                              "isp": "Example ISP",
                              "is_suspicious": true,
                              "abuse_confidence_score": 85,
                              "threat_level": "high"
                            }
                          },
                          "risk_score": 50
                        }
                        ```

                        ## Integration Options

                        - **Azure Functions**: Deploy as a serverless function for real-time enrichment
                        - - **Logic Apps**: Use as a connector in Sentinel playbooks
                          - - **Scheduled Jobs**: Run as a cron job for batch processing
                            - - **Sentinel Watchlists**: Export high-risk indicators to watchlists
                             
                              - ## Extending the Script
                             
                              - Add new enrichment sources by creating functions following this pattern:
                             
                              - ```python
                                def enrich_custom_source(indicator: str, api_key: str = None) -> Dict:
                                    enrichment = {
                                        "indicator": indicator,
                                        "enrichment_time": datetime.utcnow().isoformat()
                                    }
                                    # Add your enrichment logic here
                                    return enrichment
                                ```

                                ## License

                                MIT

                                ## Author

                                Isaac Amoussou-Kpakpa - [IsaacInCyber](https://github.com/IsaacInCyber)
