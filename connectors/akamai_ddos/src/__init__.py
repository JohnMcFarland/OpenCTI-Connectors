"""Akamai DDoS → OpenCTI connector.

Pulls Akamai Prolexic (L3/L4) and SIEM (L7) DDoS telemetry and structures it as
first-hand internal observation (Incident Response container + Incident + Sightings)
per the data_model/ source of truth. See CONNECTOR_SCOPE.md.
"""
