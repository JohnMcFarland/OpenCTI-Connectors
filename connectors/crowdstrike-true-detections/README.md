# CrowdStrike True Positive Detections Connector

This is an EXTERNAL-IMPORT connector that queries the CrowdStrike Falcon 
[Detects](https://falconpy.io/Service-Collections/Detects.html) API for recent detections with the
status of "true_positive". The connector uploads data and relationships related to the detections
into the OpenCTI platform on a configurable interval.

All detections are attributed to a single tenant Organization, configured via
`CROWDSTRIKE_TRUE_DETECTIONS_ORGANIZATION_NAME`. The Organization is resolved by name at startup
and created if it does not already exist.


The connector imports the following OpenCTI object types:
* AttackPatterns
* Identities
* Incidents
* Infrastructures
* Locations
* Relationships
* Reports
* Software
* StixCyberObservables

**NOTE** - This connector requires API access and refresh tokens that can be acquired from the
CrowdStrike Falcon administrator.

## Installation

The OpenCTI CrowdStrike True Positive Detections Connector requires access to the OpenCTI platform and API. Enabling this connector could be done by 
launching the Python process directly after providing the correct configuration in the [`config.yml`](src/config.yml) file or
within Docker with the image `opencti/crowdstrike-true-detections:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Requirements

- OpenCTI Platform >= 5.9.6

Python libraries:
- pycti == 5.9.6
- crowdstrike-falconpy == 1.2.16

## Configuration
| Parameter                                                          | Docker envvar                                                      | Mandatory | Description                                                                                                                                                                                                                                           |
|--------------------------------------------------------------------|--------------------------------------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                                                      | `OPENCTI_URL`                                                      | Yes       | The URL of the OpenCTI platform.                                                                                                                                                                                                                      |
| `opencti_token`                                                    | `OPENCTI_TOKEN`                                                    | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                                                                                                                                           |
| `connector_id`                                                     | `CONNECTOR_ID`                                                     | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                                                                                                    |
| `connector_type`                                                   | `CONNECTOR_TYPE`                                                   | Yes       | Must be `Template_Type` (this is the connector type).                                                                                                                                                                                                 |
| `connector_name`                                                   | `CONNECTOR_NAME`                                                   | Yes       | Option `Template`                                                                                                                                                                                                                                     |
| `connector_scope`                                                  | `CONNECTOR_SCOPE`                                                  | Yes       | Supported scope: Template Scope (MIME Type or Stix Object)                                                                                                                                                                                            |
| `connector_confidence_level`                                       | `CONNECTOR_CONFIDENCE_LEVEL`                                       | Yes       | The default confidence level for created sightings (a number between 1 and 4).                                                                                                                                                                        |
| `connector_log_level`                                              | `CONNECTOR_LOG_LEVEL`                                              | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                                                                                                         |
| `crowdstrike_true_detections_interval`                            | `CROWDSTRIKE_TRUE_DETECTIONS_INTERVAL`                            | No        | The interval, in hours, before the connector script will run again. Default value is '1'.                                                                                                                                                             |
| `crowdstrike_true_detections_client_id`                           | `CROWDSTRIKE_TRUE_DETECTIONS_CLIENT_ID`                           | Yes       | The API access client id required for authentication with API Requests.                                                                                                                                                                               |
| `crowdstrike_true_detections_client_secret`                       | `CROWDSTRIKE_TRUE_DETECTIONS_CLIENT_SECRET`                       | Yes       | The API access secret required for authentication with API Requests.                                                                                                                                                                                  |
| `crowdstrike_true_detections_organization_name`                   | `CROWDSTRIKE_TRUE_DETECTIONS_ORGANIZATION_NAME`                   | Yes       | The name of the single tenant Organization that all detections are attributed to. Resolved by name in OpenCTI and created if not present.                                                                                                              |
| `crowdstrike_true_detections_organizations_marking_definitions`   | `CROWDSTRIKE_TRUE_DETECTIONS_ORGANIZATIONS_MARKING_DEFINITIONS`   | Yes       | The marking definition type(s) to assign to organizations created by the connector. Format is a String with each marking separated with a comma. No spaces between values. An empty string will result in no marking definitions being applied.       |
| `crowdstrike_true_detections_attack_patterns_marking_definitions` | `CROWDSTRIKE_TRUE_DETECTIONS_ATTACK_PATTERNS_MARKING_DEFINITIONS` | Yes       | The marking definition type(s) to assign to attack patterns created by the connector. Format is a String with each marking separated with a comma. No spaces between values. An empty string will result in no marking definitions being applied.     |
| `crowdstrike_true_detections_default_marking_definitions`         | `CROWDSTRIKE_TRUE_DETECTIONS_DEFAULT_MARKING_DEFINITIONS`         | Yes       | The marking definition type(s) to assign to all other entities created by the connector. Format is a String with each marking separated with a comma. No spaces between values. An empty string will result in no marking definitions being applied.  |

A playbook has been created within OpenCTI that is used to apply marking definitions to entities created by this connector. 
