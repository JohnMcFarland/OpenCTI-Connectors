# OpenPhish Connector

This is an EXTERNAL-IMPORT connector that downloads the latest phishing email data from   
[OpenPhish](https://openphish.com/guide-feed). The connector uploads data and relationships related 
to the phishing data into the OpenCTI platform on a configurable and regular interval.


The connector imports the following OpenCTI object types:
* AttackPattern
* Campaign
* Domain
* IPv4 Address
* Incidents
* Relationship
* Report
* Sector (as Identity)
* URL

**NOTE** - This connector requires an access key id and access key secret that can be acquired from the
OpenPhish administrator.

## Installation

The OpenCTI OpenPhish Connector requires access to the OpenCTI platform and API. Enabling this connector could be done by 
launching the Python process directly after providing the correct configuration in the [`config.yml`](src/config.yml) file or
within Docker with the image `opencti/openphish:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Requirements
The formal scoping document for this connector detailing its requirements can be found [here](https://docs.google.com/document/d/1GB_zRzkhkfeww1JZIseTNNhbCZnEJVKjXhwJ6HMdB90/)

- OpenCTI Platform >= 5.12.33

Python libraries:
- pycti == 5.12.33
- boto3

## Configuration 
| Parameter                                       | Docker envvar                                   | Mandatory | Description                                                                                                                                                                                                                                       |
|-------------------------------------------------|-------------------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                                   | `OPENCTI_URL`                                   | Yes       | The URL of the OpenCTI platform.                                                                                                                                                                                                                  |
| `opencti_token`                                 | `OPENCTI_TOKEN`                                 | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                                                                                                                                       |
| `connector_id`                                  | `CONNECTOR_ID`                                  | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                                                                                                |
| `connector_type`                                | `CONNECTOR_TYPE`                                | Yes       | Must be `Template_Type` (this is the connector type).                                                                                                                                                                                             |
| `connector_name`                                | `CONNECTOR_NAME`                                | Yes       | Option `Template`                                                                                                                                                                                                                                 |
| `connector_scope`                               | `CONNECTOR_SCOPE`                               | Yes       | Supported scope: Template Scope (MIME Type or Stix Object)                                                                                                                                                                                        |
| `connector_confidence_level`                    | `CONNECTOR_CONFIDENCE_LEVEL`                    | Yes       | The default confidence level for created sightings (a number between 1 and 4).                                                                                                                                                                    |
| `connector_log_level`                           | `CONNECTOR_LOG_LEVEL`                           | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                                                                                                     |
| `openphish_interval_hours`                      | `OPENPHISH_INTERVAL_HOURS`                      | No        | The interval, in hours, before the connector script will run again. Default value is '3'.                                                                                                                                                         |
| `openphish_feed_name`                           | `OPENPHISH_ACCESS_FEED_NAME`                    | Yes       | The name of the feed to download.                                                                                                                                                                                                                 |
| `openphish_access_key_id`                       | `OPENPHISH_ACCESS_KEY_ID`                       | Yes       | The API access key id required for authentication with API Requests.                                                                                                                                                                              |
| `openphish_access_key_secret`                   | `OPENPHISH_ACCESS_KEY_SECRET`                   | Yes       | The API access key secret required for authentication with API Requests.                                                                                                                                                                          |
| `openphish_organizations_marking_definitions`   | `OPENPHISH_ORGANIZATIONS_MARKING_DEFINITIONS`   | Yes       | The marking definition type(s) to assign to organizations created by the connector. Format is a String with each marking separated with a comma. No spaces between values. An empty string will result in no marking definitions being applied.   |
| `openphish_attack_patterns_marking_definitions` | `OPENPHISH_ATTACK_PATTERNS_MARKING_DEFINITIONS` | Yes       | The marking definition type(s) to assign to attack patterns created by the connector. Format is a String with each marking separated with a comma. No spaces between values. An empty string will result in no marking definitions being applied. |
| `openphish_relationships_marking_definitions`   | `OPENPHISH_RELATIONSHIPS_MARKING_DEFINITIONS`   | Yes       | The marking definition type(s) to assign to relationships created by the connector. Format is a String with each marking separated with a comma. No spaces between values. An empty string will result in no marking definitions being applied.   |

A playbook has been created within OpenCTI that is used to apply marking definitions to entities created by this connector as by default there are no marking definitions being applied to objects created by the connector.

## Usage
OpenPhish has different subscription levels for accessing their phishing feed data. The different subscription levels correspond to how frequently OpenPhish updates the phishing feeds.
And how long the feed data is stored for. Currently, this connector uses the "Premium Gov" subscription level which update frequency is 4 hours. Since the phishing feed data for this 
subscription level is updated every 4 hours, the connector is configured to run at an interval at least ever 4 hours. By default, the connector runs on an interval of 3 hours, to reduce 
the likelihood that any data is missed. As a result, some the data may be uploaded more than one time, but the OpenCTI platform will deduplicate any data that this happens to.
