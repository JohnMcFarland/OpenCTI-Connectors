# Silent Push connector

An OpenCTI `EXTERNAL_IMPORT` connector that brings two kinds of Silent Push data
into OpenCTI as observables. Each kind is a separate **stream** with its own
Report:

| Stream | What it is | Report |
| --- | --- | --- |
| **IOFA** | Silent Push's own **Indicators of Future Attack**: domains and IPs it judges to be attacker infrastructure, often before they are used. 195 global feeds, about 2 million indicators | `Silent Push IOFA \| <feed> \| <date> <time> UTC` |
| **OSINT** | The **open-source threat feeds** Silent Push collects and enriches, such as CINS Army, Green Snow, Rutgers, blocklist.de and TweetFeed. 28 feeds, of which 8 are excluded by default | `Silent Push OSINT \| <feed> \| <date> <time> UTC` |

Twice a day each stream checks for indicators that are new since its last run,
and sends only those to OpenCTI.

- **What it ingests:** Domain-Name and IPv4-Addr observables from IOFA. Domain-Name,
  IPv4-Addr, IPv6-Addr and URL observables from OSINT.
- **How often:** every 12 hours, at 00:00 and 12:00 UTC. Both streams run in
  each slot, one after the other.
- **How it groups them:** one `observable-feed` Report per source feed per
  stream per run, holding only that feed's new observables. A value listed in
  several feeds is in each of their Reports.
- **First run:** IOFA records what already exists and ingests nothing. OSINT
  takes the last 24 hours (`OSINT_INITIAL_LOOKBACK_HOURS`).
- **Every later run:** only what is new since the previous successful run.
- **Independent:** each stream has its own work item and state file. One failing
  does not stop the other, and either can be switched off.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [How a run works](#how-a-run-works)
- [What gets created in OpenCTI](#what-gets-created-in-opencti)
- [State](#state)
- [API quota](#api-quota)
- [Failure handling](#failure-handling)
- [Logs and monitoring](#logs-and-monitoring)
- [Scope and limitations](#scope-and-limitations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Requirements

- OpenCTI 6.9 (built against `pycti==6.9.13`).
- A Silent Push **Enterprise** subscription with API access, IOFA Exports and
  Feed Scan.
- The TLP marking you configure must already exist on the platform.
  `TLP:AMBER` is the default because this is a paid feed.
- A persistent Docker volume for the connector's state, about 50 MB to start.
- Outbound HTTPS to `api.silentpush.com`, `app.silentpush.com` and
  `silentpush-feeds.s3.amazonaws.com`.
- A few hundred MB of memory during a run.

## Installation

### Docker Compose (recommended)

1. In the Silent Push console, create an API key under
   **Organization > API Keys**.
2. In OpenCTI, create a user for the connector with the **Connector** role and
   copy its token. Generate a UUID for `CONNECTOR_SILENT_PUSH_ID`.
3. Put the secrets in a `.env` file next to `docker-compose.yml`. Do not commit
   it.

   ```
   OPENCTI_URL=http://opencti:8080
   OPENCTI_TOKEN=<OpenCTI connector token>
   CONNECTOR_SILENT_PUSH_ID=<UUID>
   SILENT_PUSH_API_KEY=<Silent Push API key>
   ```

4. Build and start it:

   ```bash
   docker compose up -d --build
   ```

The compose file attaches the named volume `silent-push-state` at `/data`. If
your OpenCTI runs in another compose project, add the connector to that
project's network so `OPENCTI_URL` resolves.

### Running without Docker

```bash
cd src
pip install -r requirements.txt
cp config.yml.sample config.yml   # then fill in the values
python main.py
```

Set `state_dir` to a directory that survives restarts. Environment variables
override `config.yml`.

## Configuration

Each setting can be given as an environment variable or in `src/config.yml`.

### OpenCTI and connector

| Variable | `config.yml` | Default | Purpose |
| --- | --- | --- | --- |
| `OPENCTI_URL` | `opencti.url` | required | OpenCTI base URL |
| `OPENCTI_TOKEN` | `opencti.token` | required | Token of the connector's OpenCTI user |
| `CONNECTOR_ID` | `connector.id` | required | Unique UUID for this connector instance |
| `CONNECTOR_TYPE` | `connector.type` | `EXTERNAL_IMPORT` | Do not change |
| `CONNECTOR_NAME` | `connector.name` | `Silent Push` | Name shown in OpenCTI |
| `CONNECTOR_SCOPE` | `connector.scope` | `silent-push` | Connector scope |
| `CONNECTOR_LOG_LEVEL` | `connector.log_level` | `info` | `debug`, `info`, `warn` or `error` |

### Silent Push

| Variable | `config.yml` | Default | Purpose |
| --- | --- | --- | --- |
| `SILENT_PUSH_API_KEY` | `silent_push.api_key` | required | Sent as the `x-api-key` header to Silent Push only, never to S3 |
| `SILENT_PUSH_TLP` | `silent_push.tlp` | `TLP:AMBER` | Marking on everything created, for both streams. Looked up on the platform; the connector will not start if it is missing |
| `SILENT_PUSH_CONFIDENCE` | `silent_push.confidence` | `70` | Confidence on Reports, entities, Notes and relationships |
| `SILENT_PUSH_INTERVAL_HOURS` | `silent_push.interval_hours` | `12` | Run spacing. Runs land on UTC multiples of this, so use a divisor of 24 |
| `SILENT_PUSH_RUN_ON_STARTUP` | `silent_push.run_on_startup` | `true` | Also run at start, instead of waiting for the next slot |
| `SILENT_PUSH_IOFA_ENABLED` | `silent_push.iofa_enabled` | `true` | Run the IOFA stream |
| `SILENT_PUSH_OSINT_ENABLED` | `silent_push.osint_enabled` | `true` | Run the OSINT stream |
| `SILENT_PUSH_ENRICH_BATCH_BUDGET` | `silent_push.enrich_batch_budget` | `60` | Most IOFA enrichment API calls per run. Keep `budget x runs per day` within your quota share |
| `SILENT_PUSH_OSINT_INITIAL_LOOKBACK_HOURS` | `silent_push.osint_initial_lookback_hours` | `24` | How far back OSINT's first run reaches. Later runs ignore it |
| `SILENT_PUSH_OSINT_EXCLUDE_FEEDS` | `silent_push.osint_exclude_feeds` | see below | Comma-separated open-source feed names to leave out |
| `SILENT_PUSH_STATE_DIR` | `silent_push.state_dir` | `/data` | Where the state files live. Must be persistent |

`OSINT_EXCLUDE_FEEDS` defaults to the feeds that duplicate connectors you are
likely to run directly:
`UrlHaus,FeodoTracker,ThreatFox Official Recent Domains,ThreatFox Recent IPs,ThreatFox Recent URLs,OpenPhish,AlienVault Domain,AlienVault IP`.
Set it to an empty value to take every open-source feed.

## How a run works

At each slot the IOFA stream runs, then the OSINT stream.

### IOFA stream

1. **Download the exports.** The connector fetches
   `GET /api/v1/export/iofa-exports/all_iofas_domains.txt/` and
   `.../all_iofas_ips.txt/`. Silent Push answers with a redirect to a signed,
   short-lived S3 link. The connector checks that the link is HTTPS on
   `silentpush-feeds.s3.amazonaws.com` and downloads it without the API key.
   The two files hold about 2 million bare values and cost one quota request
   each.
2. **Find what is new.** Each value is compared with the state file
   `seen_iofa.txt`. Values already handled are dropped. A value that leaves the
   export and later returns is not treated as new.
3. **Load the feed catalogue.** `GET /api/v1/feeds/` gives feed names and
   tags. Only feeds with category `iofa` are used. This step is skipped when
   nothing is new.
4. **Enrich the new values.** They are shuffled and split into batches of up to
   100 domains (`POST /api/v1/enrich/domain/bulk/`) or 200 IPs
   (`POST /api/v1/enrich/ipv4/bulk/`). Domain and IP batches alternate so
   neither type crowds out the other. A run makes at most
   `ENRICH_BATCH_BUDGET` calls, and the rest wait for the next run.
5. **Build STIX.** Each value becomes an observable with its score, listing
   dates, source feeds and, for IPs, its ASN and country. Values from threat
   actor, C2 framework or botnet feeds are linked to an entity (see below).
6. **Send and record**, as described below.

### OSINT stream

1. **Find the open-source vendors.** The feed catalogue lists the feeds with
   category `open_source` and their vendors.
2. **Work out the window.** On the first run it starts
   `OSINT_INITIAL_LOOKBACK_HOURS` ago. After that it starts when the previous
   successful run started, less a one-hour overlap for clock skew and late
   timestamps. The start of each successful run is kept in the connector's
   platform state (`osint_last_run`).
3. **Pull the window through Feed Scan.** Open-source feeds have no export
   file. The connector queries `POST /app/v1/feed-scan/query-data/` with
   `datasource = ["FEED"] AND feed_scope = ["GLOBAL"] AND vendor = [...] AND first_seen_on >= "now-<N>d"`,
   sorted newest first, 1,000 rows per page. Feed Scan only accepts whole-day
   windows, so the connector pages until it passes the exact start time and
   stops. Rows arrive already enriched, so no enrichment calls are needed.
4. **Filter.** Rows not in the `open_source` category, and rows from
   `OSINT_EXCLUDE_FEEDS`, are dropped. A value listed in several feeds becomes
   one observable that names every feed.
5. **Drop repeats.** Each value is compared with `seen_osint.txt`, so the
   overlap, and values a feed re-adds with a fresh timestamp, are never
   ingested twice.
6. **Build STIX.** Each value becomes an observable with its score, source feeds
   and vendors, and for IPv4 its ASN and country.
7. **Send and record**, as described below. The window's start moves forward
   only after every bundle is sent.

### Sending and recording

Objects go to OpenCTI in bundles of up to 1,000. Each bundle carries its own
copy of every feed Report it touches, holding that bundle's observables for
that feed, so OpenCTI can process them in any order and merges the refs. Values are appended to the stream's state file only
after their bundle is sent.

A stream that finds nothing new creates no Report.

### Report naming

Each Report is named for its stream, source feed and slot (SP-FEED-REPORTS-V1),
for example:

- `Silent Push IOFA | Threat Actor - FIN7 Domains | 2026-11-07 12:00 UTC`
- `Silent Push OSINT | CINS Army List IP | 2026-11-07 12:00 UTC`

Values with no named feed go to `Silent Push <stream> | unattributed | <slot>`.
Feed names are folded to ASCII in the Report name.
Silent Push splits some large feeds into numbered parts (`Bulletproof Hosting IPs
Part 3`). Parts share their base feed's Report (`SP-FEED-PARTS-V1`); each
observable's description still names the exact part.

**Contents are observables only.** Relationships, Autonomous Systems,
Countries, feed entities (Intrusion Set, Tool, Malware) and author identities
are sent in the same bundle but are not Report members, which keeps each
Report small enough for OpenCTI's container views. Those edges remain on each
observable.

`published` is the slot's start time, so a run restarted within the same slot
adds to the same Report rather than creating a second one.

## What gets created in OpenCTI

IOFA objects are authored by the **Silent Push** Organization identity. OSINT
observables are authored by the **original feed's publisher** (the feed
`vendor` of the earliest listing, e.g. CINS or Green Snow), because the author
is the source of the information; Silent Push still authors the enrichment it
adds (Autonomous System, Country) and the Report. Publishers that are people,
such as the TweetFeed author, are Individuals (`INDIVIDUAL_VENDORS` in
`stix_builder.py`). Authorship is `createdBy` only: no observable is linked to
its author by a relationship, and author identities are sent in the bundle so
`createdBy` resolves but are not part of the Report's contents.
Everything is marked with the configured TLP. No Indicators are created
(`x_opencti_create_indicator` is off), so promotion to Indicators stays with
your platform's own rules. No Labels are applied, because feed names are not
collection requirements.

### IOFA stream

| Silent Push data | OpenCTI |
| --- | --- |
| Export value (domain) | Domain-Name observable |
| Export value (IPv4) | IPv4-Addr observable |
| `sp_risk_score` | Observable score (`x_opencti_score`, 0-100) |
| Feed names, feed tags, first and last listed dates | Observable description |
| `asn`, `asname` (IPv4 only) | Autonomous System, `belongs-to` from the IP |
| `ip_location.country_code` (IPv4 only) | Country, `located-at` from the IP |
| Threat actor and APT feeds | Intrusion Set, `related-to` from the observable |
| C2 framework and RMM feeds | Tool, `related-to` from the observable |
| Botnet and traffic distribution system feeds | Malware, `related-to` from the observable |
| Each run | One `observable-feed` Report per source feed, containing that feed's observables |

Relationships carry the date the value was first listed in that feed as their
start time. A value listed in both the Domain and IP feed of a pair gets one
edge to the shared entity, from the earlier listing.

### OSINT stream

| Feed Scan data | OpenCTI |
| --- | --- |
| `indicator` with `type` `domain` | Domain-Name observable |
| `indicator` with `type` `ip` | IPv4-Addr or IPv6-Addr observable |
| `indicator` with `type` `url` | URL observable |
| `sp_risk_score` (highest across its feeds) | Observable score (`x_opencti_score`, 0-100) |
| `feed`, `vendor`, `first_seen_on`, `last_seen_on`, tags | Observable description, such as `Listed in open-source feeds collected by Silent Push: CINS Army List IP (CINS)` |
| `asn`, `asname` (IPv4 only) | Autonomous System, `belongs-to` from the IP |
| `ip_location.country_code` (IPv4 only) | Country, `located-at` from the IP |
| Each run | One `observable-feed` Report per source feed, containing that feed's observables |

OSINT values are not linked to Intrusion Sets, Tools or Malware: these
feeds carry no attribution.

**Open-source feeds.** As of November 2026, 13 of the 28 return data through
Feed Scan:

| Vendor | Feeds | Size |
| --- | --- | --- |
| AlienVault | AlienVault IP, AlienVault Domain (excluded by default) | ~29,000, almost all refreshed daily |
| CINS | CINS Army List IP | ~15,000 |
| Daniel López | TweetFeed Domains, IPs, URLs | ~7,800 |
| Green Snow | Green Snow | ~3,600 |
| Rutgers | Rutgers | ~1,900 |
| blocklist.de | BlockListIP | ~1,200 |
| Emerging Threat | Emerging Threat IP | ~500 |
| OpenPhish | OpenPhish (excluded by default) | ~300 |
| Greynoise | CVE-2021-44228 log4j scanning IPs | ~150 |
| MalSilo, Bot Scout, mitchell krogza | small lists | under 20 each |

The abuse.ch feeds (UrlHaus, FeodoTracker, ThreatFox), HybridAnalysis, Maltrail,
MiraiTracker, Rescure and CyberCure were empty in Feed Scan when tested. The
connector queries every open-source vendor in the catalogue, so they are picked
up if Silent Push starts populating them.

### IOFA entities

The entity comes from the feed's name. The trailing "Domains" or "IPs" is
dropped so both feeds of a pair map to the same entity. New feeds that follow
the same naming patterns are picked up without a code change.

**Intrusion Sets (28).** Feeds named `Threat Actor - <name>` or
`APT - <name>` create the Intrusion Set `<name> (SilentPush)`. The suffix keeps
Silent Push's attribution apart from intrusion sets you curate yourself.

98Shield, APT28, APT34/OilRig, APT35/Charming Kitten, APT42, COLDRIVER,
DriveSurge, FIN6, FIN7, Gamaredon, Ghostwriter, HellHounds, Huione Group, IVAN,
Kimsuky, Lazarus, Moonstone Sleet, Patchwork,
Pointe Fisher (Suspected UAC-0195 / UNC5792), PoisonSeed,
Salt Typhoon / UNC4841, Sapphire Sleet, Scattered Lapsus$ Hunters (SLSH),
Silver Dragon, Storm-1679 Disinformation, UAC-0195, Verb0, la02.

Names are kept as Silent Push writes them, apart from correcting "Fin7" to
"FIN7". So `Pointe Fisher (Suspected UAC-0195 / UNC5792) (SilentPush)` and
`UAC-0195 (SilentPush)` are separate Intrusion Sets; merge them in OpenCTI if
you treat them as one.

**Tools (5).** Dual-use software attackers run, which the data model classes as
Tool. Created without a suffix.

| Feed | Tool |
| --- | --- |
| Cobaltstrike C2 | Cobalt Strike |
| Sliver C2 | Sliver |
| Havoc C2 | Havoc |
| Adaptix C2 | Adaptix |
| Screen Connect RMM leveraged by Threat Actors | ScreenConnect |

**Malware (5).** Created as malware families, without a suffix.

| Feed | Malware |
| --- | --- |
| Botnet - Nosviak4 C2 | Nosviak4 |
| Botnet - Socks5Systemz | Socks5Systemz |
| Botnet API - TCPSYN | TCPSYN |
| Keitaro C2 | Keitaro |
| zTDS C2 | zTDS |

Every other IOFA feed, such as bulletproof hosting, phishing and infostealer
feeds (including `Infostealer - Lumma C2`), gives observables with no entity.
Their feed names still appear in the observable description.

An entity appears only once an indicator from its feed arrives. Small feeds can
take weeks to show up.

**Assessment Notes.** Each Intrusion Set, Tool and Malware gets an Assessment
Note saying the link is Silent Push's own attribution, that it has not been
independently verified, and that IOFA entries are predictive. The Note is
written once and reused on later runs.

### What is skipped

- Values Silent Push marks as benign (`benign_info.known_benign`) or sinkholed
  (`sinkhole_info.known_sinkhole_ip`, `ns_reputation.is_sinkholed`,
  `ip_flags.is_sinkhole`).
- Values that are not a valid domain, IP address or http(s) URL, or whose type
  does not match what the source says it is.
- OSINT rows from excluded feeds or outside the `open_source` category.

Benign, sinkholed and unbuildable values are recorded as handled and not looked
at again.

## State

The OSINT cursor lives in the connector's platform state, like every other
connector in this repository. Only the seen-value sets stay on disk in
`STATE_DIR`, because about two million values do not fit in connector state:

| Where | Stream | Holds |
| --- | --- | --- |
| `seen_iofa.txt` | IOFA | Every value handled. Starts at about 30 MB, grows by up to what the enrichment budget covers: at the defaults, roughly 12,000 to 24,000 lines a day |
| `seen_osint.txt` | OSINT | Every value handled. Grows by the number of new OSINT values |
| platform state `osint_last_run` | OSINT | When the last successful OSINT run started |

The value files are append-only, flushed to disk after each bundle, and survive
a partial line left by a crash. A value that drops off a feed and later returns
is not ingested again.

**IOFA has no backlog.** Its exports carry no dates, so with no state file the
first run saves the current export as a baseline and ingests nothing. If
`seen_iofa.txt` is lost, the next run saves a new baseline, and anything added
in between is never ingested. Watch for the
`No state file: saved a baseline and ingested nothing` warning on any run after
the first.

**OSINT works from time.** With no `osint_last_run` in connector state, it takes the last
`OSINT_INITIAL_LOOKBACK_HOURS` and logs `No OSINT cursor: taking the initial
lookback window`. If the connector is down for days, the next run reaches back
to the last successful run, however long ago.

**Keep the volume.** To start a stream over on purpose, stop the connector and
delete that stream's files.

## API quota

Silent Push allows 15,000 API requests a month, **shared across your whole
organisation**. You can check the balance with `GET /api/v1/users-quota/`.

| Use | Requests |
| --- | --- |
| IOFA export downloads | 2 per run, 4 a day |
| Feed catalogue | A few per run |
| IOFA enrichment | Early estimate from a 1% sample was 50-90 a day. Live, on 2026-11-08 one run found 24,355 new values, far more than the budget covers, so the ceiling below is what is actually spent |
| IOFA enrichment ceiling | `ENRICH_BATCH_BUDGET` per run: 60 x 2 = 120 a day, about 3,600 a month at the defaults |
| OSINT Feed Scan | One request per 1,000-row page. With the default exclusions a 24-hour window was about 11 pages in November 2026: about 6 per 12-hour run, 11 a day, about 330 a month |

An IOFA enrichment call that comes back empty is retried up to twice more, so a
bad run can use up to three times the budget. Lower `ENRICH_BATCH_BUDGET` if
other teams need more of the quota. Values that do not fit wait for later runs,
so a lower budget delays ingestion but loses nothing.

## Failure handling

| Situation | What happens |
| --- | --- |
| Silent Push returns 429 or 5xx | Retried up to 3 times with backoff, honouring `Retry-After` |
| Other 4xx, such as an invalid key | That stream's run fails and is marked in error in OpenCTI. Nothing is recorded as handled |
| One stream fails | The other stream still runs in the same slot |
| Export redirect is not HTTPS on the expected S3 host | The IOFA run fails. The link is never followed |
| Export is truncated or has fewer than 1,000 lines | The IOFA run fails, so a broken file cannot become a baseline or hide additions |
| Feed catalogue has no IOFA, or no open-source, feeds | That stream fails, rather than ingesting without attribution |
| Feed Scan returns rows that are not newest first, or without a date | The OSINT run fails, because stopping at the window's start would no longer be safe |
| Feed Scan returns no rows for the window | Logged as a warning. The window's start does not move, so the next run reads it again |
| An IOFA enrichment batch comes back empty | That batch waits for the next run. After 3 empty batches in a row the run stops early |
| IOFA enrichment answers, but no row matches any value sent | The IOFA run fails. This points to a change in Silent Push's response format |
| IOFA enrichment answers some values but not others | The missing ones are ingested bare, with no score or feed context |
| Sending a bundle to OpenCTI fails | That stream's run fails. Values from that bundle are not recorded and are retried next run |

Each stream's run appears in **Data > Ingestion > Connectors > Silent Push** as
its own work item, named for example `Silent Push OSINT 2026-11-07 12:00 UTC`.

## Logs and monitoring

The connector logs one line per stream per run, with a `stream` field of
`IOFA` or `OSINT`:

- `Silent Push run complete`, with counts. Both streams report:
  - `new`: values not seen before.
  - `ingested`: values sent to OpenCTI.
  - `benign_or_sinkhole_skipped` and `unusable_skipped`: values dropped.

  IOFA also reports `no_enrichment_row`, `batches_deferred` and
  `carried_over` (values left for the next run). OSINT also reports `since`
  (the window's start), `rows` pulled, `values` after grouping,
  `excluded_feed_rows` and `unusable_rows`.
- `Silent Push run failed`, with the stream and error. The signed S3 link is
  never included in errors.
- `No state file: saved a baseline and ingested nothing`, on IOFA's first
  run or after its state was lost.
- `No OSINT cursor: taking the initial lookback window`, on OSINT's first run.
- `Feed Scan returned no OSINT rows; cursor not moved`, when a window is empty.

An IOFA `carried_over` count that keeps growing means the budget is too low for
the volume of additions.

## Scope and limitations

- **IOFA and open-source feeds only.** Your organisation's own feeds and the
  Bulk Data and Archive exports are not pulled.
- **IOFA is domains and IPv4 only.** Its exports contain no URLs, CIDRs or IPv6
  addresses.
- **OSINT relies on Feed Scan.** It is the only route to the open-source feeds,
  and it is part of Silent Push's web application API rather than its
  documented public API. If Silent Push changes it, the OSINT stream fails
  loudly and IOFA carries on.
- **OSINT volume.** A live 24-hour window in November 2026 held
  27,805 rows, 16,810 of them AlienVault and 300 OpenPhish. With those
  excluded, as by default, that leaves about 10,700 rows: roughly 9,600 IPv4
  addresses, 50 domains and 45 URLs a day, mostly from CINS, Rutgers, Green
  Snow and blocklist.de.
- **OSINT runs take minutes.** Each Feed Scan page takes about 25 seconds, so
  with the default exclusions a 24-hour first run reads for about 5 minutes,
  and a 12-hour run about 2 to 3.
- **Run frequency depends on Silent Push.** If Silent Push refreshes the IOFA
  export once a day, only one of the two daily IOFA runs finds new values; the
  other works through the carried-over backlog within its budget.
- **IOFA volume exceeds the default budget.** Live additions (24,355 in one run
  on 2026-11-08) are far above what 120 enrichment calls a day can cover, so
  `carried_over` grows. Raising the budget spends shared quota and adds
  OpenCTI load; narrowing which IOFA feeds are ingested is the alternative.
- **IOFA attribution comes from feed names.** Silent Push has no field saying
  which feeds name an actor or tool. A feed renamed outside the patterns above
  stops producing its entity, and its values still arrive without one.
- **IOFA scores do not rank.** In sampling, every IOFA value scored 100.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Connector exits at start with `marking definition not found` | The `SILENT_PUSH_TLP` marking does not exist on the platform |
| Connector exits at start with `SILENT_PUSH_API_KEY is required` | The key is not set |
| Every run fails with HTTP 401 or 403 | The key is invalid or rotated, or the subscription lacks IOFA Exports or Feed Scan |
| First run created no IOFA Report | Expected. IOFA saved its baseline |
| A run created no Report for a stream | Nothing new for that stream since the last run |
| A baseline or cursor warning on a later run | The state volume was lost or not mounted |
| IOFA `carried_over` keeps growing | Raise `ENRICH_BATCH_BUDGET`, if the quota allows |
| IOFA runs fail with `enrichment rows match none of the values sent` | Silent Push changed its enrichment response format |
| OSINT runs fail with `Feed Scan rows are not newest first` | Feed Scan's sorting changed |
| OSINT first run took a long time | Each Feed Scan page takes about 25 seconds; a 24-hour window is about 11 pages with the default exclusions. Later 12-hour windows are about half that |
| OSINT runs fail with `Field ... is not valid` | Silent Push changed Feed Scan's query fields |

## Development

```
silent_push/
├── Dockerfile
├── docker-compose.yml
├── src/
│   ├── main.py            entry point
│   ├── connector.py       schedule, both streams, budget, sending
│   ├── client.py          Silent Push API: exports, catalogue, enrichment, Feed Scan, retries
│   ├── seen_store.py      the append-only state files
│   ├── stix_builder.py    STIX objects, OSINT row handling, feed-to-entity mapping
│   ├── config.yml.sample
│   └── requirements.txt
└── tests/
```

Run the tests offline. They need no API key or OpenCTI:

```bash
pip install -r src/requirements.txt pytest
python -m pytest tests -q
```

The tests cover the client's redirect, retry and Feed Scan paging handling, the
STIX output and entity mapping, and multi-run simulations of both streams with
a moving clock, failed sends, one stream failing while the other runs, budget
carry-over and values the API never answers.
