# Adding a New IC Source Plugin

This document describes how to implement a new source plugin for the
IC Reports connector. A plugin is a single Python file in `src/plugins/`.

---

## 1. Create the plugin file

```
src/plugins/your_source.py
```

## 2. Implement the BasePlugin interface

```python
from base_plugin import BasePlugin, EnrichedReport, RawReport
from http_client import build_session, fetch_pdf, safe_get
from typing import Optional

class YourSourcePlugin(BasePlugin):
    # --- Required class attributes ---
    name = "YourSource"                              # Used as config key (lowercased)
    author_name = "Full Legal Name of Publisher"    # OpenCTI Identity name
    default_marking = "TLP:WHITE"
    report_type = "threat-report"
    confidence = 80                                  # 0-100

    def __init__(self, config, state, logger):
        super().__init__(config, state, logger)
        self.session = build_session()
        self.max_per_run = self.get_config("max_per_run", 10)

    def fetch_new_reports(self) -> list[RawReport]:
        """
        Discover new reports. Choose your discovery mechanism:
        
        Option A — RSS/Atom:
            import feedparser
            feed = feedparser.parse(feed_url)
            for entry in feed.entries: ...

        Option B — HTML scraping:
            resp = safe_get(self.session, listing_url)
            soup = BeautifulSoup(resp.text, "html.parser")
            for block in soup.find_all(...): ...

        Option C — JSON API:
            resp = safe_get(self.session, api_url)
            data = resp.json()
            for item in data["results"]: ...

        Option D — Static URL list from config:
            urls = self.get_config("report_urls", [])
            for url in urls: ...

        Always check is_seen() before adding to the return list.
        """
        raw_reports = []
        # ... your discovery logic ...
        return [r for r in raw_reports if not self.is_seen(r)][:self.max_per_run]

    def enrich_report(self, raw: RawReport) -> Optional[EnrichedReport]:
        """
        Resolve a RawReport to a fully enriched EnrichedReport.
        Return None to skip ingestion for this report (e.g. 404, wrong language).

        Attempt to:
          1. Download the PDF (preferred)
          2. Resolve publication date with maximum fidelity
          3. Set labels appropriate to this source
        """
        pdf_bytes = None
        pdf_filename = None

        if raw.url.lower().endswith(".pdf"):
            pdf_bytes = fetch_pdf(self.session, raw.url)
            pdf_filename = raw.url.split("/")[-1]
        else:
            # Fetch landing page, look for PDF link
            resp = safe_get(self.session, raw.url)
            if resp:
                from bs4 import BeautifulSoup
                from urllib.parse import urljoin
                soup = BeautifulSoup(resp.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    if a["href"].lower().endswith(".pdf"):
                        pdf_url = urljoin(raw.url, a["href"])
                        pdf_bytes = fetch_pdf(self.session, pdf_url)
                        pdf_filename = pdf_url.split("/")[-1]
                        break

        return EnrichedReport(
            raw=raw,
            pdf_bytes=pdf_bytes,
            pdf_filename=pdf_filename,
            author_name=self.author_name,
            marking=self.default_marking,
            report_type=self.report_type,
            labels=["YourSource"],
            resolved_published=raw.published,
        )
```

## 3. Register the plugin

In `src/plugins/__init__.py`, add your module to `PLUGIN_MODULES`:

```python
PLUGIN_MODULES = [
    ...
    "plugins.your_source",   # Add this line
]
```

## 4. Add config block to config.yml.template

```yaml
plugins:
  yoursource:            # Must match name.lower().replace(" ", "_")
    enabled: true
    max_per_run: 10
    rate_limit_delay: 1.5
    # ... any plugin-specific config keys ...
```

## 5. Key constraints (non-negotiable)

| Constraint | Rationale |
|---|---|
| Never create Indicators | Per ingestion manual — auto-generated only |
| Author = publisher, not connector | Traceability to original source |
| Published date = source date, not ingestion date | Data integrity |
| External Reference URL = dedup key | Idempotent ingestion |
| PDF attached to Report container | Analyst can trigger workbench review |
| Report status = "Draft" on creation | Requires analyst review before promotion |
| No entities or observables created | Report-only mode; extraction is analyst's job |

## 6. Discovery mechanism guidance

| Source type | Recommended mechanism |
|---|---|
| Has RSS/Atom feed | `feedparser` — always prefer structured feeds |
| JSON API available | Direct API calls — most reliable |
| Listing page with predictable structure | BeautifulSoup scraping + change detection |
| Infrequent, known URLs | Static URL list in config |
| FOIA-style search | API/form POST with search terms from config |

## 7. Rate limiting

All plugins share `http_client.safe_get()` which enforces a per-request delay.
Set `rate_limit_delay` in config (seconds). Minimum 1.0 for .gov sites.
Never hammer .mil or .gov domains — they may block the connector IP.
