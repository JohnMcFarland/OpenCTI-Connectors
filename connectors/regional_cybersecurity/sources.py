from dataclasses import dataclass


@dataclass(frozen=True)
class FeedConfig:
    url: str
    label: str = ""


@dataclass(frozen=True)
class AgencySource:
    key: str
    name: str
    country: str
    feeds: tuple[FeedConfig, ...] = ()
    scraper: str = ""  # empty = feed-based; "enisa", "certin" = custom scraper
    tlp: str = ""
    report_type: str = ""
    confidence: int = 0


# ── Phase 1: Tier 1 agencies with clean RSS/Atom feeds ──────────────

SOURCES: list[AgencySource] = [
    AgencySource(
        key="cisa",
        name="Cybersecurity and Infrastructure Security Agency",
        country="United States",
        feeds=(
            FeedConfig(
                "https://www.cisa.gov/cybersecurity-advisories/all.xml",
                "advisories",
            ),
        ),
    ),
    AgencySource(
        key="ncsc_uk",
        name="National Cyber Security Centre",
        country="United Kingdom",
        feeds=(
            FeedConfig(
                "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
                "all",
            ),
        ),
    ),
    AgencySource(
        key="cccs",
        name="Canadian Centre for Cyber Security",
        country="Canada",
        feeds=(
            FeedConfig(
                "https://cyber.gc.ca/webservice/en/rss/alerts",
                "alerts",
            ),
        ),
    ),
    AgencySource(
        key="acsc",
        name="Australian Cyber Security Centre",
        country="Australia",
        feeds=(
            FeedConfig(
                "https://www.cyber.gov.au/rss/advisories",
                "advisories",
            ),
            FeedConfig(
                "https://www.cyber.gov.au/rss/alerts",
                "alerts",
            ),
        ),
    ),
    AgencySource(
        key="cert_eu",
        name="CERT-EU",
        country="European Union",
        feeds=(
            FeedConfig(
                "https://cert.europa.eu/publications/security-advisories-rss",
                "security-advisories",
            ),
            FeedConfig(
                "https://cert.europa.eu/publications/threat-intelligence-rss",
                "threat-intelligence",
            ),
        ),
    ),
    AgencySource(
        key="jpcert",
        name="JPCERT/CC",
        country="Japan",
        feeds=(
            FeedConfig(
                "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
                "alerts",
            ),
            FeedConfig(
                "https://blogs.jpcert.or.jp/en/atom.xml",
                "blog",
            ),
        ),
    ),
    AgencySource(
        key="ncsc_fi",
        name="NCSC-FI",
        country="Finland",
        feeds=(
            FeedConfig(
                "https://www.kyberturvallisuuskeskus.fi/feed/rss/en",
                "news",
            ),
        ),
    ),

    # ── Phase 2: European + APAC CERTs with English RSS ─────────────

    AgencySource(
        key="cert_pl",
        name="CERT Polska",
        country="Poland",
        feeds=(
            FeedConfig("https://cert.pl/en/rss.xml", "news"),
        ),
    ),
    AgencySource(
        key="cert_at",
        name="CERT.at",
        country="Austria",
        feeds=(
            FeedConfig(
                "https://cert.at/cert-at.en.blog.rss_2.0.xml", "blog"
            ),
        ),
    ),
    AgencySource(
        key="govcert_ch",
        name="Swiss GovCERT",
        country="Switzerland",
        feeds=(
            FeedConfig(
                "https://www.newsd.admin.ch/newsd/feeds/rss?lang=en&org-nr=1101",
                "news",
            ),
        ),
    ),
    AgencySource(
        key="cert_be",
        name="Centre for Cybersecurity Belgium",
        country="Belgium",
        feeds=(
            FeedConfig("https://ccb.belgium.be/advisories.xml", "advisories"),
            FeedConfig("https://ccb.belgium.be/news.xml", "news"),
        ),
    ),
    AgencySource(
        key="cert_lv",
        name="CERT.LV",
        country="Latvia",
        feeds=(
            FeedConfig("https://cert.lv/en/feed/rss/all", "all"),
        ),
    ),
    AgencySource(
        key="govcert_hk",
        name="GovCERT.HK",
        country="Hong Kong",
        feeds=(
            FeedConfig(
                "https://www.govcert.gov.hk/en/rss_security_alerts.xml",
                "security-alerts",
            ),
        ),
    ),

    # ── Phase 2: Scraper-based sources ──────────────────────────────

    AgencySource(
        key="enisa",
        name="ENISA",
        country="European Union",
        scraper="enisa",
    ),
    AgencySource(
        key="cert_in",
        name="CERT-In",
        country="India",
        scraper="certin",
    ),

    # ── Phase 3: Global CERTs (Europe) ─────────────────────────────

    AgencySource(
        key="cert_fr",
        name="CERT-FR",
        country="France",
        feeds=(
            FeedConfig("https://www.cert.ssi.gouv.fr/feed/", "advisories"),
        ),
    ),
    AgencySource(
        key="cert_bund",
        name="CERT-Bund",
        country="Germany",
        feeds=(
            FeedConfig(
                "https://wid.cert-bund.de/content/public/securityAdvisory/rss",
                "advisories",
            ),
        ),
    ),
    AgencySource(
        key="cert_se",
        name="CERT-SE",
        country="Sweden",
        feeds=(
            FeedConfig("https://www.cert.se/feed", "alerts"),
        ),
    ),
    AgencySource(
        key="cfcs_dk",
        name="CFCS",
        country="Denmark",
        feeds=(
            FeedConfig("https://samsik.dk/feed/", "news"),
        ),
    ),
    AgencySource(
        key="csirt_it",
        name="CSIRT Italia",
        country="Italy",
        feeds=(
            FeedConfig(
                "https://acn.gov.it/portale/feedrss/-/journal/rss/20119/723192",
                "advisories",
            ),
        ),
    ),
    AgencySource(
        key="si_cert",
        name="SI-CERT",
        country="Slovenia",
        feeds=(
            FeedConfig("https://www.cert.si/en/feed/", "news"),
        ),
    ),
    AgencySource(
        key="cert_hr",
        name="CARnet CERT",
        country="Croatia",
        feeds=(
            FeedConfig("https://www.cert.hr/feed/", "news"),
        ),
    ),
    AgencySource(
        key="govcert_bg",
        name="CERT Bulgaria",
        country="Bulgaria",
        feeds=(
            FeedConfig("https://www.govcert.bg/en/feed/", "news"),
        ),
    ),
    AgencySource(
        key="cert_ee",
        name="CERT-EE",
        country="Estonia",
        feeds=(
            FeedConfig(
                "https://www.ria.ee/en/rss-feeds/rss.xml", "news"
            ),
        ),
    ),

    # ── Phase 3: Global CERTs (Americas) ───────────────────────────

    AgencySource(
        key="cert_cc",
        name="CERT Coordination Center",
        country="United States",
        feeds=(
            FeedConfig(
                "https://www.kb.cert.org/vuls/atomfeed/",
                "vulnerability-notes",
            ),
        ),
    ),
    AgencySource(
        key="cert_br",
        name="CERT.br",
        country="Brazil",
        feeds=(
            FeedConfig("https://cert.br/rss/certbr-rss.xml", "news"),
        ),
    ),
    AgencySource(
        key="first",
        name="FIRST",
        country="International",
        feeds=(
            FeedConfig(
                "https://www.first.org/newsroom/news/rss.xml", "news"
            ),
            FeedConfig(
                "https://www.first.org/blog/rss.xml", "blog"
            ),
        ),
    ),

    # ── Phase 3: Global CERTs (Asia-Pacific) ───────────────────────

    AgencySource(
        key="cert_ua",
        name="CERT-UA",
        country="Ukraine",
        feeds=(
            FeedConfig(
                "https://cert.gov.ua/api/articles/rss", "articles"
            ),
        ),
    ),
    AgencySource(
        key="krcert",
        name="KrCERT/CC",
        country="South Korea",
        feeds=(
            FeedConfig(
                "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133",
                "security-notices",
            ),
            FeedConfig(
                "https://www.boho.or.kr/kr/rss.do?bbsId=B0000302",
                "vulnerabilities",
            ),
        ),
    ),
    AgencySource(
        key="twcert",
        name="TWCERT/CC",
        country="Taiwan",
        feeds=(
            FeedConfig(
                "https://www.twcert.org.tw/en/rss-139-2.xml", "tvn-en"
            ),
            FeedConfig(
                "https://www.twcert.org.tw/tw/rss-104-1.xml",
                "security-news",
            ),
        ),
    ),
    AgencySource(
        key="thaicert",
        name="ThaiCERT",
        country="Thailand",
        feeds=(
            FeedConfig("https://www.thaicert.or.th/feed", "alerts"),
        ),
    ),
]
