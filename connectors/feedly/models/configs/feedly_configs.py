from connectors_sdk import ListFromString
from models.configs import ConfigBaseSettings
from pydantic import Field, PositiveInt, SecretStr


class _ConfigLoaderFeedly(ConfigBaseSettings):
    """Interface for loading Feedly dedicated configuration."""

    interval: PositiveInt = Field(
        default=60,
        description="Polling interval in minutes.",
    )
    stream_ids: ListFromString = Field(
        default=[],
        description="Comma separated list of Feedly stream IDs to monitor.",
    )
    days_to_back_fill: PositiveInt = Field(
        default=7,
        description="Number of days to back fill for new streams.",
    )
    api_key: SecretStr = Field(
        description="Feedly API key for authentication.",
    )
    marking: str = Field(
        default="TLP:CLEAR",
        description="Marking definition to apply to all ingested objects.",
    )
    confidence: PositiveInt = Field(
        default=50,
        description="Confidence score (0-100) applied to all ingested objects.",
    )
    attach_pdf: bool = Field(
        default=True,
        description="Fetch and attach a PDF of each article to its report in OpenCTI.",
    )
    pdf_timeout: PositiveInt = Field(
        default=30,
        description="HTTP timeout in seconds when fetching article HTML for PDF rendering.",
    )
    pdf_render_timeout: PositiveInt = Field(
        default=120,
        description="Maximum seconds weasyprint may spend rendering a single article PDF. "
                    "Renders exceeding this limit are aborted and the PDF skipped.",
    )
    pdf_max_mb: PositiveInt = Field(
        default=12,
        description="Maximum PDF file size in MB. PDFs exceeding this limit are discarded.",
    )
    pdf_user_agent: str = Field(
        default="Mozilla/5.0 (compatible; Feedly-OpenCTI/1.0)",
        description="User-Agent header sent when fetching article HTML.",
    )
