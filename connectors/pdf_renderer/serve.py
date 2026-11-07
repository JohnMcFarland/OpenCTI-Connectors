"""Entry point: run the pdf-renderer app under uvicorn.

The __main__ guard matters: forkserver workers re-import the main module, and
must not start a second server.
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, log_level="info")
