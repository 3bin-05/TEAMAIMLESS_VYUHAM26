"""AEGIS Backend FastAPI Entrypoint."""
from api.app import app

__all__ = ["app"]

if __name__ == "__main__":
    import os
    from pathlib import Path
    import uvicorn

    host = os.getenv("AEGIS_API_HOST", "127.0.0.1")
    port = int(os.getenv("AEGIS_API_PORT", "8000"))
    backend_dir = str(Path(__file__).parent.resolve())
    uvicorn.run("main:app", host=host, port=port, reload=True, reload_dirs=[backend_dir])
