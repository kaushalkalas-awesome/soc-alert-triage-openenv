# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
FastAPI application entry point for the SOC Alert Triage environment.

This module provides the standard server entry point used by OpenEnv tooling.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
ROOT_DIR = SERVER_DIR.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from openenv.core.env_server.http_server import create_app
except ImportError:
    from openenv.core.env_server import create_app

try:
    from ..models import SocAlertAction, SocAlertObservation
    from .environment import SocAlertTriageEnvironment
except ImportError:
    from models import SocAlertAction, SocAlertObservation
    from environment import SocAlertTriageEnvironment


def create_soc_environment() -> SocAlertTriageEnvironment:
    """Factory for per-session environment instances."""
    return SocAlertTriageEnvironment()


app = create_app(
    create_soc_environment,
    SocAlertAction,
    SocAlertObservation,
    env_name="soc_openenv",
)

from fastapi.responses import RedirectResponse
@app.get("/", include_in_schema=False)
def root_redirect():
    """Redirect root to the OpenAPI Swagger dashboard."""
    return RedirectResponse(url="/docs")


def main(host: str = "0.0.0.0", port: int | None = None):
    """Run the SOC Alert Triage environment server with uvicorn."""
    import uvicorn

    if port is None:
        port = int(os.getenv("API_PORT", "7860"))

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
