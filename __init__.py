# Copyright (c) 2026. All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""SOC Alert Triage Environment package exports."""

from typing import Any

from .server.models import (
    SocAlertAction,
    SocAlertObservation,
    SocAlertState,
)

__all__ = [
    "SocAlertAction",
    "SocAlertObservation",
    "SocAlertState",
    "SocAlertTriageEnv",
]


def __getattr__(name: str) -> Any:
    if name == "SocAlertTriageEnv":
        from .client import SocAlertTriageEnv as _SocAlertTriageEnv

        return _SocAlertTriageEnv
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
