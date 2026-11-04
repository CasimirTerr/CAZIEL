from __future__ import annotations

from pathlib import Path

import pytest

from caziel import analysis, cloud

ROOT = Path(__file__).resolve().parent.parent
FLEET = ROOT / "examples" / "harbor-fleet"
KX1 = FLEET / "robots" / "kx1"


@pytest.fixture(scope="session")
def fleet() -> cloud.Fleet:
    return cloud.load(FLEET)


@pytest.fixture(scope="session")
def report(fleet: cloud.Fleet) -> analysis.Report:
    return analysis.analyze(fleet)


@pytest.fixture(scope="session")
def model(fleet: cloud.Fleet):
    return fleet.groups[0].model
