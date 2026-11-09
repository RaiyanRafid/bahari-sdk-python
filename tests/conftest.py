import pytest

from helpers import FakeBahari, Keys


@pytest.fixture(scope="session")
def keys() -> Keys:
    return Keys("k1")


@pytest.fixture
def bahari(keys: Keys) -> FakeBahari:
    return FakeBahari(keys)
