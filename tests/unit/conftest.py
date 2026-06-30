import pytest


@pytest.fixture(scope="session")
def _test_db():
    yield


@pytest.fixture(autouse=True)
def _clean_tables(_test_db):
    yield
