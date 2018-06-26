import pytest


@pytest.fixture
def app():
    from server import server
    return server
