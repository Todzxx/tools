import pytest
import ipaddress
import logging
from network_inventory.scanner.engine import ScannerEngine


@pytest.fixture
def logger():
    return logging.getLogger("test")


@pytest.fixture
def engine(logger):
    return ScannerEngine(logger)


def test_validate_target_valid_private(engine):
    network = engine.validate_target(
        "192.168.1.0/24", allow_public=False, max_hosts=1024
    )
    assert isinstance(network, ipaddress.IPv4Network)
    assert str(network) == "192.168.1.0/24"


def test_validate_target_invalid_cidr(engine):
    with pytest.raises(ValueError, match="Invalid target"):
        engine.validate_target("192.168.1.300/24", allow_public=False, max_hosts=1024)


def test_validate_target_public_denied(engine):
    with pytest.raises(ValueError, match="Target must be a private/local network"):
        engine.validate_target("8.8.8.0/24", allow_public=False, max_hosts=1024)


def test_validate_target_public_allowed(engine):
    network = engine.validate_target("8.8.8.0/24", allow_public=True, max_hosts=1024)
    assert str(network) == "8.8.8.0/24"


def test_validate_target_too_large(engine):
    with pytest.raises(ValueError, match="exceeds safety limit"):
        engine.validate_target("10.0.0.0/16", allow_public=False, max_hosts=1024)
