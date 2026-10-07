"""Behaviour tests for system trust-store selection."""

import pytest

from auth_guide.system_trust import (
    TrustStoreOverride,
    UnsupportedTrustStoreError,
    select_system_trust_store,
)


@pytest.mark.parametrize(
    ("override", "expected_name"),
    [
        ("macos", "macos"),
        ("debian", "debian"),
        ("redhat", "redhat"),
    ],
)
@pytest.mark.anyio
async def test_explicit_trust_store_selection_uses_the_requested_supported_store(
    override: TrustStoreOverride, expected_name: str
) -> None:
    trust_store = await select_system_trust_store(override)

    assert trust_store.name == expected_name


@pytest.mark.parametrize(
    ("os_release", "expected_name"),
    [
        ({"ID": "debian"}, "debian"),
        ({"ID_LIKE": "debian ubuntu"}, "debian"),
        ({"ID": "fedora"}, "redhat"),
        ({"ID_LIKE": "rhel fedora"}, "redhat"),
    ],
)
@pytest.mark.anyio
async def test_automatic_linux_selection_uses_the_declared_distribution_family(
    os_release: dict[str, str], expected_name: str
) -> None:
    trust_store = await select_system_trust_store("auto", system_name="Linux", os_release=os_release)
    assert trust_store.name == expected_name


@pytest.mark.anyio
async def test_automatic_selection_rejects_an_unsupported_platform() -> None:
    with pytest.raises(UnsupportedTrustStoreError, match="FreeBSD"):
        await select_system_trust_store("auto", system_name="FreeBSD", os_release={})
