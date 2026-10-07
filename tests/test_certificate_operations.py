"""Behaviour tests for the authority's owned certificate operations boundary."""

from __future__ import annotations

import threading

import pytest

from auth_guide.certificate_operations import CertificateOperations, CertificateOperationsClosedError


@pytest.mark.anyio
async def test_certificate_operations_run_work_through_an_owned_started_worker() -> None:
    operations = CertificateOperations()

    with pytest.raises(CertificateOperationsClosedError):
        await operations.call(threading.get_ident)

    await operations.start()
    worker_thread_id = await operations.call(threading.get_ident)

    assert worker_thread_id != threading.get_ident()

    await operations.aclose()

    with pytest.raises(CertificateOperationsClosedError):
        await operations.call(threading.get_ident)
