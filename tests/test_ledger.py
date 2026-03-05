"""Tests for the hash-chained audit ledger."""

from src.models.database import compute_hash


def test_hash_deterministic():
    data = {"action": "APPROVE", "system": "test", "score": 85}
    h1 = compute_hash(data)
    h2 = compute_hash(data)
    assert h1 == h2


def test_hash_changes_with_data():
    h1 = compute_hash({"action": "APPROVE"})
    h2 = compute_hash({"action": "BLOCK"})
    assert h1 != h2


def test_hash_is_sha256():
    h = compute_hash({"test": True})
    assert len(h) == 64  # SHA-256 hex digest length
    assert all(c in "0123456789abcdef" for c in h)


def test_chain_integrity():
    """Verify that chained hashes form an immutable sequence."""
    genesis = compute_hash({"genesis": True})
    record1 = compute_hash({"record": 1, "previous_hash": genesis})
    record2 = compute_hash({"record": 2, "previous_hash": record1})

    # Tampering with record1 should break the chain
    tampered = compute_hash({"record": 1, "previous_hash": genesis, "tampered": True})
    assert tampered != record1
    # Record2 depends on record1, so if record1 changes, record2 is invalid
    record2_with_tampered = compute_hash({"record": 2, "previous_hash": tampered})
    assert record2_with_tampered != record2
