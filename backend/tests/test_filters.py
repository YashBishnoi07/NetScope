import pytest

from netscope.filters import sanitize_bpf_filter


def test_sanitize_bpf_filter_accepts_valid_input() -> None:
    assert sanitize_bpf_filter("tcp and port 443") == "tcp and port 443"


def test_sanitize_bpf_filter_rejects_invalid_input() -> None:
    with pytest.raises(ValueError):
        sanitize_bpf_filter("tcp && exec")
