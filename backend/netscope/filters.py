from __future__ import annotations


def sanitize_bpf_filter(value: str | None) -> str:
    if value is None:
        return ""
    cleaned = value.strip()
    forbidden = [";", "&&", "||", "import", "os.", "subprocess", "eval", "exec"]
    for token in forbidden:
        if token in cleaned:
            raise ValueError(f"Invalid BPF filter token: {token}")
    return cleaned
