from __future__ import annotations

PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def service_name(port: int | None, transport: str | None = None) -> str:
    if port is None:
        return "Unknown"
    name = PORT_SERVICES.get(port, "Unknown")
    if transport == "UDP" and port == 53:
        return "DNS"
    return name
