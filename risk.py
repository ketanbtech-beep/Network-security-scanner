HIGH_RISK_PORTS = {
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL"
}

MEDIUM_RISK_PORTS = {
    21: "FTP",
    445: "SMB"
}


def get_risk(port):
    if port in HIGH_RISK_PORTS:
        return "HIGH"

    if port in MEDIUM_RISK_PORTS:
        return "MEDIUM"

    return "LOW"
