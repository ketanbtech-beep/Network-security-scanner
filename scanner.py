import socket
import json
import csv
import os
import argparse

from concurrent.futures import ThreadPoolExecutor

from services import get_service
from risk import get_risk
from banner import grab_banner


def parse_ports(port_range):
    try:
        start, end = map(int, port_range.split("-"))

        if start < 1 or end > 65535 or start > end:
            raise ValueError

        return range(start, end + 1)

    except ValueError:
        raise argparse.ArgumentTypeError(
            "Port range must be like 1-1000"
        )


parser = argparse.ArgumentParser(
    description="Network Security Scanner"
)

parser.add_argument(
    "target",
    help="Target IP address"
)

parser.add_argument(
    "--ports",
    default="1-1000",
    type=parse_ports,
    help="Port range, example: 1-1000"
)

args = parser.parse_args()

target = args.target
ports = args.ports


try:
    socket.inet_aton(target)
except OSError:
    print("[!] Invalid IP address.")
    exit(1)


print("\n" + "=" * 60)
print("             NETWORK SECURITY SCANNER")
print("=" * 60)
print(f"Target: {target}")
print("-" * 60)


def scan_port(port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.5)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:

            service = get_service(port)
            risk = get_risk(port)

            banner = grab_banner(target, port)

            return {
                "port": port,
                "service": service,
                "risk": risk,
                "banner": banner[:200]
            }

    except socket.error:
        pass

    finally:
        sock.close()

    return None


open_ports = []

with ThreadPoolExecutor(max_workers=100) as executor:

    results = executor.map(scan_port, ports)

    for result in results:

        if result:

            open_ports.append(result)

            print(
                f"Port {result['port']:<5} | "
                f"Service: {result['service']:<12} | "
                f"Risk: {result['risk']}"
            )

            if result["banner"] != "No banner information available":
                print(
                    f"  Banner: "
                    f"{result['banner'][:100]}"
                )


print("-" * 60)

high = sum(
    1 for item in open_ports
    if item["risk"] == "HIGH"
)

medium = sum(
    1 for item in open_ports
    if item["risk"] == "MEDIUM"
)

low = sum(
    1 for item in open_ports
    if item["risk"] == "LOW"
)


print(f"Open Ports : {len(open_ports)}")
print(f"High Risk  : {high}")
print(f"Medium Risk: {medium}")
print(f"Low Risk   : {low}")


os.makedirs("reports", exist_ok=True)


json_report = {
    "target": target,
    "open_ports": open_ports,
    "summary": {
        "total_open": len(open_ports),
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low
    }
}


with open("reports/scan.json", "w") as file:
    json.dump(
        json_report,
        file,
        indent=4
    )


with open(
    "reports/scan.csv",
    "w",
    newline=""
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=[
            "port",
            "service",
            "risk",
            "banner"
        ]
    )

    writer.writeheader()
    writer.writerows(open_ports)


print("-" * 60)
print("Reports saved:")
print("  reports/scan.json")
print("  reports/scan.csv")
print("=" * 60)
print("Scan completed.")
