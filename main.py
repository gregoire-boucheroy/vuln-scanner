import argparse
from scanner.port_scanner import scan_ports


def parse_ports(ports_str: str) -> list[int]:
    return [int(port.strip()) for port in ports_str.split(",") if port.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Mini vulnerability scanner")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--ports", required=True, help="Comma-separated ports, e.g. 22,80,443")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    results = scan_ports(args.target, ports, args.timeout)

    print(f"Scan results for {args.target}")
    for result in results:
        print(f"[{result.state.upper()}] {result.port}/{result.protocol}")


if __name__ == "__main__":
    main()