import argparse

from scanner.port_scanner import scan_ports
from scanner.service_detection import detect_service
from scanner.report import generate_report, save_report


def parse_ports(ports_str: str) -> list[int]:
    return [int(port.strip()) for port in ports_str.split(",") if port.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Mini vulnerability scanner")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--ports", required=True, help="Comma-separated ports, e.g. 22,80,443")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--output", help="Output file (JSON report)")

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    results = scan_ports(args.target, ports, args.timeout)

    print(f"Scan results for {args.target}")

    for result in results:
        if result.state == "open":
            result.service = detect_service(args.target, result.port, args.timeout)

        line = f"[{result.state.upper()}] {result.port}/{result.protocol}"

        if result.service:
            service_name = result.service.name
            service_version = f" ({result.service.version})" if result.service.version else ""
            line += f" -> {service_name}{service_version}"

        print(line)
    
    if args.output:
        report = generate_report(args.target, results)
        save_report(report, args.output)
        print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()