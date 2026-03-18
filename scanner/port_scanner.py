import socket
from scanner.models import PortResult


def scan_port(target: str, port: int, timeout: float = 1.0) -> PortResult:
    result = PortResult(port=port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        status = sock.connect_ex((target, port))
        if status == 0:
            result.state = "open"
        else:
            result.state = "closed"
    except socket.gaierror:
        result.state = "error"
    except socket.error:
        result.state = "error"
    finally:
        sock.close()

    return result


def scan_ports(target: str, ports: list[int], timeout: float = 1.0) -> list[PortResult]:
    results = []

    for port in ports:
        results.append(scan_port(target, port, timeout))

    return results