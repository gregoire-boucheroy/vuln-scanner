import re
import socket
from typing import Optional

from scanner.models import ServiceInfo


def detect_service(target: str, port: int, timeout: float = 1.0) -> Optional[ServiceInfo]:
    """
    Detect a service running on an open port.
    Current V1 supports:
    - SSH banner grabbing
    - HTTP header inspection
    """
    if port == 22:
        return detect_ssh_service(target, port, timeout)

    if port in (80, 8080):
        return detect_http_service(target, port, timeout)

    return None


def detect_ssh_service(target: str, port: int = 22, timeout: float = 1.0) -> Optional[ServiceInfo]:
    """
    Connect to an SSH service and read its banner.
    Example banner:
    SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()

        if not banner:
            return ServiceInfo(name="ssh", banner=None)

        version = extract_ssh_version(banner)

        return ServiceInfo(
            name="ssh",
            version=version,
            banner=banner,
        )

    except socket.error:
        return None
    finally:
        sock.close()


def detect_http_service(target: str, port: int = 80, timeout: float = 1.0) -> Optional[ServiceInfo]:
    """
    Connect to an HTTP service, send a HEAD request, and parse the Server header.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Connection: close\r\n\r\n"
    )

    try:
        sock.connect((target, port))
        sock.sendall(request.encode())

        response = sock.recv(4096).decode(errors="ignore")
        if not response:
            return ServiceInfo(name="http", banner=None)

        server_header = extract_http_server_header(response)
        version = extract_http_version(server_header) if server_header else None

        return ServiceInfo(
            name="http",
            version=version,
            banner=server_header or response.splitlines()[0],
        )

    except socket.error:
        return None
    finally:
        sock.close()


def extract_ssh_version(banner: str) -> Optional[str]:
    """
    Extract version information from an SSH banner.
    Example:
    SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5 -> OpenSSH_8.2p1
    """
    match = re.search(r"SSH-\d+\.\d+-(.+)", banner)
    if match:
        return match.group(1).strip()
    return None


def extract_http_server_header(response: str) -> Optional[str]:
    """
    Extract the Server header from an HTTP response.
    """
    for line in response.splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return None


def extract_http_version(server_header: str) -> Optional[str]:
    """
    Try to extract version info from a Server header.
    Example:
    nginx/1.18.0 -> 1.18.0
    Apache/2.4.52 -> 2.4.52
    """
    match = re.search(r"/([\w\.\-]+)", server_header)
    if match:
        return match.group(1)
    return None