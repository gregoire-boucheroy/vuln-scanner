from scanner.service_detection import (
    extract_http_server_header,
    extract_http_version,
    extract_ssh_version,
)


def test_extract_ssh_version_from_openssh_banner():
    banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    version = extract_ssh_version(banner)

    assert version == "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"


def test_extract_ssh_version_returns_none_for_invalid_banner():
    banner = "INVALID_BANNER"
    version = extract_ssh_version(banner)

    assert version is None


def test_extract_http_server_header():
    response = (
        "HTTP/1.1 200 OK\r\n"
        "Date: Tue, 18 Mar 2026 12:00:00 GMT\r\n"
        "Server: nginx/1.18.0\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
    )

    server_header = extract_http_server_header(response)

    assert server_header == "nginx/1.18.0"


def test_extract_http_server_header_returns_none_if_missing():
    response = (
        "HTTP/1.1 200 OK\r\n"
        "Date: Tue, 18 Mar 2026 12:00:00 GMT\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
    )

    server_header = extract_http_server_header(response)

    assert server_header is None


def test_extract_http_version_from_nginx_header():
    server_header = "nginx/1.18.0"
    version = extract_http_version(server_header)

    assert version == "1.18.0"


def test_extract_http_version_from_apache_header():
    server_header = "Apache/2.4.52"
    version = extract_http_version(server_header)

    assert version == "2.4.52"


def test_extract_http_version_returns_none_if_no_version():
    server_header = "nginx"
    version = extract_http_version(server_header)

    assert version is None