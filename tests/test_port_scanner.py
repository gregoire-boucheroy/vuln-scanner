from scanner.port_scanner import scan_port


def test_scan_port_returns_portresult():
    result = scan_port("127.0.0.1", 1, timeout=0.1)

    assert result.port == 1
    assert result.protocol == "tcp"
    assert result.state in {"open", "closed", "error"}