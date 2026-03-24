from scanner.cve_lookup import find_cves, normalize_product_name
from scanner.models import ServiceInfo


def test_normalize_product_name_openssh():
    service = ServiceInfo(
        name="ssh",
        version="OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    )

    assert normalize_product_name(service) == "openssh"


def test_normalize_product_name_nginx():
    service = ServiceInfo(
        name="http",
        version="nginx/1.18.0",
        banner="nginx/1.18.0",
    )

    assert normalize_product_name(service) == "nginx"


def test_find_cves_returns_results_for_known_product():
    service = ServiceInfo(
        name="ssh",
        version="OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    )

    cves = find_cves(service)

    assert len(cves) > 0
    assert cves[0].cve_id.startswith("CVE-")


def test_find_cves_returns_empty_for_unknown_product():
    service = ServiceInfo(
        name="custom-service",
        version="1.0.0",
        banner="custom-service/1.0.0",
    )

    cves = find_cves(service)

    assert cves == []