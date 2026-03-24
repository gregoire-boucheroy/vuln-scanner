from scanner.models import ServiceInfo, Vulnerability


MOCK_CVE_DB = {
    "openssh": [
        Vulnerability(
            cve_id="CVE-2020-14145",
            description="OpenSSH vulnerable to information exposure in certain configurations.",
            severity="medium",
            score=5.3,
        ),
        Vulnerability(
            cve_id="CVE-2021-41617",
            description="OpenSSH privilege escalation vulnerability in some environments.",
            severity="high",
            score=7.0,
        ),
    ],
    "nginx": [
        Vulnerability(
            cve_id="CVE-2021-23017",
            description="1-byte memory overwrite in resolver component.",
            severity="high",
            score=7.7,
        )
    ],
    "apache": [
        Vulnerability(
            cve_id="CVE-2021-41773",
            description="Path traversal and file disclosure vulnerability.",
            severity="critical",
            score=9.8,
        )
    ],
}


def normalize_product_name(service: ServiceInfo) -> str | None:
    if not service.version and not service.banner and not service.name:
        return None

    candidates = [
        (service.version or "").lower(),
        (service.banner or "").lower(),
        (service.name or "").lower(),
    ]

    if any("openssh" in value for value in candidates):
        return "openssh"
    if any("nginx" in value for value in candidates):
        return "nginx"
    if any("apache" in value for value in candidates):
        return "apache"

    return None


def find_cves(service: ServiceInfo) -> list[Vulnerability]:
    product = normalize_product_name(service)
    if not product:
        return []

    return MOCK_CVE_DB.get(product, [])