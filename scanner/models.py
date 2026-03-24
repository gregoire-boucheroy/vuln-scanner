from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServiceInfo:
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: Optional[str] = None
    score: Optional[float] = None


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: Optional[ServiceInfo] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)