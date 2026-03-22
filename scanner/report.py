import json
from typing import List

from scanner.models import PortResult


def port_result_to_dict(result: PortResult) -> dict:
    return {
        "port": result.port,
        "protocol": result.protocol,
        "state": result.state,
        "service": {
            "name": result.service.name,
            "version": result.service.version,
            "banner": result.service.banner,
        } if result.service else None,
    }


def generate_report(target: str, results: List[PortResult]) -> dict:
    return {
        "target": target,
        "ports": [port_result_to_dict(r) for r in results],
    }


def save_report(report: dict, filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)