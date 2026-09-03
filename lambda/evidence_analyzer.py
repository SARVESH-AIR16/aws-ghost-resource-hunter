import json
from pathlib import Path


INVENTORY_FILE = Path("reports/raw_inventory.json")
EVIDENCE_DIR = Path("reports/evidence")
OUTPUT_FILE = Path("reports/final_ghost_report.json")


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def count_ec2_instances(data):
    return sum(
        len(reservation.get("Instances", []))
        for reservation in data.get("Reservations", [])
    )


def count_resources():
    evidence = {}

    evidence["ec2_instances"] = count_ec2_instances(
        load_json(EVIDENCE_DIR / "ec2_instances.json")
    )

    evidence["ebs_volumes"] = len(
        load_json(EVIDENCE_DIR / "ebs_volumes.json").get(
            "Volumes", []
        )
    )

    evidence["elastic_ips"] = len(
        load_json(EVIDENCE_DIR / "elastic_ips.json").get(
            "Addresses", []
        )
    )

    evidence["nat_gateways"] = len(
        load_json(EVIDENCE_DIR / "nat_gateways.json").get(
            "NatGateways", []
        )
    )

    return evidence


def analyze():
    inventory = load_json(INVENTORY_FILE)
    resources = inventory.get("Resources", [])

    evidence = count_resources()

    risk_candidates = []

    if evidence["ec2_instances"] > 0:
        risk_candidates.append({
            "resource_type": "ec2:instance",
            "risk": "HIGH",
            "evidence": (
                f"{evidence['ec2_instances']} EC2 instance(s) "
                "detected."
            ),
            "action": "Investigate instance activity and necessity.",
        })

    if evidence["ebs_volumes"] > 0:
        risk_candidates.append({
            "resource_type": "ec2:volume",
            "risk": "HIGH",
            "evidence": (
                f"{evidence['ebs_volumes']} EBS volume(s) detected."
            ),
            "action": "Check attachment and usage.",
        })

    if evidence["elastic_ips"] > 0:
        risk_candidates.append({
            "resource_type": "ec2:elastic-ip",
            "risk": "MEDIUM",
            "evidence": (
                f"{evidence['elastic_ips']} Elastic IP(s) detected."
            ),
            "action": "Check association and necessity.",
        })

    if evidence["nat_gateways"] > 0:
        risk_candidates.append({
            "resource_type": "ec2:nat-gateway",
            "risk": "HIGH",
            "evidence": (
                f"{evidence['nat_gateways']} NAT gateway(s) detected."
            ),
            "action": "Check usage and necessity.",
        })

    report = {
        "summary": {
            "resources_in_inventory": len(resources),
            "ec2_instances": evidence["ec2_instances"],
            "ebs_volumes": evidence["ebs_volumes"],
            "elastic_ips": evidence["elastic_ips"],
            "nat_gateways": evidence["nat_gateways"],
            "ghost_candidates": len(risk_candidates),
        },
        "evidence": evidence,
        "ghost_candidates": risk_candidates,
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report


def main():
    report = analyze()
    summary = report["summary"]

    print("👻 Ghost Hunter Final Analysis")
    print()
    print(
        f"Resources in inventory : "
        f"{summary['resources_in_inventory']}"
    )
    print(
        f"EC2 instances          : "
        f"{summary['ec2_instances']}"
    )
    print(
        f"EBS volumes            : "
        f"{summary['ebs_volumes']}"
    )
    print(
        f"Elastic IPs            : "
        f"{summary['elastic_ips']}"
    )
    print(
        f"NAT gateways           : "
        f"{summary['nat_gateways']}"
    )
    print(
        f"Ghost candidates       : "
        f"{summary['ghost_candidates']}"
    )
    print()
    print(f"Report written to      : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
