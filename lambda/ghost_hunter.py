import json
import sys
from collections import Counter
from pathlib import Path


INPUT_FILE = Path(
    sys.argv[1] if len(sys.argv) > 1 else "reports/raw_inventory.json"
)

OUTPUT_FILE = Path(
    sys.argv[2] if len(sys.argv) > 2 else "reports/ghost_report.json"
)


BASELINE_RESOURCE_TYPES = {
    "ec2:vpc",
    "ec2:subnet",
    "ec2:security-group",
    "ec2:security-group-rule",
    "ec2:route-table",
    "ec2:internet-gateway",
    "ec2:dhcp-options",
    "ec2:network-acl",
    "athena:workgroup",
    "athena:datacatalog",
    "xray:sampling-rule",
    "events:event-bus",
    "elasticache:user",
    "resource-explorer-2:index",
    "resource-explorer-2:view",
}


RISK_RULES = {
    "ec2:instance": {
        "risk": "HIGH",
        "reason": "Compute resource requires activity verification.",
        "action": "Check usage before considering cleanup.",
    },
    "ec2:volume": {
        "risk": "HIGH",
        "reason": "Storage resource may incur charges if provisioned.",
        "action": "Check attachment and usage before cleanup.",
    },
    "ec2:elastic-ip": {
        "risk": "MEDIUM",
        "reason": "Public IP allocation requires further inspection.",
        "action": "Check whether the address is associated and required.",
    },
    "ec2:nat-gateway": {
        "risk": "HIGH",
        "reason": "Network translation resource can be a significant cost source.",
        "action": "Verify usage and necessity before cleanup.",
    },
    "rds:db": {
        "risk": "HIGH",
        "reason": "Database resource requires activity and retention verification.",
        "action": "Check usage, backups, and retention requirements.",
    },
    "elasticache:cluster": {
        "risk": "HIGH",
        "reason": "Cache resource requires activity verification.",
        "action": "Check usage and cluster necessity.",
    },
    "elasticloadbalancing:load-balancer": {
        "risk": "HIGH",
        "reason": "Load balancer requires usage verification.",
        "action": "Check traffic and attached targets.",
    },
}


def load_inventory():
    """Load resources from a Resource Explorer JSON file."""
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Inventory file not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    resources = data.get("Resources", [])

    if not isinstance(resources, list):
        raise ValueError("The 'Resources' field must be a list.")

    return resources


def extract_tags(resource):
    """Extract tags from the Resource Explorer Properties list."""
    properties = resource.get("Properties", [])

    if not isinstance(properties, list):
        return []

    for prop in properties:
        if not isinstance(prop, dict):
            continue

        if prop.get("Name") == "tags":
            tags = prop.get("Data", [])

            if isinstance(tags, list):
                return tags

            return []

    return []


def classify_resource(resource):
    """Classify the resource using safe initial rules."""
    resource_type = resource.get("ResourceType", "unknown")

    if resource_type in BASELINE_RESOURCE_TYPES:
        return "baseline_infrastructure"

    if resource_type in RISK_RULES:
        return "review_candidate"

    return "review_candidate"


def build_risk_information(resource, classification):
    """Assign a risk level and explanation."""
    resource_type = resource.get("ResourceType", "unknown")

    if classification == "baseline_infrastructure":
        return {
            "risk": "NONE",
            "reason": (
                "Baseline or control-plane resource; "
                "existence alone is not evidence of waste."
            ),
            "recommended_action": "Ignore unless there is specific evidence.",
        }

    rule = RISK_RULES.get(resource_type)

    if rule:
        return {
            "risk": rule["risk"],
            "reason": rule["reason"],
            "recommended_action": rule["action"],
        }

    return {
        "risk": "LOW",
        "reason": (
            "Resource type is not currently covered by a stronger "
            "risk rule."
        ),
        "recommended_action": "Inspect before taking action.",
    }


def analyze_resources(resources):
    """Analyze resources and assign classification and risk."""
    service_counter = Counter()
    type_counter = Counter()
    risk_counter = Counter()

    all_resources = []
    baseline_resources = []
    review_candidates = []

    for resource in resources:
        service = resource.get("Service", "unknown")
        resource_type = resource.get("ResourceType", "unknown")

        service_counter[service] += 1
        type_counter[resource_type] += 1

        tags = extract_tags(resource)
        classification = classify_resource(resource)

        risk_info = build_risk_information(
            resource,
            classification,
        )

        record = {
            "arn": resource.get("Arn"),
            "region": resource.get("Region"),
            "service": service,
            "resource_type": resource_type,
            "tags": tags,
            "classification": classification,
            "risk": risk_info["risk"],
            "reason": risk_info["reason"],
            "recommended_action": risk_info["recommended_action"],
        }

        risk_counter[risk_info["risk"]] += 1
        all_resources.append(record)

        if classification == "baseline_infrastructure":
            baseline_resources.append(record)
        else:
            review_candidates.append(record)

    return {
        "summary": {
            "total_resources": len(all_resources),
            "baseline_infrastructure": len(baseline_resources),
            "review_candidates": len(review_candidates),
        },
        "risk_summary": dict(risk_counter),
        "services": dict(service_counter),
        "resource_types": dict(type_counter),
        "baseline_infrastructure": baseline_resources,
        "review_candidates": review_candidates,
        "all_resources": all_resources,
    }


def save_report(report):
    """Save the report to JSON."""
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)


def main():
    """Run the Ghost Hunter analysis."""
    resources = load_inventory()
    report = analyze_resources(resources)
    save_report(report)

    summary = report["summary"]

    print("👻 Ghost Hunter analysis complete")
    print(f"Resources scanned        : {summary['total_resources']}")
    print(
        f"Baseline infrastructure  : "
        f"{summary['baseline_infrastructure']}"
    )
    print(
        f"Review candidates        : "
        f"{summary['review_candidates']}"
    )

    print("\nRisk summary:")
    for risk, count in sorted(report["risk_summary"].items()):
        print(f"  {risk:6} : {count}")

    print(f"\nReport written to         : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
