import json
from pathlib import Path

import boto3


PROFILE_NAME = "ghost-hunter"
REGION = "ap-south-1"

OUTPUT_DIR = Path("reports/evidence")


def create_session():
    """Create a Boto3 session using the Ghost Hunter profile."""
    return boto3.Session(
        profile_name=PROFILE_NAME,
        region_name=REGION,
    )


def save_json(filename, data):
    """Save AWS API response to the evidence directory."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    output_file = OUTPUT_DIR / filename

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, default=str)

    return output_file


def collect_ec2_evidence(session):
    """Collect read-only EC2 resource evidence."""
    ec2 = session.client("ec2")

    results = {}

    print("🔎 Checking EC2 instances...")
    results["ec2_instances"] = ec2.describe_instances()

    print("🔎 Checking EBS volumes...")
    results["ebs_volumes"] = ec2.describe_volumes()

    print("🔎 Checking Elastic IP addresses...")
    results["elastic_ips"] = ec2.describe_addresses()

    print("🔎 Checking NAT gateways...")
    results["nat_gateways"] = ec2.describe_nat_gateways()

    return results


def save_evidence(results):
    """Save each evidence category separately."""
    files = {}

    files["ec2_instances"] = save_json(
        "ec2_instances.json",
        results["ec2_instances"],
    )

    files["ebs_volumes"] = save_json(
        "ebs_volumes.json",
        results["ebs_volumes"],
    )

    files["elastic_ips"] = save_json(
        "elastic_ips.json",
        results["elastic_ips"],
    )

    files["nat_gateways"] = save_json(
        "nat_gateways.json",
        results["nat_gateways"],
    )

    return files


def count_resources(results):
    """Count resources returned by each API."""
    return {
        "ec2_instances": sum(
            len(reservation.get("Instances", []))
            for reservation in results["ec2_instances"].get(
                "Reservations", []
            )
        ),
        "ebs_volumes": len(
            results["ebs_volumes"].get("Volumes", [])
        ),
        "elastic_ips": len(
            results["elastic_ips"].get("Addresses", [])
        ),
        "nat_gateways": len(
            results["nat_gateways"].get("NatGateways", [])
        ),
    }


def main():
    print("👻 Ghost Hunter AWS Evidence Collector")
    print(f"Profile : {PROFILE_NAME}")
    print(f"Region  : {REGION}")
    print()

    session = create_session()

    # Verify the identity before collecting anything.
    sts = session.client("sts")
    identity = sts.get_caller_identity()

    print("Authenticated identity:")
    print(identity["Arn"])
    print()

    results = collect_ec2_evidence(session)
    files = save_evidence(results)
    counts = count_resources(results)

    print()
    print("✅ Collection complete")
    print()
    print("Resources discovered:")

    for resource_type, count in counts.items():
        print(f"  {resource_type:15} : {count}")

    print()
    print("Evidence files:")

    for resource_type, file_path in files.items():
        print(f"  {resource_type:15} : {file_path}")


if __name__ == "__main__":
    main()
