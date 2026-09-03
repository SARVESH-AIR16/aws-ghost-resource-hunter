import json
import os
from datetime import datetime, timedelta, timezone

import boto3


REGION = os.environ.get("AWS_REGION", "ap-south-1")
VIEW_ARN = os.environ.get("GHOST_HUNTER_VIEW_ARN")

CPU_LOOKBACK_MINUTES = 60
CPU_PERIOD_SECONDS = 300
LOW_CPU_THRESHOLD = 5.0


def get_resource_inventory(resource_explorer):
    """Search the configured Resource Explorer view."""
    if not VIEW_ARN:
        raise RuntimeError(
            "GHOST_HUNTER_VIEW_ARN environment variable is not set."
        )

    response = resource_explorer.search(
        QueryString="*",
        ViewArn=VIEW_ARN,
    )

    return response.get("Resources", [])


def get_ec2_instances(ec2):
    """Return EC2 instances with basic state information."""
    response = ec2.describe_instances()

    instances = []

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instances.append(
                {
                    "instance_id": instance.get("InstanceId"),
                    "state": instance.get("State", {}).get(
                        "Name",
                        "unknown",
                    ),
                    "instance_type": instance.get("InstanceType"),
                    "launch_time": instance.get("LaunchTime"),
                }
            )

    return instances


def get_cpu_activity(cloudwatch, instance_id):
    """Read one hour of EC2 CPU activity."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(
        minutes=CPU_LOOKBACK_MINUTES
    )

    response = cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[
            {
                "Name": "InstanceId",
                "Value": instance_id,
            }
        ],
        StartTime=start_time,
        EndTime=end_time,
        Period=CPU_PERIOD_SECONDS,
        Statistics=["Average"],
        Unit="Percent",
    )

    datapoints = response.get("Datapoints", [])

    if not datapoints:
        return {
            "status": "no_data",
            "average_cpu_percent": None,
            "datapoints": 0,
        }

    averages = [
        point["Average"]
        for point in datapoints
        if "Average" in point
    ]

    if not averages:
        return {
            "status": "no_data",
            "average_cpu_percent": None,
            "datapoints": 0,
        }

    average_cpu = sum(averages) / len(averages)

    return {
        "status": "available",
        "average_cpu_percent": round(
            average_cpu,
            2,
        ),
        "datapoints": len(averages),
    }


def analyze_instance_activity(cloudwatch, instances):
    """Combine instance state and CPU evidence."""
    results = []
    candidates = []

    for instance in instances:
        instance_id = instance["instance_id"]
        state = instance["state"]

        record = {
            "instance_id": instance_id,
            "state": state,
            "instance_type": instance["instance_type"],
            "launch_time": instance["launch_time"],
        }

        if state == "running":
            activity = get_cpu_activity(
                cloudwatch,
                instance_id,
            )

            record["cpu_activity"] = activity

            if (
                activity["status"] == "available"
                and activity["average_cpu_percent"] < LOW_CPU_THRESHOLD
            ):
                record["activity_assessment"] = "low_activity"

                candidates.append(
                    {
                        "resource_type": "ec2:instance",
                        "instance_id": instance_id,
                        "risk": "HIGH",
                        "evidence": (
                            f"Average CPU was "
                            f"{activity['average_cpu_percent']}% "
                            f"over the last "
                            f"{CPU_LOOKBACK_MINUTES} minutes."
                        ),
                        "action": (
                            "Investigate workload usage before "
                            "considering any cleanup."
                        ),
                    }
                )

            elif activity["status"] == "available":
                record["activity_assessment"] = "activity_detected"

            else:
                record["activity_assessment"] = "insufficient_data"

        elif state in {"stopped", "stopping"}:
            record["activity_assessment"] = "stopped_instance"

            candidates.append(
                {
                    "resource_type": "ec2:instance",
                    "instance_id": instance_id,
                    "risk": "MEDIUM",
                    "evidence": (
                        f"Instance state is '{state}'."
                    ),
                    "action": (
                        "Check whether the stopped instance and "
                        "its attached storage are still required."
                    ),
                }
            )

        else:
            record["activity_assessment"] = "state_requires_review"

        results.append(record)

    return results, candidates


def analyze_ebs_volumes(volumes):
    """Identify unattached EBS volumes."""
    results = []
    candidates = []

    for volume in volumes:
        attachments = volume.get("Attachments", [])
        attached = bool(attachments)

        record = {
            "volume_id": volume.get("VolumeId"),
            "state": volume.get("State"),
            "size_gib": volume.get("Size"),
            "encrypted": volume.get("Encrypted"),
            "attached": attached,
        }

        if attached:
            record["assessment"] = "attached"
        else:
            record["assessment"] = "unattached"

            candidates.append(
                {
                    "resource_type": "ec2:volume",
                    "volume_id": volume.get("VolumeId"),
                    "risk": "HIGH",
                    "evidence": (
                        "EBS volume has no current attachment."
                    ),
                    "action": (
                        "Verify the volume is no longer needed "
                        "before considering deletion."
                    ),
                }
            )

        results.append(record)

    return results, candidates


def analyze_elastic_ips(addresses):
    """Identify unassociated Elastic IP addresses."""
    results = []
    candidates = []

    for address in addresses:
        associated = bool(
            address.get("AssociationId")
            or address.get("InstanceId")
            or address.get("NetworkInterfaceId")
        )

        record = {
            "allocation_id": address.get("AllocationId"),
            "public_ip": address.get("PublicIp"),
            "associated": associated,
        }

        if associated:
            record["assessment"] = "associated"
        else:
            record["assessment"] = "unassociated"

            candidates.append(
                {
                    "resource_type": "ec2:elastic-ip",
                    "allocation_id": address.get(
                        "AllocationId"
                    ),
                    "risk": "HIGH",
                    "evidence": (
                        "Elastic IP is currently unassociated."
                    ),
                    "action": (
                        "Verify the address is not reserved for "
                        "a planned workload before release."
                    ),
                }
            )

        results.append(record)

    return results, candidates


def analyze_nat_gateways(nat_gateways):
    """Identify NAT Gateway state and review candidates."""
    results = []
    candidates = []

    for gateway in nat_gateways:
        state = gateway.get("State", "unknown")

        record = {
            "nat_gateway_id": gateway.get(
                "NatGatewayId"
            ),
            "state": state,
            "vpc_id": gateway.get("VpcId"),
            "subnet_id": gateway.get("SubnetId"),
        }

        if state == "available":
            record["assessment"] = (
                "active_nat_gateway_requires_usage_review"
            )

            candidates.append(
                {
                    "resource_type": "ec2:nat-gateway",
                    "nat_gateway_id": gateway.get(
                        "NatGatewayId"
                    ),
                    "risk": "HIGH",
                    "evidence": (
                        "NAT Gateway is available. "
                        "Usage should be reviewed because NAT "
                        "gateways incur hourly and data-processing "
                        "charges."
                    ),
                    "action": (
                        "Review architecture and traffic before "
                        "considering any change."
                    ),
                }
            )

        elif state in {"failed", "deleting"}:
            record["assessment"] = "state_requires_review"

        else:
            record["assessment"] = "not_currently_available"

        results.append(record)

    return results, candidates


def collect_ec2_evidence(ec2, cloudwatch):
    """Collect EC2 inventory and cost-risk evidence."""
    instances = get_ec2_instances(ec2)

    volume_response = ec2.describe_volumes()
    volumes = volume_response.get("Volumes", [])

    address_response = ec2.describe_addresses()
    addresses = address_response.get("Addresses", [])

    nat_response = ec2.describe_nat_gateways()
    nat_gateways = nat_response.get("NatGateways", [])

    instance_activity, instance_candidates = (
        analyze_instance_activity(
            cloudwatch,
            instances,
        )
    )

    volume_analysis, volume_candidates = (
        analyze_ebs_volumes(volumes)
    )

    ip_analysis, ip_candidates = (
        analyze_elastic_ips(addresses)
    )

    nat_analysis, nat_candidates = (
        analyze_nat_gateways(nat_gateways)
    )

    return {
        "ec2_instances": len(instances),
        "ebs_volumes": len(volumes),
        "elastic_ips": len(addresses),
        "nat_gateways": len(nat_gateways),

        "instance_activity": instance_activity,
        "ebs_analysis": volume_analysis,
        "elastic_ip_analysis": ip_analysis,
        "nat_gateway_analysis": nat_analysis,

        "activity_candidates": (
            instance_candidates
            + volume_candidates
            + ip_candidates
            + nat_candidates
        ),
    }


def lambda_handler(event, context):
    """Run one Ghost Hunter scan."""
    started_at = datetime.now(
        timezone.utc
    ).isoformat()

    resource_explorer = boto3.client(
        "resource-explorer-2",
        region_name=REGION,
    )

    ec2 = boto3.client(
        "ec2",
        region_name=REGION,
    )

    cloudwatch = boto3.client(
        "cloudwatch",
        region_name=REGION,
    )

    resources = get_resource_inventory(
        resource_explorer
    )

    evidence = collect_ec2_evidence(
        ec2,
        cloudwatch,
    )

    candidates = evidence.pop(
        "activity_candidates"
    )

    report = {
        "project": "AWS Ghost Resource Hunter",
        "scan_started_at": started_at,
        "region": REGION,
        "inventory_count": len(resources),
        "evidence": evidence,
        "ghost_candidates": candidates,
        "candidate_count": len(candidates),
    }

    print(
        json.dumps(
            report,
            indent=2,
            default=str,
        )
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            report,
            default=str,
        ),
    }


if __name__ == "__main__":
    lambda_handler({}, None)
