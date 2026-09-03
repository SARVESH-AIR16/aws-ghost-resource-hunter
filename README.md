# 👻 AWS Ghost Resource Hunter

A serverless AWS resource-auditing tool that discovers cloud resources, collects read-only evidence, and identifies potential cost-risk candidates without automatically deleting anything.

## 🎯 Project Goal

Cloud resources can remain after workloads are removed or changed. These resources may create unnecessary operational or infrastructure costs.

Ghost Resource Hunter is designed to help identify resources that deserve human review by combining:

* Resource discovery
* Resource state and attachment information
* Activity evidence where available
* Evidence-based risk classification

The project follows a **read-only detection first** approach. It does not automatically delete infrastructure.

## 🏗️ Architecture

```text
AWS Resource Explorer
        │
        ▼
Ghost Hunter Lambda
        │
        ├── EC2
        │    ├── Instances
        │    ├── EBS Volumes
        │    ├── Elastic IPs
        │    └── NAT Gateways
        │
        └── CloudWatch
             └── EC2 CPU activity
        │
        ▼
Evidence Analysis
        │
        ▼
Risk Classification
        │
        ▼
Ghost Candidates
```

## ☁️ AWS Services

* AWS Lambda
* AWS Resource Explorer
* Amazon EC2
* Amazon CloudWatch
* AWS IAM
* Amazon CloudWatch Logs

## 🔐 Security Model

Ghost Hunter uses separate permissions for local development and the deployed Lambda function.

### Lambda execution role

`GhostHunterLambdaExecutionRole`

The role is limited to:

* Resource Explorer view access
* Resource Explorer search
* EC2 read-only `Describe*` operations
* CloudWatch metric reads
* CloudWatch logging

The Lambda function does not receive administrator permissions and does not receive personal AWS access keys.

### Local development

Local testing uses a named AWS CLI login profile.

No access keys or secret keys are stored in the repository.

## 🔎 Detection Logic

Ghost Hunter currently evaluates:

### EC2 instances

* Instance state
* CPU activity when metric data is available
* Low-activity evidence

### EBS volumes

* Attached vs. unattached state
* Volume size
* Encryption status

### Elastic IP addresses

* Associated vs. unassociated state

### NAT Gateways

* Gateway state
* VPC and subnet information
* Review requirement for active gateways

The project intentionally distinguishes:

```text
No metric data
≠
Idle resource
```

Missing evidence is never automatically treated as proof that a resource is unused.

## 🧪 Testing

The project was tested in two environments:

### Local testing

The Lambda handler was executed locally using Boto3 and real AWS read-only APIs.

### AWS Lambda testing

The same logic was packaged as a ZIP deployment and executed in AWS Lambda.

The deployed function successfully scanned the configured AWS Region.

## 💰 Cost-Control Strategy

The project is designed to keep AWS usage extremely small.

* Serverless Lambda instead of EC2
* No NAT Gateway created for the project
* No EC2 instance created just for testing
* No EBS test volume created
* No Elastic IP created for testing
* Manual Lambda invocation during development
* CloudWatch log retention configured to 7 days
* Read-only API operations
* No automatic destructive cleanup

## 📁 Project Structure

```text
aws-ghost-resource-hunter/
├── README.md
├── .gitignore
├── lambda/
│   ├── ghost_hunter.py
│   ├── aws_collector.py
│   ├── evidence_analyzer.py
│   └── lambda_function.py
├── tests/
│   └── mock_inventory.json
├── docs/
└── reports/
```

Real AWS inventory and evidence files are intentionally excluded from the public repository.

## 🚀 Deployment

The current Lambda deployment uses:

```text
Runtime: Python 3.14
Architecture: ARM64
Handler: lambda_function.lambda_handler
Memory: 128 MB
Timeout: 30 seconds
```

The deployed Lambda uses an IAM execution role rather than personal AWS credentials.

## ⚠️ Current Limitations

The current version focuses on a small set of AWS infrastructure resources.

CPU-based activity analysis is only performed when EC2 instances actually exist and CloudWatch metric data is available.

The current project does not automatically delete resources.

## 🔭 Future Improvements

Planned improvements include:

* Additional AWS resource types
* More activity signals
* Better risk scoring
* Historical evidence
* Cost-aware prioritization
* Automated report generation
* Optional scheduled scans
* Portfolio dashboard

## 📌 Project Status

**Working MVP**

The project has been successfully tested locally and deployed to AWS Lambda with real AWS read-only access.
