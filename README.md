# 👻 AWS Ghost Resource Hunter

A serverless AWS resource-auditing tool that discovers cloud resources, collects read-only evidence, and identifies resources that deserve further investigation for potential waste or unnecessary cost.

> **Detection first. Deletion never happens automatically.**

## 🎯 Project Goal

Cloud environments can accumulate resources after workloads are changed or removed.

Ghost Resource Hunter is designed to help identify resources that deserve human review by combining:

- AWS resource discovery
- Resource state and attachment information
- Read-only evidence collection
- Risk classification
- Human-in-the-loop review

The project intentionally avoids automatic destructive actions.

---

## 🏗️ Architecture

```text
                    AWS Resource Explorer
                            │
                            ▼
                    Resource Inventory
                            │
                            ▼
                 Ghost Hunter Lambda
                     Python 3.14
                        ARM64
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
        Resource Explorer              Amazon EC2
          discovery                 read-only checks
                                      │
                              ┌───────┼────────┐
                              │       │        │
                              ▼       ▼        ▼
                           Instances EBS      EIP/NAT
                              │
                              ▼
                       Evidence Analysis
                              │
                              ▼
                       Risk Classification
                              │
                              ▼
                       Ghost Candidates
