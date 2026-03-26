# cloud-security-research-journal
A hands-on cloud security research journey covering attack techniques, detection engineering, and defensive strategie.

### Topic: Structured Transition from Threat Hunter and Security Researcher to Cloud Security Researcher — Foundation Mapping, Attack Surface Analysis & Detection Engineering Strategy

---

## Learning Objective

To conduct a rigorous, honest self-assessment of an unconventional entry into cloud security research and translate that foundation into a structured, research-grade curriculum targeting roles in Security Research, Detection Engineering, and Threat Hunting within cloud-native environments.

The central question this session answers: **What does a APT hunter actually need to learn to become an effective cloud security researcher, and what can they skip?**

This matters because cloud security research suffers from a persistent skill bifurcation: practitioners with deep cloud platform knowledge rarely have genuine adversarial tradecraft experience, while offensive operators rarely understand cloud-native telemetry, IAM policy evaluation, or detection engineering at scale. Bridging that gap is the value proposition being built here.

---

## Core Concepts

**The Five Research Domains:**

The program is structured across five domains that together define the cloud security researcher skill surface:

- **Domain 1 — Threat Protection & AI:** Cloud-native detection engineering, ML-based anomaly detection, CSPM, SOAR automation, and APT behavioral analysis in cloud environments.
- **Domain 2 — Data Protection & Confidentiality:** Applied cryptography, Trusted Execution Environments (TEEs), homomorphic encryption, differential privacy, SMPC, and data sovereignty architecture across providers.
- **Domain 3 — Architecture Security:** Container runtime internals, Kubernetes attack chains, Zero-Trust architecture, serverless/FaaS attack surface, and API gateway security.
- **Domain 4 — Emerging Technology:** Post-quantum cryptography (NIST FIPS 203/204/205), blockchain for identity, DevSecOps pipeline attacks, and cloud forensics in virtualized environments.
- **Domain 5 — Core Foundations:** Multi-cloud IAM (AWS/Azure/GCP), IaC misconfiguration analysis, cloud governance as code, and complete multi-cloud kill-chain mapping.

**Starting Position (Honest Assessment):**

| Domain | Starting Phase | Key Accelerator |
|---|---|---|
| D1 — Threat Protection | Advanced (detection), Intermediate (ML/AWS) | APT hunting at scale surpasses beginner/intermediate detection phases |
| D5 — Core Foundations | Intermediate (GCP done), Beginner (AWS, Azure) | Network architecture, Linux, AD knowledge all transfer directly |
| D3 — Architecture Security | Intermediate (OT/arch), Beginner (K8s) | OT architecture and offensive skills accelerate threat modeling |
| D4 — Emerging Tech | Intermediate (forensics) | Windows forensics and memory analysis transfer strongly to cloud forensics |
| D2 — Data Protection | Beginner (cryptography theory) | CS degree in progress provides the mathematical foundation |

---

## Deep Dive & Analysis

### How the Skill Transfer Actually Works

The document's core analytical insight is that cloud security is not a new discipline so much as a new *terrain* for existing security thinking. The mechanisms are familiar — authentication, authorization, network segmentation, log telemetry, anomaly detection — but the implementation primitives are cloud-native and require deliberate re-mapping.

**Active Directory → Entra ID:** Years of experience with Windows domain services, Kerberos, LDAP, and AD trust relationships translate almost directly to Azure Entra ID concepts. The attack surface (token theft, pass-the-hash variants, privilege escalation through group membership) has structural analogs in Entra ID attack techniques — PRT (Primary Refresh Token) abuse, pass-the-certificate, device identity attacks — that are conceptually familiar even if the tooling is new.

**Network Architecture → Cloud Networking:** Traditional network security work (segmentation, ACLs, routing, firewall policy) maps onto VPCs, security groups, NACLs, PrivateLink, and WAF configurations. The mental model of network trust zones transfers directly; the cloud-specific primitives are a vocabulary problem, not a conceptual one.

**SIEM/Big Data Hunting → CloudTrail + KQL:** The hypothesis-driven hunting methodology built in military context — formulating a behavioral hypothesis, identifying the data source that would contain evidence, writing a targeted query, and triaging results — is directly portable to AWS CloudTrail analysis and Microsoft Sentinel KQL hunting. The schema is new; the methodology is not.

**EDR/EPP Tuning → CSPM:** Experience tuning endpoint detection policies (McAfee ePO, ENS, DLP) has a structural analog in CSPM tooling (Prowler, ScoutSuite). Both involve: defining a policy baseline, scanning against it, triaging findings by exploitability, and writing compensating controls. The domain shifts from endpoint to cloud configuration; the operational workflow is identical.

**Malware Analysis → Cloud Ransomware Kill-Chain:** Windows malware analysis and memory forensics provides a unique lens for analyzing cloud-deployed ransomware. Understanding how ransomware stages execution (dropper → persistence → lateral movement → encryption trigger) maps directly to analyzing cloud ransomware campaigns (ALPHV/BlackCat cloud targeting, Scattered Spider, LockBit S3 encryption). The artifact types change (EBS snapshots vs disk images) but the forensic reasoning process is the same.

### Where Genuine Gaps Exist

Three areas represent true conceptual gaps, not just vocabulary gaps:

1. **AWS IAM Policy Evaluation Logic** — AWS IAM is architecturally more complex than GCP or Entra RBAC. The intersection of identity-based policies, resource-based policies, permission boundaries, service control policies (SCPs), and cross-account trust relationships creates a multi-layered evaluation engine with non-obvious precedence rules. The 21 documented privilege escalation paths (Rhino Security guide) emerge directly from these evaluation subtleties. This is genuinely new conceptual territory.

2. **Applied Cryptography** — The mathematical foundations of symmetric/asymmetric encryption, PKI, and especially post-quantum cryptographic primitives (lattice-based schemes, ML-KEM/ML-DSA/SLH-DSA) are not transferable from operational security work. A CS degree in progress will provide the algebraic foundation; this domain is correctly sequenced last.

3. **Kubernetes Control Plane Security** — Container runtime internals (Linux namespaces, cgroups, seccomp profiles), Kubernetes RBAC bypass, etcd exposure, pod escape techniques, and service account token theft represent a genuinely new attack surface without direct analogies to prior experience.

---

## Threat Modeling Perspective

### What an Attacker Actually Targets (Multi-Cloud)

Mapping from the documented attack surfaces across all three providers:

**AWS Attack Surface:**
- IAM privilege escalation via `iam:CreatePolicyVersion`, `iam:PassRole` + `lambda:CreateFunction`, `ec2:RunInstances` + `iam:PassRole`, and `sts:AssumeRole` chaining
- S3 bucket enumeration and exfiltration
- CloudTrail log tampering to reduce forensic visibility
- Cross-account role assumption through misconfigured trust policies

**Azure Attack Surface:**
- Primary Refresh Token (PRT) theft enabling persistent authentication bypass
- Pass-the-certificate attacks against device identities
- PIM (Privileged Identity Management) abuse — activating dormant privileged roles
- Conditional Access policy bypass through device compliance spoofing
- Azure AD to Azure RBAC privilege escalation (they are separate systems with separate permission models)

**GCP Attack Surface:**
- Service account impersonation chains via `iam.serviceAccounts.actAs`
- Organization hierarchy attacks targeting overpermissioned folder-level bindings
- GKE (Google Kubernetes Engine)-specific privilege escalation through workload identity
- Lateral movement via project-level service account key theft

**IaC Attack Surface:**
- Terraform state files stored in misconfigured S3 buckets (contain plaintext secrets and resource configurations)
- CloudFormation templates with hardcoded credentials
- Helm chart misconfigurations granting excessive RBAC permissions
- CI/CD pipeline injection via GitHub Actions workflow modification (OIDC abuse, dependency confusion)

**Cross-Cloud Kill-Chain (Nation-State Perspective):**

Initial access via OIDC token theft or supply chain compromise → persistence through Lambda backdoors or scheduled cloud functions → lateral movement via cross-account role assumption → collection through S3 enumeration and managed service API access → exfiltration → CloudTrail log deletion to remove forensic artifacts.

This kill-chain maps cleanly to MITRE ATT&CK for Cloud (IaaS/SaaS/Containers matrices) and extends on-premise APT kill-chain reasoning to a cloud-native context.

### Trust Boundary Analysis

The critical insight across all three providers is that **IAM is the new perimeter**. Traditional network perimeter security is supplementary in cloud environments — an attacker with valid credentials and sufficient IAM permissions can operate entirely within the "allowed" API surface while causing catastrophic damage. This shifts the detection focus from network anomaly detection (which remains relevant) to **behavioral anomaly detection against the IAM and management API layer**.

Key trust boundaries:
- The management plane (IAM API, control plane APIs) vs. data plane (S3 object access, EC2 workloads)
- Cross-account trust relationships (particularly in AWS Organizations)
- The OIDC federation boundary between CI/CD systems and cloud IAM
- The boundary between Kubernetes workload identity and cloud IAM (e.g., GKE Workload Identity, EKS Pod Identity)

---

## Detection & Defense Ideas

### Cloud Logging Telemetry Map

| Provider | Log Source | Security-Relevant Events |
|---|---|---|
| AWS | CloudTrail | IAM policy changes, `AssumeRole`, `GetCallerIdentity`, unusual API calls, `DeleteTrail` |
| AWS | VPC Flow Logs | Lateral movement, unusual egress, port scanning patterns |
| AWS | GuardDuty | ML-based anomaly detection on CloudTrail + DNS + VPC Flow |
| Azure | AuditLogs | RBAC changes, PIM activations, Conditional Access policy modifications |
| Azure | SigninLogs | Impossible travel, legacy authentication, MFA failures |
| Azure | Sentinel Analytics | Behavioral analytics rules across all Entra/M365 telemetry |
| GCP | Cloud Audit Logs | Admin Activity, Data Access, System Event logs |
| GCP | Security Command Center | Misconfiguration findings, threat detection |

### Hunting Hypotheses (Derived from IDF APT Experience)

**Hypothesis 1 — Credential Staging Before Exfiltration:**
Nation-state actors frequently stage credentials (access keys, service account keys) days before exfiltration begins. Hunt for: `iam:CreateAccessKey` or `iam:CreateServiceAccountKey` events on service accounts not previously seen generating such events, followed by no subsequent API calls from that key for 24-72 hours, then sudden high-volume API activity.

**Hypothesis 2 — Permission Escalation Via Policy Version Rollback:**
`iam:SetDefaultPolicyVersion` allows reverting an IAM policy to a previous, more permissive version without creating new policy content — evading detections that only monitor `CreatePolicy` or `AttachRolePolicy`. Hunt for: `SetDefaultPolicyVersion` events where the target version predates the current version by more than 30 days.

**Hypothesis 3 — Cross-Account Reconnaissance Before Lateral Movement:**
APT actors enumerate cross-account trust relationships before attempting lateral movement. Hunt for: `sts:AssumeRole` failures from IAM principals that are not observed in the baseline, followed within 24 hours by successful `AssumeRole` to any external account.

**Hypothesis 4 — Anomalous Service Combination Enumeration:**
Attackers enumerating an unfamiliar cloud environment call combinations of services they wouldn't normally co-access. Hunt for: IAM principals calling more than 5 distinct AWS service namespaces in a single hour window that historically call fewer than 2, without a corresponding deployment pipeline event.

### Detection-as-Code: Sigma Rule Sketch

```yaml
title: AWS IAM Policy Version Rollback (Privilege Escalation)
status: experimental
description: >
  Detects rollback to a previously permissive IAM policy version,
  a technique to restore broad permissions without creating new policy content.
  Associated with: MITRE ATT&CK T1098.003 (Account Manipulation - Additional Cloud Roles)
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: SetDefaultPolicyVersion
    requestParameters.policyArn|contains: 'iam:::'
  filter_routine:
    userAgent|contains:
      - 'aws-sdk-go'
      - 'Terraform'
  condition: selection and not filter_routine
falsepositives:
  - Legitimate policy rollback after failed deployment (correlate with change management records)
level: high
tags:
  - attack.privilege_escalation
  - attack.t1098.003
```

### ML Anomaly Detection Approach

Leverage existing PySpark/Big Data skills to build an Isolation Forest anomaly detector on CloudTrail IAM events:

- **Feature engineering:** API call frequency by service (normalized per hour), geographic deviation score (Haversine distance from last observed IP centroid), time-of-day deviation (z-score against per-principal historical distribution), unique service namespace count per session, `AssumeRole` chain depth
- **Evaluation:** Precision/recall curves against labeled CloudGoat attack scenario replays
- **Production consideration:** False positive rate is the critical metric in cloud environments — start with high contamination parameters and tune down using analyst feedback

The key differentiator over generic anomaly detection: feature engineering informed by real APT behavioral knowledge. Nation-state actors don't just generate statistical anomalies — they generate specific *behavioral* anomalies (impossible service combinations, credential staging windows, reconnaissance-then-lateral patterns) that generic models miss but hypothesis-driven feature engineering captures.

### Hardening Recommendations

- **AWS:** Enforce SCPs that deny `iam:CreatePolicyVersion`, `iam:DeleteTrail`, and `ec2:RunInstances` except from approved automation principals at the Organization level
- **Azure:** Enable PIM for all privileged roles with no standing access; enforce Conditional Access requiring compliant device + MFA for all privileged operations
- **GCP:** Disable service account key creation at the Organization Policy level (`constraints/iam.disableServiceAccountKeyCreation`); use Workload Identity for all compute workloads
- **All providers:** Enable centralized logging with tamper-resistant storage (AWS CloudTrail Organization Trail to a logging account; Azure Sentinel with immutable storage; GCP log sink to locked storage bucket); alert on any event that modifies logging configuration

---

## Key Insights

**The asymmetry that creates research opportunity:** Most cloud security tools and detections are written by engineers who understand cloud platforms deeply but have never operated against real APT adversaries. Most APT hunters have never operated in cloud environments. The intersection of genuine threat intelligence knowledge and cloud security depth is where the highest-value research lives — and it is currently underpopulated.

**IAM is not just an access control system — it is a complete attack surface.** The 21 documented AWS IAM privilege escalation paths are not edge cases or bugs; they emerge from the intended design of IAM's composition rules. Understanding IAM deeply means understanding it as an attacker would: as a graph of principal-permission-resource relationships where the question is not "what is this user allowed to do?" but "what is the minimum sequence of allowed API calls that produces an outcome the policy author did not intend?"

**Cloud-connected OT security is a genuinely underexplored research niche.** As industrial control systems increasingly integrate with cloud infrastructure (SCADA telemetry ingestion, remote maintenance access, historian data in cloud data lakes), the attack surface of OT systems becomes partially cloud-native. Researchers with both OT architecture depth and cloud security knowledge are exceptionally rare. This intersection — where a successful cloud IAM attack can potentially reach OT control systems — is publishable at top venues and directly relevant to nation-state threat intelligence.

**Detection engineering and offensive security are more complementary than competing.** The ability to execute an attack scenario (via CloudGoat, Stratus Red Team, Pacu) and immediately observe its CloudTrail footprint, then write a detection against that footprint, produces detections of materially higher quality than detections written from documentation alone. The offensive background (HDE certification) is not incidental to detection engineering — it is a prerequisite for writing detections that hold up against real attackers.

**Adversarial ML is a natural research extension.** If an attacker with knowledge of ML-based cloud detection systems (GuardDuty, Sentinel Analytics) deliberately crafts API call sequences that stay statistically normal while achieving privilege escalation, do current detection models hold? This question — translating real APT evasion tradecraft into a formal adversarial ML research framework — sits at the frontier of the field and is exactly the kind of research that emerges from the rare combination of APT operational knowledge and ML engineering skill.

---

## Challenges / Knowledge Gaps

**AWS IAM policy evaluation order** is more complex than initially apparent. The interaction of identity-based policies, resource-based policies, permission boundaries, and SCPs does not follow a simple additive model. The precedence rules (explicit deny always wins, then SCPs, then permission boundaries, then identity/resource policy intersection) create a multi-layered evaluation tree that requires deliberate study and lab practice to internalize. Reading the AWS documentation is insufficient; working through CloudGoat's IAM escalation scenarios is required.

**KQL (Kusto Query Language) for Sentinel** — while the hunting methodology transfers directly, KQL's syntax is distinct from the SQL-like query languages used in prior Big Data work. The table schemas (AuditLogs, SigninLogs, CommonSecurityLog) require deliberate study. Goal: write 10 production-quality hunting rules within the first two weeks of Sentinel exposure.

**Academic research methodology** is an unfamiliar operational context. Writing a security paper for IEEE S&P, USENIX Security, or NDSS has specific expectations around: related work positioning, threat model formalization, experimental design, statistical validity of results, and artifact release. This is a learnable process but requires deliberate study alongside technical work.

**Cryptography depth** — the mathematical foundations of lattice-based post-quantum cryptography (Learning With Errors, Module-LWE) require algebraic background that is being built in parallel through CS coursework. Implementation work (using liboqs, Microsoft SEAL) can proceed before formal mathematical mastery, but research-level contribution requires the mathematical foundation.

---

## Next Steps

1. **Immediate (Week 1-2):** Complete all 6 levels of flaws.cloud (Scott Piper). For each level: document the attack chain, identify the CloudTrail events that would have captured it, write a detection artifact. Begin publishing these to GitHub as the first portfolio entries.

2. **Week 3-4:** Deep-dive AWS IAM policy evaluation. Work through the Rhino Security 21 privilege escalation paths systematically against a personal AWS test account. Document each path: attack mechanism → CloudTrail footprint → Sigma detection rule → remediation.

3. **Month 1-2:** Begin CloudGoat lab scenarios in parallel. For every scenario: attack path → CloudTrail JSON analysis → GuardDuty finding mapping → Sigma rule → MITRE ATT&CK technique tag. This becomes the foundation portfolio reference document.

4. **Month 2-3:** Stand up Azure Sentinel instance. Port existing hunting hypotheses (developed from IDF context) into KQL analytics rules against the AuditLogs and SigninLogs schemas. Validate against Stratus Red Team Azure technique simulations.

5. **Month 3-4:** Build first ML detection artifact: Isolation Forest on CloudTrail IAM events, using features derived from APT behavioral knowledge. Evaluate against CloudGoat attack replays. Write this up as a technical blog post with open-source code.

6. **Parallel:** Begin reading *SoK: An Analysis of Cloud IAM (IEEE 2022)* to understand the academic landscape and identify open research problems in multi-cloud IAM policy analysis.

---

## Professional Summary

This research log documents the first day of a structured transition from military cyber operations to cloud security research — a transition that is unusual in its starting position. Five years as an IDF APT threat hunting lead and OT security architect, combined with the Hacking Defined Expert certification and GCP Security training, means this program begins approximately 40% complete.

The session's primary output is a rigorous skills mapping that identifies precisely what transfers (APT hunting methodology, detection engineering instincts, offensive tradecraft, network architecture reasoning) and what requires deliberate study (AWS and Azure IAM, Kubernetes attack surface, applied cryptography). This distinction matters because it allows the curriculum to be front-loaded with genuine gaps rather than wasted on re-learning already-mastered skills.

Three research angles of particular value were identified during this session: (1) **Cloud-connected OT security** — the attack surface at the intersection of cloud IAM and industrial control systems is both personally grounded and underexplored in the academic literature; (2) **Nation-state APT behavioral signatures in cloud environments** — empirical APT behavioral knowledge applied to cloud detection modeling is rare enough to be genuinely publishable at top venues; (3) **Adversarial ML evasion against cloud detection models** — translating real APT evasion tradecraft into a formal adversarial ML research framework, targeting USENIX Security or NDSS.

The certification pathway (AWS SAA-C03 → AZ-500 → CKA/CKS → AWS Security Specialty → CCSP → OSCP upgrade) is sequenced to validate platform breadth before specializing into security depth, consistent with how hiring managers at cloud security research organizations evaluate candidates.

The portfolio strategy is clear: every lab exercise produces a public artifact (detection rule, hunting query, attack path documentation), and the cumulative body of work constitutes a research portfolio that demonstrates not just knowledge, but the ability to reason from first principles about cloud security problems — which is the distinguishing characteristic of a researcher rather than a practitioner.

---

*Entry 001 of ongoing Cloud Security Research Journal | Program: Personalized Curriculum v3.0 | Domain focus this session: Overview & Program Architecture | Next entry: AWS IAM Policy Evaluation Logic — Deep Dive*
