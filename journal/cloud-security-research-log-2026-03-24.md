# 2026-03-24 — S3 Misconfigurations, CodeFinger, and First Look at Sentinel

## Focus
Worked through flaws.cloud levels 1–3 to ground S3 misconfiguration patterns in hands-on context, then studied the CodeFinger ransomware campaign as a real-world case where those patterns get weaponized. Briefly mapped Microsoft Sentinel's data model to understand where cloud detection actually lives.

---

## Key Takeaways

- **The bucket is rarely the real problem.** In flaws.cloud, the bucket is the entry point — but the actual leverage comes from what's *in* it (credentials, config files) and what the associated IAM role is allowed to do. Fixing bucket ACLs without auditing downstream role permissions is cosmetic remediation.

- **CodeFinger uses no malware.** The entire attack — re-encrypting S3 objects under an attacker-controlled KMS key — is executed through legitimate AWS API calls. `PutBucketEncryption` pointing to an external KMS ARN is the pivot. Endpoint security is completely blind to this. Detection lives entirely in CloudTrail management events.

- **S3 data events are opt-in, which means most environments are blind to object-level operations by default.** `CopyObject`, `GetObject`, `DeleteObjectVersion` — the exact calls used in the encryption and cleanup phases of CodeFinger — don't appear in CloudTrail unless data event logging is explicitly enabled per bucket. This is a structural coverage gap, not a tuning problem.

- **Versioning + MFA Delete is the most effective single control against S3 ransomware.** Suspending versioning requires `s3:PutBucketVersioning` — alerting on that call from any non-pipeline principal is a high-signal, low-noise detection with almost no legitimate edge cases.

- **Sentinel's most underused table for credential-based attacks is `AADNonInteractiveUserSignInLogs`.** Interactive sign-ins get all the attention, but stolen token replay (PRT abuse, refresh token theft) shows up almost exclusively in non-interactive sign-in logs. If you're not hunting that table, you have a blind spot for the most common post-phishing Azure lateral movement pattern.

---

## Security Perspective

The CodeFinger pattern generalizes beyond S3. The same "substitute the encryption key" logic applies to RDS (KMS key rotation abuse), EBS snapshots, and Secrets Manager overwrites. Any AWS resource that delegates encryption to KMS and allows key ARN modification via API is a potential target — the attack surface is the intersection of "high-value data" and "modifiable encryption configuration."

Cross-account KMS trust is the root enabler. In environments without an SCP restricting `kms:GenerateDataKey` to key ARNs owned by the organization, an attacker with compromised credentials can silently onboard a victim account onto their key. This is invisible to GuardDuty out of the box.

---

## Detection / Defense Idea

**Alert on `PutBucketEncryption` where the KMS key ARN belongs to an external account.**
This is the single highest-confidence CodeFinger precursor signal. In environments that don't use cross-account KMS intentionally, it should be a critical-severity alert with near-zero false positives.

```yaml
title: S3 Encryption Reconfigured to External KMS Key
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: PutBucketEncryption
    requestParameters.serverSideEncryptionConfiguration.rules.applyServerSideEncryptionByDefault.sseAlgorithm: "aws:kms"
  filter_internal:
    requestParameters.serverSideEncryptionConfiguration.rules.applyServerSideEncryptionByDefault.kmsMasterKeyID|startswith: "arn:aws:kms:*:[YOUR_ACCOUNT_ID]:*"
  condition: selection and not filter_internal
level: critical
tags:
  - attack.t1486
```

**Second signal: `PutBucketVersioning` with `Status: Suspended` from a non-automation principal.** Pair these two events in a timeline and you have a near-certain ransomware preparation sequence.

---

## Notes

- Need to verify: does GuardDuty have a native finding for cross-account KMS usage on S3? Haven't confirmed coverage.
- flaws.cloud levels 4–5 cover EC2 metadata and snapshot misconfigurations — want to trace how IMDS credential theft feeds into the same S3/IAM escalation pattern.
- KQL is approachable but need reps — specifically around `join` performance on high-volume tables like `SigninLogs`. Writing queries that are correct is different from writing queries that are production-ready.
- Open question: what's the realistic cost of enabling S3 data event logging on high-throughput buckets? Is selective logging (by bucket ARN) the standard approach, or do teams use S3 Storage Lens as a cheaper proxy?
