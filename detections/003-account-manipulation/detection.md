# Detection 003 — Local Administrator Group Modification

## Objective

Detect when a user account is added to the local **Administrators** group on a Windows system.

Adding an account to this group grants administrative privileges and may indicate privilege escalation, persistence, or unauthorized account manipulation.

## Data Source

Primary detection source:

- Windows Security Event Log
- Event ID 4732 — A member was added to a security-enabled local group

Investigation source:

- Event ID 4720 — A user account was created

## MITRE ATT&CK

- T1098 — Account Manipulation
- T1136.001 — Create Account: Local Account

## Test Activity

A controlled local account was created on the Windows Server:

`svc-backup`

The account was then added to the local Administrators group.

This generated:

- Event ID 4720 when the account was created
- Event ID 4732 when the account was added to Administrators

## Detection Logic

The detection monitors Event ID 4732 and filters for modifications to the local Administrators group.

```spl
host="SOC-WIN01" source="WinEventLog:Security" EventCode=4732
| rex field=_raw "Subject:\s+Security ID:\s+\S+\s+Account Name:\s+(?<ActorUser>\S+)"
| rex field=_raw "Member:\s+Security ID:\s+(?<MemberSID>\S+)"
| rex field=_raw "Group:\s+Security ID:\s+\S+\s+Group Name:\s+(?<TargetGroup>[^\r\n]+)"
| where trim(TargetGroup)="Administrators"
| table _time host ActorUser MemberSID TargetGroup
| sort 0 -_time
```

## Investigation

The Event ID 4732 event showed:

- Actor User: `Administrator`
- Target Group: `Administrators`
- Member SID ending in `-1004`

The 4732 event did not populate the member account name, so the Member SID was used as an investigation pivot.

Event ID 4720 was then reviewed.

The 4720 event showed that the same SID ending in `-1004` belonged to:

`svc-backup`

This established the following sequence:

`svc-backup created → SID assigned → same SID added to Administrators`

The SID was also independently resolved on the Windows endpoint and confirmed to belong to `svc-backup`.

## Analysis

The observed activity represents the creation of a local Windows account followed by the assignment of local administrative privileges.

In this controlled lab, the activity was intentionally generated and is therefore benign.

In a production environment, an unexpected addition to the local Administrators group should be investigated to determine whether the privilege change was authorized.

Relevant context would include:

- Account responsible for the change
- Account receiving administrative privileges
- Whether the account was recently created
- Change-management or administrator activity
- Related process execution
- Other activity associated with the account

## False Positives

Legitimate activity may include:

- Administrator-created support accounts
- Approved service accounts
- IT provisioning
- Authorized privilege changes
- Software deployment or management tools
- Planned administrative maintenance

## Tuning

The detection is restricted to Event ID 4732 where the target group is specifically:

`Administrators`

This prevents additions to unrelated local security groups from triggering this detection.

In a production environment, additional tuning could include:

- Approved administrator accounts
- Known service accounts
- Authorized management systems
- Approved change windows
- Allowlisted administrative activity

## Telemetry Validation

During testing, Windows account-management auditing was validated before finalizing the detection.

Initially:

- Security Group Management auditing was disabled
- User Account Management auditing was disabled

The required Success auditing was enabled for both categories.

After enabling the policies:

- Event ID 4720 was successfully generated when `svc-backup` was created.
- Event ID 4720 was successfully ingested into Splunk.
- Event ID 4732 was successfully generated when the account was added to Administrators.
- Event ID 4732 was successfully ingested into Splunk.
- The SID could be correlated between the account creation and privileged group modification events.

## Result

The detection successfully identified an account being added to the local Administrators group.

Investigation of the Member SID correlated the privileged group modification with the newly created `svc-backup` account.

The test demonstrated the complete detection workflow:

`Account Creation (4720) → SID Correlation → Administrator Group Addition (4732) → Investigation`

**Detection Status: Successful**
