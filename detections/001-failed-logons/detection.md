# Detection 001 — Repeated Failed Logons

## Objective

Detect repeated failed Windows authentication attempts against the same user account within a short period of time.

## Data Source

- Windows Security Event Log
- Event ID: 4625 — An account failed to log on
- Host: SOC-WIN01
- SIEM: Splunk Enterprise

## MITRE ATT&CK

- Tactic: Credential Access
- Technique: T1110 — Brute Force

The detection identifies behavior that may be associated with brute-force activity. Repeated authentication failures alone do not confirm that a brute-force attack occurred.

## Test Activity

A local test account named `soc-test` was created on SOC-WIN01.

Five failed authentication attempts were generated using:

runas /user:soc-test cmd

An incorrect password was deliberately entered five times.

## Initial Detection

The first detection grouped Event ID 4625 events using Splunk's extracted `Account_Name` field.

This produced results for both:

- Administrator
- soc-test

Inspection of the raw 4625 event showed that Windows records multiple account names within the same event.

`Administrator` appeared under the Subject section, while `soc-test` appeared under "Account For Which Logon Failed."

As a result, `Account_Name` was not sufficiently precise for identifying the targeted account.

## Detection Tuning

The detection was modified to extract the account specifically from the "Account For Which Logon Failed" section.

The extracted field was named `TargetUser`.

This eliminated the misleading Administrator result and correctly identified only:

soc-test

## Final Detection Logic

The final detection triggers when the same target account generates at least five Event ID 4625 failures within a five-minute time bucket.

The detection also retains:

- Source network address
- Logon type
- Failure reason
- Host
- Target account
- Number of failed attempts

The final SPL query is stored in `detection.spl`.

## Investigation

The test generated:

- 5 failed logons
- Target account: soc-test
- Event ID: 4625
- Logon Type: 2 (Interactive)
- Source Network Address: ::1 (local IPv6 loopback)
- Failure Reason: Unknown user name or bad password
- Status: 0xC000006D
- Sub Status: 0xC000006A

A successful Event ID 4624 authentication for `soc-test` was later identified.

The successful authentication also used Logon Type 2 and occurred approximately 27 minutes after the final failed attempt.

## Analysis

Five authentication failures followed by a successful authentication can warrant investigation because similar behavior may occur when an attacker eventually obtains or guesses a valid password.

However, this pattern does not by itself prove malicious activity.

In this controlled lab, the events were generated intentionally and are therefore benign test activity.

In a production environment, additional context would be required before escalation.

## Potential False Positives

Possible benign causes include:

- Users repeatedly mistyping passwords
- Recently changed passwords
- Stale stored credentials
- Misconfigured applications or services
- Legitimate administrative testing

## Result

The detection successfully identified repeated failed authentication attempts against the intended target account.

Reviewing the raw event exposed an issue with Splunk's generic `Account_Name` extraction. Extracting the failed target account directly improved the accuracy of the detection and removed misleading results.
