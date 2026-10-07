# Detection 002 — Encoded PowerShell Execution

## Objective

Detect PowerShell processes launched with the `-EncodedCommand` parameter or common abbreviated forms.

Encoded PowerShell is not inherently malicious, but attackers may use encoded commands to obscure command content and make analysis more difficult.

## Data Sources

Primary detection source:
- Windows Security Event Log
- Event ID 4688 — Process Creation

Investigation sources:
- PowerShell Operational Event ID 4104 — Script Block Logging
- Sysmon Event ID 1 — Process Creation

Host:
- SOC-WIN01

SIEM:
- Splunk Enterprise

## MITRE ATT&CK

- Tactic: Execution
- Technique: T1059.001 — PowerShell

## Test Activity

A benign PowerShell command was converted to Base64 and executed using PowerShell's `-EncodedCommand` parameter.

The decoded payload was:

Write-Output "SOC Detection Test"

The activity was intentionally generated in the lab and performed no malicious action.

## Detection Logic

The detection monitors Windows Event ID 4688 process creation events.

It identifies `powershell.exe` processes whose command line contains common forms of the encoded-command parameter, including:

- `-enc`
- `-enco`
- `-encod`
- `-encode`
- `-EncodedCommand`

Matching is performed case-insensitively.

The final SPL query is stored in `detection.spl`.

## Control Test

A normal PowerShell process was executed using:

powershell.exe -NoProfile -Command Get-Date

The normal PowerShell execution did not trigger the detection.

The encoded PowerShell execution did trigger the detection.

This demonstrated that the rule does not alert solely because PowerShell was executed.

## Investigation — PowerShell Script Block Logging

After the 4688 detection triggered, PowerShell Event ID 4104 was used to investigate the executed script content.

Script Block Logging exposed the decoded PowerShell content:

Write-Output "SOC Detection Test"

This demonstrates how an analyst can pivot from suspicious encoded execution to the actual PowerShell script content.

## Investigation — Sysmon

Sysmon Event ID 1 provided additional process context.

Observed fields included:

- Image: Windows PowerShell
- Command line containing `-EncodedCommand`
- User: SOC-WIN01\Administrator
- Integrity Level: High
- Parent process: Windows PowerShell
- SHA256 hash of the PowerShell executable

This provided additional context about who executed the process, its privilege level, its parent process, and the executable involved.

## Telemetry Validation and Tuning

During testing, Windows Event ID 4688 was being generated but the Process Command Line field was empty.

The lab configuration was reviewed and the following Windows policies were validated:

- Audit Process Creation — Success
- Include command line in process creation events — Enabled

After applying the policy and refreshing the system configuration, new 4688 events contained the complete process command line.

PowerShell Script Block Logging and Sysmon Event ID 1 were also validated end-to-end from Windows through the Splunk Universal Forwarder into Splunk.

This demonstrated that detection logic depends on correctly configured telemetry and that log-source validation should be performed before relying on a detection.

## Potential False Positives

Possible legitimate uses include:

- Administrative automation
- Deployment scripts
- Management tools
- Software installation
- Authorized PowerShell scripts using encoded arguments

An encoded command should therefore be investigated in context rather than automatically classified as malicious.

Relevant context includes:

- User
- Parent process
- Decoded script content
- Privilege level
- Host
- Related process activity

## Result

The detection successfully identified encoded PowerShell execution while the normal PowerShell control test did not trigger.

Windows Event ID 4688 provided the initial detection, Event ID 4104 exposed the decoded script content, and Sysmon Event ID 1 provided additional process context.

The generated activity was benign lab activity and was not classified as a malicious incident.
