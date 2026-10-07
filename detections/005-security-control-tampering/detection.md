# Detection 005 — Windows Defender Security-Control Tampering

## Objective

Detect PowerShell activity associated with attempts to disable or modify Microsoft Defender security controls.

Attackers may attempt to weaken endpoint protection before executing additional malicious activity. PowerShell commands that modify Microsoft Defender configuration can therefore provide valuable defense-evasion telemetry.

## Data Source

- Microsoft-Windows-PowerShell/Operational
- Event ID 4104 — PowerShell Script Block Logging

## MITRE ATT&CK

- T1562.001 — Impair Defenses: Disable or Modify Tools

## Test Activity

A safe simulation was performed on `SOC-WIN01`.

The following string was written through PowerShell:

`SIMULATION: Set-MpPreference -DisableRealtimeMonitoring $true`

The command was intentionally treated as text and **did not execute `Set-MpPreference` or disable Microsoft Defender**.

The purpose was to generate controlled Event ID 4104 telemetry containing a command pattern associated with Defender tampering.

## Detection Logic

```spl
host="SOC-WIN01" source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
| rex field=_raw "<EventID[^>]*>(?<EventCode>\d+)</EventID>"
| search EventCode=4104
| where match(lower(_raw), "set-mppreference") AND match(lower(_raw), "disablerealtimemonitoring")
| rex field=_raw "<Data Name='ScriptBlockText'>(?<ScriptBlockText>.*?)</Data>"
| table _time host ScriptBlockText
| sort 0 -_time
```

## Investigation

The detection identified an Event ID 4104 script block containing both:

- `Set-MpPreference`
- `DisableRealtimeMonitoring`

These terms are associated with PowerShell-based modification of Microsoft Defender configuration.

During a real investigation, the analyst should determine:

- Which user executed the PowerShell activity
- Whether the command was actually executed or merely present as text
- What PowerShell process generated the script block
- Whether Defender settings changed
- Whether other suspicious PowerShell commands occurred nearby
- Whether additional execution, persistence, or credential-access activity followed

Event ID 4688, Sysmon Event ID 1, and endpoint security telemetry can be used as additional pivots when available.

## Control Test

Normal PowerShell activity was generated using:

`Get-Date`

The normal command generated PowerShell telemetry but did not match the final detection.

This confirmed that the detection does not alert on every PowerShell script block.

## Analysis

Commands involving `Set-MpPreference` can legitimately be used by administrators to configure Microsoft Defender.

However, modifying settings such as real-time monitoring can also be associated with defense evasion.

The combination of:

`Set-MpPreference`

and:

`DisableRealtimeMonitoring`

therefore represents activity that should be investigated rather than automatically treated as malicious.

The laboratory test simulated the suspicious command pattern only. It does not demonstrate that Microsoft Defender was actually disabled.

## False Positives

Potential legitimate causes include:

- Security administrators modifying Defender settings
- Endpoint-management platforms
- Troubleshooting activity
- Approved security testing
- Administrative PowerShell scripts

## Tuning

In a production environment, the detection could be improved by:

- Allowlisting approved administrative accounts
- Correlating the script block with process-creation telemetry
- Checking whether Defender configuration actually changed
- Adding other high-risk Defender modification parameters
- Correlating with endpoint alerts
- Considering the parent process and execution context

The detection should not treat the presence of suspicious text alone as proof that a security control was successfully impaired.

## Telemetry Validation

PowerShell Script Block Logging had previously been configured for the lab.

Before developing the detection, fresh Event ID 4104 telemetry was confirmed in Splunk.

The controlled Defender-tampering simulation generated Event ID 4104 and was successfully detected.

A normal `Get-Date` control test did not trigger the detection.

## Result

The detection successfully identified PowerShell script-block telemetry containing the simulated Defender tampering pattern while excluding normal PowerShell activity.

The test demonstrated:

`PowerShell Activity → Event ID 4104 → Suspicious Defender Command Pattern → Splunk Detection → Control Test`

**Detection Status: Successful**
