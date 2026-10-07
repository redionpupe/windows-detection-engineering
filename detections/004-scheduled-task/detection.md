# Detection 004 — Suspicious Scheduled Task Creation

## Objective

Detect the creation of Windows scheduled tasks that execute command or script interpreters commonly associated with malicious execution and persistence.

Scheduled tasks can be abused by attackers to execute commands at a specific time or maintain persistence on a compromised system.

## Data Source

Primary detection source:

- Windows Security Event Log
- Event ID 4698 — A scheduled task was created

Supporting investigation source:

- Event ID 4688 — A new process was created

## MITRE ATT&CK

- T1053.005 — Scheduled Task/Job: Scheduled Task

## Test Activity

A controlled scheduled task named:

`SystemUpdateCheck`

was created on `SOC-WIN01`.

The task was configured to execute:

`cmd.exe`

with arguments that write a harmless test string to:

`C:\Windows\Temp\soc-task-test.txt`

The activity generated:

- Event ID 4688 for execution of `schtasks.exe`
- Event ID 4698 for creation of the scheduled task

No malicious payload was executed.

## Detection Logic

The detection monitors Event ID 4698 and extracts the account responsible for the change, task name, task command, and task arguments.

It then identifies newly created scheduled tasks that execute selected command or script interpreters.

```spl
host="SOC-WIN01" source="WinEventLog:Security" EventCode=4698
| rex field=_raw "Subject:\s+Security ID:\s+\S+\s+Account Name:\s+(?<ActorUser>\S+)"
| rex field=_raw "Task Name:\s+(?<TaskName>[^\r\n]+)"
| rex field=_raw "<Command>(?<TaskCommand>[^<]+)</Command>"
| rex field=_raw "<Arguments>(?<TaskArguments>[^<]+)</Arguments>"
| eval TaskName=trim(TaskName)
| where match(lower(TaskCommand), "(cmd\.exe|powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe|mshta\.exe)")
| table _time host ActorUser TaskName TaskCommand TaskArguments
| sort 0 -_time
```

## Investigation

The Event ID 4698 event showed:

- Actor User: `Administrator`
- Task Name: `\SystemUpdateCheck`
- Task Command: `cmd.exe`
- Task Arguments: command-line arguments used to write the controlled SOC test string to the Windows Temp directory

The task XML contained the complete scheduled-task configuration, including its trigger, execution command, arguments, principal, and execution settings.

Event ID 4688 also showed the execution of `schtasks.exe` used to create `SystemUpdateCheck`.

This provided a second source of telemetry confirming how the scheduled task was created.

## Control Test

A second scheduled task named:

`BenignTaskTest`

was created using:

`C:\Windows\System32\notepad.exe`

The benign task successfully generated Event ID 4698 and was visible in Splunk.

However, it did not match the final detection because `notepad.exe` was not included in the suspicious interpreter list.

The result demonstrated that the detection does not alert on every scheduled-task creation.

## Analysis

Scheduled tasks are commonly used for legitimate Windows administration and software operations, so alerting on every Event ID 4698 would create unnecessary noise.

The detection therefore focuses on scheduled tasks whose actions launch command or script interpreters such as:

- `cmd.exe`
- `powershell.exe`
- `pwsh.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`

The presence of one of these interpreters does not by itself prove malicious activity. It provides a higher-value event for analyst investigation.

## False Positives

Legitimate activity may include:

- Administrative automation
- PowerShell maintenance scripts
- Software deployment systems
- Backup jobs
- IT management tools
- Logon or maintenance scripts
- Approved scheduled administrative tasks

## Tuning

The initial telemetry contained legitimate Windows scheduled-task activity, including Windows Defender and other operating-system tasks.

Rather than alerting on every Event ID 4698, the detection was tuned to focus on scheduled tasks executing selected command and script interpreters.

A benign control task using `notepad.exe` was successfully excluded while the `SystemUpdateCheck` task using `cmd.exe` remained detected.

Further production tuning could include:

- Allowlisting approved task names
- Allowlisting known administrative scripts
- Excluding trusted management systems
- Considering the account creating the task
- Considering unusual task locations or names
- Examining task arguments for suspicious commands
- Correlating task creation with process and endpoint telemetry

## Telemetry Validation

Before generating the test activity, the Windows audit policy for:

`Other Object Access Events`

was checked and found to have auditing disabled.

Success auditing was enabled before the final test activity.

After configuration:

- Event ID 4698 was generated successfully on the Windows endpoint.
- The event was successfully ingested into Splunk.
- Event ID 4688 captured the `schtasks.exe` creation command.
- The scheduled-task XML exposed the configured command and arguments.
- A benign control task also generated Event ID 4698 and was correctly excluded by the final detection.

## Result

The detection successfully identified the controlled `SystemUpdateCheck` scheduled task because its action executed `cmd.exe`.

The `BenignTaskTest` scheduled task using `notepad.exe` did not trigger the final detection.

This demonstrated the complete workflow:

`Scheduled Task Creation → 4698 → Command Extraction → Suspicious Interpreter Detection → 4688 Investigation Pivot → False-Positive Validation`

**Detection Status: Successful**
