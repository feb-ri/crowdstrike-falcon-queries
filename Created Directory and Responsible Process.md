This query can be used for:

-   Searching for a specific created directory by its name (DirectoryName)
-   Searching for all directories created by a particular process (e.g., powershell.exe) using the process name (ProcessName).

```
(#event_simpleName=ProcessRollup2 FileName=?ProcessName) or (#event_simpleName="DirectoryCreate" FileName=?DirectoryName)
| case {
    #event_simpleName="DirectoryCreate" | rename(field="TargetFileName", as="CreatedDirectoryPath");
    #event_simpleName="ProcessRollup2" | rename(field="CommandLine", as="ResponsibleProcessCommand");
}
| falconPID:=TargetProcessId | falconPID:=ContextProcessId
| selfJoinFilter([aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName="DirectoryCreate"}], prefilter=true)
| groupBy([aid, ComputerName, falconPID], function=([collect([CreatedDirectoryPath, ResponsibleProcessCommand])]))
| CreatedDirectoryPath=* ResponsibleProcessCommand=*
| drop([falconPID])
```
