# Fixed native telemetry operations for the nonpublishing hosted build study.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Memory", "Cpu", "Stop")]
    [string]$Mode
)

$ErrorActionPreference = "Stop"
switch ($Mode) {
    "Memory" {
        [ordered]@{
            processes = @(Get-CimInstance Win32_Process |
                Select-Object ProcessId, ParentProcessId, Name, WorkingSetSize)
            memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory |
                Select-Object AvailableMBytes, CommittedBytes, CommitLimit,
                    PagesInputPersec, PagesOutputPersec
        } | ConvertTo-Json -Depth 4
    }
    "Cpu" {
        Get-CimInstance Win32_Processor |
            Select-Object Name, NumberOfCores, NumberOfLogicalProcessors |
            ConvertTo-Json
    }
    "Stop" {
        $ownedPid = 0
        if (![int]::TryParse($env:FERRUM_STUDY_CHILD_PID, [ref]$ownedPid) -or $ownedPid -le 0) {
            throw "The study must provide its owned positive process ID"
        }
        taskkill /PID $ownedPid /T /F
        exit $LASTEXITCODE
    }
}
