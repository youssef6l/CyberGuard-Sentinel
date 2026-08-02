rule Evasion_AntiAnalysis
{
    meta:
        description = "Detects anti-VM and anti-debugging techniques"
        severity     = "medium"
        category     = "evasion"

    strings:
        $vm1  = "VMware"                   ascii nocase
        $vm2  = "VirtualBox"               ascii nocase
        $vm3  = "vboxservice"              ascii nocase
        $vm4  = "vmtoolsd"                 ascii nocase
        $dbg1 = "IsDebuggerPresent"        ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $dbg3 = "NtQueryInformationProcess" ascii
        $dbg4 = "OutputDebugString"        ascii

    condition:
        2 of ($vm*)
        or 2 of ($dbg*)
        or ( 1 of ($vm*) and 1 of ($dbg*) )
}

rule Persistence_Registry_RunKey
{
    meta:
        description = "Detects persistence via registry run keys"
        severity     = "high"
        category     = "persistence"

    strings:
        $r1 = "CurrentVersion\\Run"     ascii nocase wide
        $r2 = "CurrentVersion\\RunOnce" ascii nocase wide
        $r3 = "Winlogon"                ascii nocase wide
        $r4 = "RegSetValueEx"           ascii

    condition:
        ( $r4 and 1 of ($r1, $r2, $r3) )
        or 2 of ($r1, $r2, $r3)
}

rule Persistence_Scheduled_Task
{
    meta:
        description = "Detects persistence via scheduled tasks or services"
        severity     = "high"
        category     = "persistence"

    strings:
        $t1 = "schtasks"       ascii nocase
        $t2 = "ITaskService"   ascii
        $t3 = "sc create"      ascii nocase
        $t4 = "CreateService"  ascii
        $t5 = "OpenSCManager"  ascii

    condition:
        1 of ($t1, $t2)
        or 2 of ($t3, $t4, $t5)
}

rule Evasion_ProcessInjection
{
    meta:
        description = "Detects classic process injection technique"
        severity     = "critical"
        category     = "evasion"

    strings:
        $i1 = "OpenProcess"         ascii
        $i2 = "VirtualAllocEx"      ascii
        $i3 = "WriteProcessMemory"  ascii
        $i4 = "CreateRemoteThread"  ascii
        $i5 = "NtCreateThreadEx"    ascii
        $i6 = "QueueUserAPC"        ascii

    condition:
        ( $i1 and $i2 and $i3 and 1 of ($i4, $i5, $i6) )
        or 4 of them
}

rule DownloadExecute_Generic
{
    meta:
        description = "Detects download-and-execute behavior"
        severity     = "high"
        category     = "downloader"

    strings:
        $d1 = "URLDownloadToFile" ascii
        $d2 = "InternetOpenUrl"   ascii
        $d3 = "WinHttpOpen"       ascii
        $d4 = "bitsadmin"         ascii nocase
        $d5 = "certutil"          ascii nocase
        $e1 = "WinExec"           ascii
        $e2 = "CreateProcess"     ascii
        $e3 = "ShellExecute"      ascii

    condition:
        1 of ($d*) and 1 of ($e*)
}
