rule Trojan_RAT_Generic
{
    meta:
        description = "Detects Remote Access Trojan behavioral patterns"
        severity     = "high"
        category     = "trojan"

    strings:
        $inj1 = "CreateRemoteThread"   ascii
        $inj2 = "VirtualAllocEx"       ascii
        $inj3 = "WriteProcessMemory"   ascii
        $cmd1 = "cmd.exe"              ascii nocase
        $cmd2 = "powershell"           ascii nocase
        $net1 = "WSAStartup"           ascii
        $net2 = "socket"               ascii
        $net3 = "connect"              ascii
        $reg1 = "RegSetValueEx"        ascii
        $reg2 = "CurrentVersion\\Run"  ascii nocase

    condition:
        ( 2 of ($inj*) and 2 of ($net*) )
        or ( 1 of ($reg*) and 2 of ($net*) and 1 of ($cmd*) )
}

rule Keylogger_Generic
{
    meta:
        description = "Detects keylogger API usage patterns"
        severity     = "high"
        category     = "spyware"

    strings:
        $k1 = "GetAsyncKeyState"   ascii
        $k2 = "SetWindowsHookEx"   ascii
        $k3 = "WH_KEYBOARD_LL"     ascii
        $k4 = "WH_KEYBOARD"        ascii
        $k5 = "GetKeyState"        ascii
        $k6 = "MapVirtualKey"      ascii

    condition:
        2 of them
}

rule InfoStealer_Credentials
{
    meta:
        description = "Detects credential harvesting and browser data theft"
        severity     = "critical"
        category     = "infostealer"

    strings:
        $a1 = "CryptUnprotectData" ascii
        $a2 = "Login Data"         ascii nocase
        $a3 = "cookies"            ascii nocase
        $a4 = "password"           ascii nocase
        $a5 = "chrome"             ascii nocase
        $a6 = "firefox"            ascii nocase
        $a7 = "credentials"        ascii nocase

    condition:
        ( $a1 and 1 of ($a2, $a3, $a4) )
        or ( 2 of ($a2, $a3, $a5, $a6) )
        or ( $a7 and $a4 )
}

rule Spyware_ScreenCapture
{
    meta:
        description = "Detects screen capture spyware behavior"
        severity     = "high"
        category     = "spyware"

    strings:
        $s1 = "BitBlt"              ascii
        $s2 = "GetDC"               ascii
        $s3 = "CreateCompatibleDC"  ascii
        $s4 = "PrintWindow"         ascii
        $s5 = "screenshot"          ascii nocase

    condition:
        3 of them
}
