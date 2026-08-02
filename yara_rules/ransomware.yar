rule Ransomware_Generic
{
    meta:
        description = "Detects common ransomware behavioral patterns"
        severity     = "critical"
        category     = "ransomware"

    strings:
        $enc1  = "CryptoAPI"          ascii nocase
        $enc2  = "BCryptEncrypt"      ascii
        $enc3  = "CryptEncrypt"       ascii
        $ext1  = ".encrypted"         ascii nocase
        $ext2  = ".locked"            ascii nocase
        $ext3  = ".crypted"           ascii nocase
        $note1 = "YOUR FILES"         ascii nocase
        $note2 = "decrypt"            ascii nocase
        $note3 = "ransom"             ascii nocase
        $note4 = "bitcoin"            ascii nocase
        $del1  = "vssadmin"           ascii nocase
        $del2  = "shadow"             ascii nocase

    condition:
        ( 2 of ($enc*) and 1 of ($note*) )
        or ( 1 of ($del*) and 1 of ($note*) )
        or ( 2 of ($ext*) )
}

rule Ransomware_ShadowCopy_Deletion
{
    meta:
        description = "Detects shadow copy deletion — common ransomware pre-encryption step"
        severity     = "high"
        category     = "ransomware"

    strings:
        $s1 = "vssadmin"              ascii nocase
        $s2 = "delete shadows"        ascii nocase
        $s3 = "wmic shadowcopy"       ascii nocase
        $s4 = "resize shadowstorage"  ascii nocase
        $s5 = "bcdedit"               ascii nocase

    condition:
        any of them
}
