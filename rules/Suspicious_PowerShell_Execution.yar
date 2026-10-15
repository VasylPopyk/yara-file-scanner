/* ==========================================================
   SCENARIO 1: Detection of dangerous PowerShell commands
   ========================================================== */

rule Suspicious_PowerShell_Execution {
    meta:
        description = "Detects hidden or obfuscated PowerShell invocations"
        author = "Student IR"
        severity = "High"
    strings:
        // Basic keywords and execution flags
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "-nop" nocase
        $ps4 = "-w hidden" nocase
    condition:
        $ps1 and (any of ($ps2, $ps3, $ps4))
}
