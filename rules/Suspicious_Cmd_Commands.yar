/* ==========================================================
   SCENARIO 6: Command execution signatures via CMD/Bat
   ========================================================== */

rule Suspicious_Cmd_Commands {
    meta:
        description = "Detects suspicious execution chains using the Windows command line"
        severity = "Medium"
    strings:
        // Native binary execution flags and LOLBAS binaries
        $c1 = "cmd.exe /c" nocase
        $c2 = "cmd.exe /k" nocase
        $c3 = "regsvr32 /s /u /i" nocase
        $c4 = "rundll32" nocase
    condition:
        any of them
}
