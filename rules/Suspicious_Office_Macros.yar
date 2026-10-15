/* ==========================================================
   SCENARIO 5: Malicious macros or objects in office documents
   ========================================================== */

rule Suspicious_Office_Macros {
    meta:
        description = "Detects macro execution markers and command execution triggers from Office"
        severity = "Medium"
    strings:
        // Document persistence triggers
        $m1 = "AutoOpen" nocase
        $m2 = "Document_Open" nocase
        
        // Automation object strings used to drop or run payloads
        $m3 = "WScript.Shell" nocase
        $m4 = "CreateObject" nocase
    condition:
        ($m1 or $m2) and ($m3 or $m4)
}
