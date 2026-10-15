/* ==========================================================
   SCENARIO 10: Malicious URLs or connection patterns to C2
   ========================================================== */

rule Suspicious_Network_Behaviors {
    meta:
        description = "Detects hardcoded connection strings targeting suspicious or anonymous services"
        severity = "Medium"
    strings:
        // Network protocol structures
        $net1 = "http://" ascii
        $net2 = "https://" ascii
        
        // Anonymous routing domains and text-sharing platforms often used for C2
        $tor = ".onion" nocase
        $pastebin = "pastebin.com/raw/" nocase
    condition:
        ($net1 or $net2) and ($tor or $pastebin)
}
