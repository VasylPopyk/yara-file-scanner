/* ==========================================================
   SCENARIO 3: Ransomware Indicators (system modifications and notes)
   ========================================================== */

rule Ransomware_Indicators {
    meta:
        description = "Detects code fragments used for shadow copy deletion and ransom notes"
        severity = "Critical"
    strings:
        // Commands for disabling system recovery mechanisms
        $cmd_shadow = "vssadmin delete shadows" nocase
        $cmd_recovery = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        
        // Common strings found in ransom notes
        $note = "Your files have been encrypted" nocase
        $note2 = "DECRYPT_INSTRUCTION" nocase
    condition:
        any of them
}
