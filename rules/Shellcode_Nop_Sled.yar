/* ==========================================================
   SCENARIO 7: Standard loader signatures (Shellcode / NOP sled)
   ========================================================== */

rule Shellcode_Nop_Sled {
    meta:
        description = "Detects a classic sequence of NOP instructions or memory-allocation APIs"
        severity = "High"
    strings:
        // Hexadecimal representation of a NOP sled
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        
        // API strings related to process hollowing or injection
        $api_load = "VirtualAlloc" ascii wide
        $api_exec = "CreateThread" ascii wide
    condition:
        $nop_sled or ($api_load and $api_exec)
}
