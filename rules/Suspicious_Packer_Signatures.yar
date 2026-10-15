/* ==========================================================
   SCENARIO 9: Detection of suspicious packers (e.g., UPX or Themida)
   ========================================================== */

rule Suspicious_Packer_Signatures {
    meta:
        description = "Detects signatures indicating packing or obfuscation of PE executables"
        severity = "Medium"
    strings:
        // Hexadecimal signature for MZ header (EXE file)
        $mz = { 4D 5A }
        
        // Standard strings embedded by packing tools
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $themid = "Themida" ascii
    condition:
        $mz at 0 and (any of ($upx1, $upx2, $themid))
}
