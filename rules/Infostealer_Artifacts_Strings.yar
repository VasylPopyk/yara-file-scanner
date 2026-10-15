/* ==========================================================
   SCENARIO 2: Detection of typical infostealer artifacts
   ========================================================== */

rule Infostealer_Artifacts_Strings {
    meta:
        description = "Searches for paths to browser databases and crypto wallets"
        severity = "High"
    strings:
        // Targeting browser credentials and cryptocurrency data stores
        $path1 = "Login Data" ascii wide
        $path2 = "Wallets\\Exodus" ascii wide
        $path3 = "wallet.dat" ascii wide
        $browser = "AppData\\Local\\Google\\Chrome\\User Data" ascii wide
    condition:
        2 of them
}
