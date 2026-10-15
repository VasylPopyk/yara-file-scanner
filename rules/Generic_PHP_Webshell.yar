/* ==========================================================
   SCENARIO 4: Detection of PHP Web Shells
   ========================================================== */

rule Generic_PHP_Webshell {
    meta:
        description = "Detects dangerous system command execution functions within PHP files"
        severity = "High"
    strings:
        // PHP open tag validation
        $php = "<?php" nocase
        
        // Critical system functions commonly exploited by web shells
        $func1 = "eval(" nocase
        $func2 = "assert(" nocase
        $func3 = "system(" nocase
        $func4 = "passthru(" nocase
        $func5 = "shell_exec(" nocase
    condition:
        $php and (any of ($func1, $func2, $func3, $func4, $func5))
}
