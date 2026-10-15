/* ==========================================================
   SCENARIO 8: Detection of environment checks or anti-debugging
   ========================================================== */

rule Anti_Debug_Environment_Check {
    meta:
        description = "Detects functions used to identify virtual environments or debuggers"
        severity = "Low"
    strings:
        // Win32 API functions for checking debugger status
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        
        // Common sandbox/virtual machine strings
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
    condition:
        2 of them
}
