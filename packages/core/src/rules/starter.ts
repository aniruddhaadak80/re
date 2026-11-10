// Starter rule pack. Written for RevLens; each rule explains itself in meta.description.
export const STARTER_RULES = String.raw`
rule UPX_Packed : packer
{
  meta:
    description = "UPX packer section names or magic"
    severity = "medium"
    attack = "T1027.002"
  strings:
    $a = "UPX0"
    $b = "UPX1"
    $c = "UPX!"
  condition:
    2 of them
}

rule Embedded_PE_Payload : dropper
{
  meta:
    description = "A second MZ PE header appears inside the file, often a dropped payload"
    severity = "medium"
    attack = "T1027.009"
  strings:
    $mz = { 4D 5A 90 00 03 00 00 00 }
    $dos = "This program cannot be run in DOS mode"
  condition:
    #dos > 1 or (#mz > 1 and filesize > 4KB)
}

rule Process_Injection_APIs : injection
{
  meta:
    description = "Classic remote thread process injection API set"
    severity = "high"
    attack = "T1055"
  strings:
    $a = "VirtualAllocEx"
    $b = "WriteProcessMemory"
    $c = "CreateRemoteThread"
    $d = "NtCreateThreadEx"
    $e = "QueueUserAPC"
  condition:
    $a and $b and ($c or $d or $e)
}

rule Keylogger_APIs : collection
{
  meta:
    description = "Keyboard hook or polling APIs used by keyloggers"
    severity = "medium"
    attack = "T1056.001"
  strings:
    $a = "SetWindowsHookExA"
    $b = "SetWindowsHookExW"
    $c = "GetAsyncKeyState"
    $d = "GetKeyboardState"
  condition:
    2 of them
}

rule Anti_Debug_Windows : evasion
{
  meta:
    description = "Debugger detection APIs"
    severity = "low"
    attack = "T1622"
  strings:
    $a = "IsDebuggerPresent"
    $b = "CheckRemoteDebuggerPresent"
    $c = "NtQueryInformationProcess"
    $d = "OutputDebugString"
  condition:
    2 of them
}

rule Linux_Ptrace_AntiDebug : evasion
{
  meta:
    description = "ptrace self attach or TracerPid checks on Linux"
    severity = "low"
    attack = "T1622"
  strings:
    $a = "TracerPid"
    $b = "PTRACE_TRACEME"
    $c = "/proc/self/status"
  condition:
    $a and $c or $b
}

rule Reverse_Shell_Strings : execution
{
  meta:
    description = "Common reverse shell command lines"
    severity = "high"
    attack = "T1059"
  strings:
    $a = "/bin/sh -i" nocase
    $b = "bash -i >& /dev/tcp/" nocase
    $c = "nc -e /bin/" nocase
    $d = /powershell[^\n]{0,40}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ i
  condition:
    any of them
}

rule Crypto_Constants : crypto
{
  meta:
    description = "AES S-box or SHA-256 round constants, a sign of built in cryptography"
    severity = "info"
  strings:
    $aes = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    $sha = { 98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9 }
    $sha_be = { 42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5 }
  condition:
    any of them
}

rule Ransom_Note_Language : impact
{
  meta:
    description = "Ransom note phrases"
    severity = "high"
    attack = "T1486"
  strings:
    $a = "your files have been encrypted" nocase
    $b = "bitcoin" nocase
    $c = "decrypt" nocase
    $d = ".onion" nocase
  condition:
    $a or ($b and $c and $d)
}

rule Crypto_Miner : impact
{
  meta:
    description = "Mining pool protocol or well known miner names"
    severity = "high"
    attack = "T1496"
  strings:
    $a = "stratum+tcp://" nocase
    $b = "xmrig" nocase fullword
    $c = "cryptonight" nocase
    $d = "coinhive" nocase
  condition:
    any of them
}

rule JS_Eval_Decoded : obfuscation
{
  meta:
    description = "JavaScript that evaluates decoded or fetched strings"
    severity = "medium"
    attack = "T1027"
  strings:
    $a = /eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/
    $b = /new\s+Function\s*\(\s*(atob|unescape)\s*\(/
    $c = /eval\s*\(\s*await\s+\(?\s*await\s+fetch\(/
  condition:
    any of them
}

rule NPM_Credential_Stealer : supply_chain
{
  meta:
    description = "Reads npm, ssh or cloud credential files and sends data out"
    severity = "high"
    attack = "T1552.001"
  strings:
    $f1 = ".npmrc"
    $f2 = ".ssh/id_rsa"
    $f3 = ".aws/credentials"
    $f4 = "process.env"
    $n1 = "https.request"
    $n2 = "fetch("
    $n3 = "dns.lookup"
  condition:
    1 of ($f1, $f2, $f3) and $f4 and 1 of ($n*)
}

rule Discord_Token_Grabber : collection
{
  meta:
    description = "Looks for Discord token storage and webhooks"
    severity = "high"
    attack = "T1528"
  strings:
    $a = "discord.com/api/webhooks" nocase
    $b = "Local Storage\\leveldb" nocase
    $c = /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/
  condition:
    $a and ($b or $c)
}
`;
