# Detection Rules

Custom SPL detection rules mapped to MITRE ATT&CK.

| Rule | MITRE ID | Technique | File |
|---|---|---|---|
| Suspicious Account Creation | T1136 | Create Account | [T1136_account_creation.spl](windows/T1136_account_creation.spl) |
| Brute Force Login Attempts | T1110 | Brute Force | [T1110_bruteforce.spl](windows/T1110_bruteforce.spl) |
| Suspicious PowerShell Encoded Command | T1059.001 | PowerShell | [T1059_powershell_encoded.spl](windows/T1059_powershell_encoded.spl) |
| Startup Folder Persistence | T1547.001 | Registry Run Keys / Startup Folder | [T1547_startup_persistence.spl](windows/T1547_startup_persistence.spl) |
