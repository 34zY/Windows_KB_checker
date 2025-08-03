# Windows_KB_checker

Run this script in PowerShell to check for missing Windows Kernel security patches

This script checks for missing Windows Kernel security patches. 
It lists known vulnerabilities, their corresponding KBs, CVEs, and public exploit URLs. 
The output indicates whether each KB is installed or missing. If a KB is missing, it provides a warning and a link to the public exploit URL via SecWiki/windows-kernel-exploits github page.
Designed to be user-friendly and informative, it helps users understand their system's security posture regarding kernel vulnerabilities.

Ensure you have the necessary permissions to run this script.

# Usage

```powershell
.\windows_KB_checker.ps1
```

# Disclaimer

I'm not responsible for bad uses of this script.

# References

https://github.com/SecWiki/windows-kernel-exploits
