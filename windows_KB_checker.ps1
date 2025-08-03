#################################
# Author: 34ZY
# Date: 2025-08-03
# Version: 1.0
# Description: Windows Kernel Vulnerability Checker
# Usage: Run this script in PowerShell to check for missing Windows Kernel security patches.
#          It will list known vulnerabilities, their corresponding KBs, CVEs, and public exploit URLs.
#          The script will output the status of each KB, indicating whether it is installed or missing.
#          If a KB is missing, it will provide a warning and a link to the public exploit URL.
#          This script is designed to be user-friendly and informative, making it easy
#          for users to understand their system's security posture regarding kernel vulnerabilities.
#################################

$Vulnerabilities = @(
    
    @{ KB = "4013081"; CVE = "MS17-017"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS17-017" },
    @{ KB = "4013389"; CVE = "MS17-010"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS17-010" },
    @{ KB = "3199135"; CVE = "MS16-135"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-135" },
    @{ KB = "3186973"; CVE = "MS16-111"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-111" },
    @{ KB = "3178466"; CVE = "MS16-098"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-098" },
    @{ KB = "3164038"; CVE = "MS16-075"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-075" },
    @{ KB = "3143145"; CVE = "MS16-034"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-034" },
    @{ KB = "3143141"; CVE = "MS16-032"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-032" },
    @{ KB = "3136041"; CVE = "MS16-016"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-016" },
    @{ KB = "3134228"; CVE = "MS16-014"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-014" },
    @{ KB = "3089656"; CVE = "MS15-097"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-097" },
    @{ KB = "3067505"; CVE = "MS15-076"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-076" },
    @{ KB = "3077657"; CVE = "MS15-077"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-077" },
    @{ KB = "3057839"; CVE = "MS15-061"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-061" },
    @{ KB = "3057191"; CVE = "MS15-051"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051" },
    @{ KB = "3031432"; CVE = "MS15-015"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-015" },
    @{ KB = "3036220"; CVE = "MS15-010"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-010" },
    @{ KB = "3023266"; CVE = "MS15-001"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-001" },
    @{ KB = "2989935"; CVE = "MS14-070"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-070" },
    @{ KB = "3011780"; CVE = "MS14-068"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-068" },
    @{ KB = "3000061"; CVE = "MS14-058"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-058" },
    @{ KB = "2992611"; CVE = "MS14-066"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-066" },
    @{ KB = "2975684"; CVE = "MS14-040"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-040" },
    @{ KB = "2914368"; CVE = "MS14-002"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-002" },
    @{ KB = "2850851"; CVE = "MS13-053"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS13-053" },
    @{ KB = "2840221"; CVE = "MS13-046"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS13-046" },
    @{ KB = "2778930"; CVE = "MS13-005"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS13-005" },
    @{ KB = "2671387"; CVE = "MS12-020"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS12-020" },
    @{ KB = "2592799"; CVE = "MS11-080"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-080" },
    @{ KB = "2566454"; CVE = "MS11-062"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-062" },
    @{ KB = "2503665"; CVE = "MS11-046"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-046" },
    @{ KB = "2393802"; CVE = "MS11-011"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-011" },
    @{ KB = "2305420"; CVE = "MS10-092"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-092" },
    @{ KB = "2160329"; CVE = "MS10-048"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-048" },
    @{ KB = "977165";  CVE = "MS10-015"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-015" },
    @{ KB = "958644";  CVE = "MS08-067"; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS08-067" }
)

Write-Host "`n[>] Checking for missing Windows Kernel security patches..." -ForegroundColor Cyan

foreach ($entry in $Vulnerabilities) {
    try {
        $hotfix = Get-HotFix -Id $entry.KB -ErrorAction Stop
        Write-Host "[*] KB$($entry.KB) is installed — patched for $($entry.CVE)" -ForegroundColor Green
    }
    catch {
        Write-Warning "`n[!] POTENTIALLY VULNERABLE: $($entry.CVE)"
        Write-Host "    [!] Missing Patch: KB$($entry.KB)" -ForegroundColor Yellow
        Write-Host "    [+] Exploit URL: $($entry.URL)" -ForegroundColor Red
    }
}

Write-Host "`n[+] Kernel patch audit complete.`n" -ForegroundColor Cyan


