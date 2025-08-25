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
    @{ KB = "4013081"; CVE = "MS17-017"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS17-017" },
    @{ KB = "4013389"; CVE = "MS17-010"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS17-010" },
    @{ KB = "3199135"; CVE = "MS16-135"; OS = "Windows 8.1"; MinBuild = 9600; MaxBuild = 9600; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-135" },
    @{ KB = "3186973"; CVE = "MS16-111"; OS = "Windows 8.1"; MinBuild = 9600; MaxBuild = 9600; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-111" },
    @{ KB = "3178466"; CVE = "MS16-098"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-098" },
    @{ KB = "3164038"; CVE = "MS16-075"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-075" },
    @{ KB = "3143145"; CVE = "MS16-034"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-034" },
    @{ KB = "3143141"; CVE = "MS16-032"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-032" },
    @{ KB = "3136041"; CVE = "MS16-016"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-016" },
    @{ KB = "3134228"; CVE = "MS16-014"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-014" },
    @{ KB = "3089656"; CVE = "MS15-097"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-097" },
    @{ KB = "3067505"; CVE = "MS15-076"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-076" },
    @{ KB = "3077657"; CVE = "MS15-077"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-077" },
    @{ KB = "3057839"; CVE = "MS15-061"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-061" },
    @{ KB = "3057191"; CVE = "MS15-051"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051" },
    @{ KB = "3031432"; CVE = "MS15-015"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-015" },
    @{ KB = "3036220"; CVE = "MS15-010"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-010" },
    @{ KB = "3023266"; CVE = "MS15-001"; OS = "Windows 10"; MinBuild = 10240; MaxBuild = 19044; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-001" },
    @{ KB = "2989935"; CVE = "MS14-070"; OS = "Windows 8"; MinBuild = 9200; MaxBuild = 9200; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-070" },
    @{ KB = "3011780"; CVE = "MS14-068"; OS = "Windows 8"; MinBuild = 9200; MaxBuild = 9200; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-068" },
    @{ KB = "3000061"; CVE = "MS14-058"; OS = "Windows 8"; MinBuild = 9200; MaxBuild = 9200; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-058" },
    @{ KB = "2992611"; CVE = "MS14-066"; OS = "Windows 8"; MinBuild = 9200; MaxBuild = 9200; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-066" },
    @{ KB = "2975684"; CVE = "MS14-040"; OS = "Windows 8"; MinBuild = 9200; MaxBuild = 9200; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-040" },
    @{ KB = "2914368"; CVE = "MS14-002"; OS = "Windows 8"; MinBuild = 9200; MaxBuild = 9200; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-002" },
    @{ KB = "2850851"; CVE = "MS13-053"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS13-053" },
    @{ KB = "2840221"; CVE = "MS13-046"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS13-046" },
    @{ KB = "2778930"; CVE = "MS13-005"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS13-005" },
    @{ KB = "2671387"; CVE = "MS12-020"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS12-020" },
    @{ KB = "2592799"; CVE = "MS11-080"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-080" },
    @{ KB = "2566454"; CVE = "MS11-062"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-062" },
    @{ KB = "2503665"; CVE = "MS11-046"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-046" },
    @{ KB = "2393802"; CVE = "MS11-011"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-011" },
    @{ KB = "2305420"; CVE = "MS10-092"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-092" },
    @{ KB = "2160329"; CVE = "MS10-048"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-048" },
    @{ KB = "977165";  CVE = "MS10-015"; OS = "Windows 7"; MinBuild = 7601; MaxBuild = 7601; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-015" },
    @{ KB = "958644";  CVE = "MS08-067"; OS = "Windows XP"; MinBuild = 2600; MaxBuild = 2600; URL = "https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS08-067" }
)

Write-Host "`n[>] Verify vulnerability patches on Windows ..." -ForegroundColor Cyan

$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$buildNumber = [int]$osInfo.BuildNumber
$osCaption = $osInfo.Caption
Write-Host "[i] Detect OS : $osCaption (Build $buildNumber)" -ForegroundColor Gray

foreach ($entry in $Vulnerabilities) {
    if ($osCaption -notlike "*$($entry.OS)*") {
        Write-Host "[>] Ignored : $($entry.CVE) — Not applicable (Different OS)" -ForegroundColor DarkGray
        continue
    }
    if ($buildNumber -lt $entry.MinBuild -or $buildNumber -gt $entry.MaxBuild) {
        Write-Host "[>] Ignored : $($entry.CVE) — Out of scope Build ($($entry.MinBuild)-$($entry.MaxBuild))" -ForegroundColor DarkGray
        continue
    }
    try {
        Get-HotFix -Id $entry.KB -ErrorAction Stop | Out-Null
        Write-Host "[*] KB$($entry.KB) installed — Corrected $($entry.CVE)" -ForegroundColor Green
    } catch {
        Write-Warning "`n[!] Vulnerable : $($entry.CVE)"
        Write-Host "    [!] Missing patch : KB$($entry.KB)" -ForegroundColor Yellow
        Write-Host "    [+] Exploit URL : $($entry.URL)" -ForegroundColor Red
    }
}

Write-Host "`n[+] Job finished.`n" -ForegroundColor Cyan
Write-Host "`n[+] Kernel patch audit complete.`n" -ForegroundColor Cyan


