# Downloads the Visual Studio Team Services Build Agent and installs on the new machine
# and registers with the Visual Studio Team Services account and build agent pool

# Enable -Verbose option
[CmdletBinding()]
Param(
[Parameter(Mandatory=$true)]$VSTSAccount,
[Parameter(Mandatory=$true)]$PersonalAccessToken,
[Parameter(Mandatory=$true)]$AgentName,
[Parameter(Mandatory=$true)]$PoolName,
[Parameter(Mandatory=$true)]$runAsAutoLogon,
[Parameter(Mandatory=$false)]$vmAdminUserName,
[Parameter(Mandatory=$false)]$vmAdminPassword
)

function PrepMachineForAutologon () {
    # Create a PS session for the user to trigger the creation of the registry entries required for autologon
    $computerName = "localhost"
    $password = ConvertTo-SecureString $vmAdminPassword -AsPlainText -Force
    if ($vmAdminUserName.Split("\").Count -eq 2)
    {
      $domain = $vmAdminUserName.Split("\")[0]
      $userName = $vmAdminUserName.Split('\')[1]
    }
    else
    {
      $domain = $Env:ComputerName
      $userName = $vmAdminUserName
      Write-Verbose "Username constructed to use for creating a PSSession: $domain\\$userName"
    }
   
    $credentials = New-Object System.Management.Automation.PSCredential("$domain\\$userName", $password)
    Enter-PSSession -ComputerName $computerName -Credential $credentials
    Exit-PSSession
  
    $ErrorActionPreference = "stop"
  
    try
    {
      # Check if the HKU drive already exists
      Get-PSDrive -PSProvider Registry -Name HKU | Out-Null
      $canCheckRegistry = $true
    }
    catch [System.Management.Automation.DriveNotFoundException]
    {
      try 
      {
        # Create the HKU drive
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
        $canCheckRegistry = $true
      }
      catch 
      {
        # Ignore the failure to create the drive and go ahead with trying to set the agent up
        Write-Warning "Moving ahead with agent setup as the script failed to create HKU drive necessary for checking if the registry entry for the user's SId exists.\n$_"
      }
    }
  
    # 120 seconds timeout
    $timeout = 120 
  
    # Check if the registry key required for enabling autologon is present on the machine, if not wait for 120 seconds in case the user profile is still getting created
    while ($timeout -ge 0 -and $canCheckRegistry)
    {
      $objUser = New-Object System.Security.Principal.NTAccount($vmAdminUserName)
      $securityId = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
      $securityId = $securityId.Value
  
      if (Test-Path "HKU:\\$securityId")
      {
        if (!(Test-Path "HKU:\\$securityId\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
        {
          New-Item -Path "HKU:\\$securityId\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Force
          Write-Host "Created the registry entry path required to enable autologon."
        }
        
        break
      }
      else
      {
        $timeout -= 10
        Start-Sleep(10)
      }
    }
  
    if ($timeout -lt 0)
    {
      Write-Warning "Failed to find the registry entry for the SId of the user, this is required to enable autologon. Trying to start the agent anyway."
    }
}

Write-Verbose "Entering InstallVSOAgent.ps1" -verbose

$currentLocation = Split-Path -parent $MyInvocation.MyCommand.Definition
Write-Verbose "Current folder: $currentLocation" -verbose

#Create a temporary directory where to download from VSTS the agent package (vsts-agent.zip) and then launch the configuration.
$agentTempFolderName = Join-Path $env:temp ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $agentTempFolderName
Write-Verbose "Temporary Agent download folder: $agentTempFolderName" -verbose

$serverUrl = "https://$VSTSAccount.visualstudio.com"
Write-Verbose "Server URL: $serverUrl" -verbose

$retryCount = 3
$retries = 1
Write-Verbose "Downloading Agent install files" -verbose
do
{
  try
  {
    Write-Verbose "Trying to get download URL for latest VSTS agent release..."
    $latestReleaseDownloadUrl = "https://vstsagentpackage.azureedge.net/agent/2.126.0/vsts-agent-win-x64-2.126.0.zip"
    Invoke-WebRequest -Uri $latestReleaseDownloadUrl -Method Get -OutFile "$agentTempFolderName\agent.zip"
    Write-Verbose "Downloaded agent successfully on attempt $retries" -verbose
    break
  }
  catch
  {
    $exceptionText = ($_ | Out-String).Trim()
    Write-Verbose "Exception occured downloading agent: $exceptionText in try number $retries" -verbose
    $retries++
    Start-Sleep -Seconds 30 
  }
} 
while ($retries -le $retryCount)

# Construct the agent folder under the main (hardcoded) C: drive.
$agentInstallationPath = Join-Path "C:" $AgentName 
# Create the directory for this agent.
New-Item -ItemType Directory -Force -Path $agentInstallationPath 

# Create a folder for the build work
New-Item -ItemType Directory -Force -Path (Join-Path $agentInstallationPath $WorkFolder)

Write-Verbose "Extracting the zip file for the agent" -verbose
$destShellFolder = (new-object -com shell.application).namespace("$agentInstallationPath")
$destShellFolder.CopyHere((new-object -com shell.application).namespace("$agentTempFolderName\agent.zip").Items(),16)

# Removing the ZoneIdentifier from files downloaded from the internet so the plugins can be loaded
# Don't recurse down _work or _diag, those files are not blocked and cause the process to take much longer
Write-Verbose "Unblocking files" -verbose
Get-ChildItem -Recurse -Path $agentInstallationPath | Unblock-File | out-null

# Retrieve the path to the config.cmd file.
$agentConfigPath = [System.IO.Path]::Combine($agentInstallationPath, 'config.cmd')
Write-Verbose "Agent Location = $agentConfigPath" -Verbose
if (![System.IO.File]::Exists($agentConfigPath))
{
    Write-Error "File not found: $agentConfigPath" -Verbose
    return
}

# Call the agent with the configure command and all the options (this creates the settings file) without prompting
# the user or blocking the cmd execution

Write-Verbose "Configuring agent" -Verbose

# Set the current directory to the agent dedicated one previously created.
Push-Location -Path $agentInstallationPath

if ($runAsAutoLogon -ieq "true")
{
  PrepMachineForAutologon

  # Setup the agent with autologon enabled
  .\config.cmd --unattended --url $serverUrl --auth PAT --token $PersonalAccessToken --pool $PoolName --agent $AgentName --runAsAutoLogon --overwriteAutoLogon --windowslogonaccount $vmAdminUserName --windowslogonpassword $vmAdminPassword
}
else 
{
  # Setup the agent as a service
  .\config.cmd --unattended --url $serverUrl --auth PAT --token $PersonalAccessToken --pool $PoolName --agent $AgentName --runasservice
}

Pop-Location

Write-Verbose "Agent install output: $LASTEXITCODE" -Verbose

Write-Verbose "Installing PoshSSDTBuildDeploy from PowerShell Gallery..." -Verbose
Install-Module PoshSSDTBuildDeploy -Force

Write-Verbose "Installing Azure RM from PowerShell Gallery..." -Verbose
Install-Module AzureRM -Force

#deploy 4.7.1
Function Test-NetInstalled {
    
    param(
        [Parameter(Position = 1, mandatory = $false)]
        [String] $DotNetVersion
    )
    [Int] $RegEditDotNet | Out-Null
    [bool] $RequiredVersion = $true
    $OSVersion = (get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName

    
    $dWord = Get-ChildItem "hklm:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" | Get-ItemPropertyValue -Name Release 
    if ($DotNetVersion) {
        switch ($DotNetVersion) {
            "4.5" { $RegEditDotNet = 378389} 
            "4.5.1" { $RegEditDotNet = 378675}
            "4.5.2" { $RegEditDotNet = 379893}
            "4.6" { $RegEditDotNet = 393295}
            "4.6.1" { $RegEditDotNet = 394254}
            "4.6.2" { $RegEditDotNet = 394802}
            "4.7" { $RegEditDotNet = 460798}
            "4.7.1" {
                if ($OSVersion -like "%2016%") {
                    $RegEditDotNet = 461310
                } 
                else {
                    $RegEditDotNet = 461308
                }
            }
            default {$RegEditDotNet = 0}
        }
        if ($dWord -lt $RegEditDotNet -or $RegEditDotNet -eq 0 ) {
            Write-Error "You must have .NET $DotNetVersion installed on this machine to continue!"
            $RequiredVersion = $false
        }
        else {
            Write-Host "At least $DotNetVersion is installed!" -ForegroundColor White -BackgroundColor Red
        }
    }

    switch ($dWord) {
        378389 { $DotNetVersion = "4.5"  }
        378675 { $DotNetVersion = "4.5.1"}
        379893 { $DotNetVersion = "4.5.2" }
        393295 { $DotNetVersion = "4.6"   }
        394254 { $DotNetVersion = "4.6.1" }
        394802 { $DotNetVersion = "4.6.2" }
        460798 { $DotNetVersion = "4.7"   }
        461308 { $DotNetVersion = "4.7.1" }
        461310 { $DotNetVersion = "4.7.1" }
    }
    $DotNetInfo = @{ DotNetVersion = $DotNetVersion; DWORD = $dWord[0]; RequiredVersion = $RequiredVersion}
    return $DotNetInfo
}

function Install-Net471 {
    param ( [string] $WorkingFolder,
        [string] $uri
    )

    $splitArray = $uri -split "/"
    $fileName = $splitArray[-1]
    
    Write-Verbose "Am attempting to install .NET 4.7.1" -Verbose
    $netInstaller = Join-Path -Path $WorkingFolder -ChildPath $fileName
    try {
        Invoke-WebRequest -Uri $uri -OutFile $netInstaller 
    }
    catch {
        Throw $_.Exception
    }
    If ((Test-Path $netInstaller)) {
        "File downloaded!"
    }
    else {
        "Oh dear!"
    }
    "attempting to install .Net 4.7.1..."
    try {
        $args = " /q /norestart"
        $installNet471BuildTools = Start-Process $netInstaller -ArgumentList $args -Wait -PassThru -WorkingDirectory $WorkingFolder -NoNewWindow
    }
    catch {
        $_.Exception
    }
    if ($installNet471BuildTools.ExitCode -eq 0) {
        Write-Host "Install Successful!" -ForegroundColor DarkGreen -BackgroundColor White
    }
    else {
        Write-Error "Something went wrong in installing .NET 4.7.1."
    }
}

$GetDotNetVersion = Test-NetInstalled
$whatIsInstalled = $GetDotNetVersion.DotNetVersion
if ($whatIsInstalled -ne "4.7.1") {
    $net471sdk = "https://download.microsoft.com/download/9/0/1/901B684B-659E-4CBD-BEC8-B3F06967C2E7/NDP471-DevPack-ENU.exe"
    $net471 = "https://download.microsoft.com/download/9/E/6/9E63300C-0941-4B45-A0EC-0008F96DD480/NDP471-KB4033342-x86-x64-AllOS-ENU.exe"
    Install-Net471 -WorkingFolder $agentInstallationPath -uri $net471sdk
    Install-Net471 -WorkingFolder $agentInstallationPath -uri $net471
}
