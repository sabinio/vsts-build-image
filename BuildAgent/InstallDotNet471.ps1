
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
