#Requires -Version 3.0

Param(
	[parameter(Mandatory=$true)] [string]$environmentprefix,
    [string] $ResourceGroupName = $environmentprefix.ToLowerInvariant() + '_' + 'scv',
    [string] $BaTemplateFile = 'azuredeployba.json',
    [string] $BaTemplateParametersFile = 'azuredeployba.parameters.json',
    [string] $ResourceGroupLocation = 'North Europe',
	[string] $AgentName = $environmentprefix.ToLowerInvariant() + 'buildagent',
	[string]$vmIPPublicDnsName = $AgentName + 'ip',
	[Parameter(Mandatory=$true)]$VSTSAccount,
	[Parameter(Mandatory=$true)]$PersonalAccessToken,
	[Parameter(Mandatory=$true)]$PoolName,
	[Parameter(Mandatory=$true)]$runAsAutoLogon,
	[Parameter(Mandatory=$true)]$vmAdminUserName,
	[Parameter(Mandatory=$true)]$vmAdminPassword
)
if ([string]::IsNullOrEmpty($(Get-AzureRmContext).Account)) {
    Login-AzureRmAccount
}

$PersonalAccessToken = ConvertTo-SecureString "$PersonalAccessToken" -AsPlainText -Force
$vmAdminPassword = ConvertTo-SecureString "$vmAdminPassword" -AsPlainText -Force

$OptionalParameters = New-Object -TypeName Hashtable
$OptionalParameters["VSTSAccount"] = $VSTSAccount
$OptionalParameters["PersonalAccessToken"] = $PersonalAccessToken
$OptionalParameters["vmName"] = $AgentName
$OptionalParameters["PoolName"] = $PoolName
$OptionalParameters["enableAutologon"] = $runAsAutoLogon
$OptionalParameters["vmAdminUserName"] = $vmAdminUserName
$OptionalParameters["vmAdminPassword"] = $vmAdminPassword
$OptionalParameters["vmIPPublicDnsName"] = $vmIPPublicDnsName

# Create or update the resource group using the specified template file and template parameters file
New-AzureRmResourceGroup -Name $ResourceGroupName -Location $ResourceGroupLocation -Verbose -Force

    New-AzureRmResourceGroupDeployment -Name ((Get-ChildItem ($PSScriptRoot + '\' + $BaTemplateFile)).BaseName + '-' + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')) `
                                       -ResourceGroupName $ResourceGroupName `
                                       -TemplateFile ($PSScriptRoot + '\' + $BaTemplateFile) `
                                       -TemplateParameterFile ($PSScriptRoot + '\' + $BaTemplateParametersFile) `
                                       -Force -Verbose `
                                       -ErrorVariable ErrorMessages `
                                       @OptionalParameters