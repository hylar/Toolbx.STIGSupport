function Compare-RegistryDWord {
	<#
	.SYNOPSIS
		This checks the registry for the provided key value and returns a results hashtable.

	.PARAMETER KeyPath
		The full path to the registry Key
	.PARAMETER ValueName
		The name of the target value
	.PARAMETER Expected
		The expected value of the registry setting
	#>
	Param
	(
		[Parameter(Mandatory = $true)]
		[string]$KeyPath,
		[Parameter(Mandatory = $true)]
		[string]$ValueName,
		[Parameter(Mandatory = $true)]
		[int]$Expected
	)

	Write-Verbose "[$($MyInvocation.MyCommand)]Checking - $KeyPath $ValueName"

	# Initial Variables
	$Results = @{
		VulnID   = ""
		RuleID   = ""
		Details  = ""
		Comments = ""
		Status   = "Not_Reviewed"
	}

	$key = (Get-ItemProperty $KeyPath -Name $ValueName -ErrorAction SilentlyContinue);

	if (!$key) {
		$Results.Details = "Registry value at $keyPath with name $valueName was not found!";
		$Results.Status = "Open";
	}
	else {
		[int]$value = $key.$valueName;
		if ($value -eq $Expected) {
			$Results.Status = "NotAFinding";
			$Results.Details = "$valueName is set to $value. See comments for details.";
		}
		else {
			$Results.Status = "Open";
			$Results.Details = "$valueName is set to $value, instead of $pass! See comments for details.";
		}
	}

	$Results.Comments = $key | Select-Object PSPath,PSChildName,$ValueName | Out-String;

	return $Results;
}