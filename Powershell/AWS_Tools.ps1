param( #Accept a profile path from commandline.
    $Path
)

<# Begin ---- Script Setup Operations ---- #>
#Script Module(s)
Import-Module -Name AWSPowershell -Verbose:$False

# Script Author Information
$script:ProgramName = "AWS_Tools"
$script:ProgramDate = "13 Jul 2016"
$script:ProgramAuthor = "Geoffrey Guynn"
$script:ProgramAuthorEmail = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("Z2VvZmZyZXlAZ3V5bm4ub3Jn"))
$script:ProgramVersion = "1.0.0.0"
$script:ProgramCopyright = "Copyright 2016 - Geoffrey Guynn - Free use with attribution AS-IS with no Warranty or Liability"

#Script Information
$script:WorkingFileName = $MyInvocation.MyCommand.Definition
$script:WorkingDirectory = Split-Path $script:WorkingFileName -Parent
$script:AWS_Root = Split-Path $script:WorkingDirectory -Parent
$script:JSON_path = if ($Path) {$Path} Else {Join-Path -Path $script:AWS_Root -ChildPath "\data\profiles\AWS_Ubuntu_Free_Tier.json"}
$script:SessionToken = [Guid]::NewGuid()
$script:KeyStore = ""

#Script Developer Options
$script:VerbosePreference = "Continue"
$script:DebugPreference = "SilentlyContinue"
$script:LogFile = Join-Path -Path $script:WorkingDirectory -ChildPath "logs\$((Get-Date).ToString("yyyy_MM_ddTHHmmss"))_AWS_Tools.log"
<# End ---- Script Setup Operations ---- #>

<# Begin ---- Script Logging ---- #>
Function Log {
    param(
        $Message,
        $Source=$((Get-PSCallStack)[0].Command),
        $Type="Info",
        $Exception,
        $Logfile = $script:LogFile,
        [switch]$Throw,
        [switch]$NoHeader,
        [switch]$NoNewLine,
        [switch]$Verbose
    )

    #Logfile prep
    if ($Logfile){
        $LogFileDirectory = Split-Path $Logfile -Parent
        if ((Test-Path $LogFileDirectory -PathType Container) -eq $False){
            mkdir $LogFileDirectory | Out-Null
        }
    }

    #Timestamp our log entries.
    $Datetime = Get-Date
    $DateTimeStamp = $DateTime.ToString("M/dd/yy h:mm:sstt")
    $TimeStamp = $DateTime.ToString("h:mm:sstt")
    
    #Process exceptions first
    if ($Exception){
        if ($Logfile){"$TimeStamp [Exception][$Source] $Message $($Exception.exception.message).`n$($Exception.exception.stacktrace)" >> $script:LogFile}
        throw "$TimeStamp [Exception][$Source] $Message $($Exception.exception.message)"
    }
    if ($Throw.IsPresent){
        if ($Logfile){"$TimeStamp [Exception][$Source] $Message" >> $script:LogFile}
        throw "$TimeStamp [Exception][$Source] $Message"
    }

    #Process function messages and verbose messages
    if (($Type -eq "Function") -or $Verbose.IsPresent){
        #Even if verbose isn't enabled in console, still log those messages to the file.
        if ($Logfile){"$TimeStamp [$Type][$Source] $Message" >> $script:LogFile}
        if ($script:VerbosePreference -eq "Continue"){
            Write-Verbose "$TimeStamp [$Type][$Source] $Message"
        }
    }
    #Process normal messages
    else {
        #Set colors for normal message types
	    switch($Type){
            "Success"{$printcolors = @{foreground="green"}}
		    "Error"{$printColors = @{foreground="red"}}
		    "Warning"{$printColors = @{foreground="yellow"}}
		    default{$printColors = @{foreground="gray"}}
	    }
        #Message needs headers.
        if ($NoHeader.IsPresent -eq $False){
                if ($Logfile){"$TimeStamp [$Type][$Source] $Message" >> $script:LogFile}
                Write-Host -Object "$TimeStamp [$Type][$Source] $Message" -NoNewline:$($NoNewLine.IsPresent) @printcolors
        }
        #Message uses no headers.
        else {
            if ($Logfile){"$Message" >> $script:LogFile}
            Write-Host -Object "$Message" -NoNewline:$($NoNewLine.IsPresent) @printcolors
        }
    }
}
<# End ---- Script Logging ---- #>

<# Begin ---- AWS Functions ---- #>
Function Get-JSONProfile($Path) {
    BEGIN {
        Log -Type Function -Message "Started execution"
    }
    PROCESS {
        if ( -not $path ){
            Log -Throw -Message "No JSON profile was provided, this script requires a JSON profile to perform actions in AWS."
        }

        if ( -not (Test-Path $Path) ) {
            Log -Throw -Message "Profile JSON $path doesn't exist!"
        }
        else {
            Log -Message "Reading JSON profile from $Path"
            $JSON_Data = Get-Content -Path $Path -Raw | ConvertFrom-Json
        }

        return $JSON_Data
    }
    END {
        Log -Type Function -Message "Finished execution"
    }
}
Function Get-AWSLocalCredentials($Username, $AccessKey, $SecretKey, $CredentialFile) {
    BEGIN {
        Log -Type Function -Message "Started execution"
    }
    PROCESS {
        #The user hardcoded credentials, use them.
        if ($AccessKey -and $SecretKey){
            Log -Message "Using hardcoded credentials."
            Log -Verbose -Message "return @{Username=$Username; AccessKey=********; SecretKey=********}"
            return @{Username=$Username; AccessKey=$AccessKey; SecretKey=$SecretKey}
        }

        #No hardcoded credentials, did they provide a downloaded credentials CSV from AWS?
        if (!$CredentialFile){
            Log -Throw -Message "No AWS access_key/secret_key combo specified and no AWS credential file specified, you must provide one or the other!"
        }

            #Does the CSV exist?
        if (!(Test-Path $CredentialFile -PathType Leaf)){
            Log -Throw -Message "Credential file $CredentialFile doesn't exist!"
        }

        #Read the CSV and look for a matching username. Skip headers if present.
        Log -Message "Reading credentials from $CredentialFile."
        $Credentials = Import-CSV -Path $CredentialFile -Header "Username","AccessKey", "SecretKey" | Select-Object -skip 1
        $UserCredentials = $Credentials | ? {$_.Username -eq $UserName}
        if ($UserCredentials){
            Log -Verbose -Message "return @{Username=$($UserCredentials.Username); AccessKey=********; SecretKey=********}"
            return @{Username=$UserCredentials.Username; AccessKey=$UserCredentials.AccessKey; SecretKey=$UserCredentials.SecretKey}
        }
    
        Log -Throw -Message "No credentials found for $Username in $CredentialFile"
    }
    END {
        Log -Type Function -Message "Finished execution"
    }
}
Function Set-AWSSession($Connection) {
    BEGIN {
        Log -Type Function -Message "Started execution"
    }
    PROCESS {
        if ($Connection.use_default_profile -eq $True) {
            Log -Message "Using credentials from default AWS profile."
            Set-DefaultAWSRegion -Region $Connection.region_name
        return
    }
        else {
            Log -Message "Using credentials from JSON profile."
            $GetCredentials_params = @{
                Username = $Connection.username
                AccessKey = $Connection.access_key
                SecretKey = $Connection.secret_key
                CredentialFile = $Connection.credential_file
            }

            $Credentials = Get-AWSLocalCredentials @GetCredentials_params
            Set-AWSCredentials -AccessKey $Credentials.AccessKey -SecretKey $Credentials.SecretKey -SessionToken $script:SessionToken -Verbose:$False
            
            Log -Message "Setting default region to $($Connection.region_name) for this session."
            Set-DefaultAWSRegion -Region $Connection.region_name
            return
        }
    }
    END {
        Log -Type Function -Message "Finished execution"
    }
}
Function Map-JSONParamsToPowershell($CmdletName, $Hashtable){
    BEGIN {
        Log -Type Function -Message "Started execution"
    }
    PROCESS {    
        if (!$Hashtable){
            Log -Throw -Message "No hashtable passed to Map-JSONParamsToPowershell function!"
        }

        #Param mapping from JSON to PS Cmdlet params
        #This allows one JSON template to be consumed by multiple script languages.
    
        switch($CmdletName){
            "New-EC2Instance" {
                if ($Hashtable.Monitoring){
                    $Hashtable.Add("Monitoring_Enabled", $Instance_Config.Monitoring.Enabled)
                    $Hashtable.Remove("Monitoring")
                }
                if ($Hashtable.Placement.GroupName){
                    $Hashtable.Add("PlacementGroup", $Hashtable.Placement.GroupName)
                }
                if ($Hashtable.Placement.Tenancy){
                    $Hashtable.Add("Tenancy", $Hashtable.Placement.Tenancy)
                }
                if ($Hashtable.Placement.AvailabilityZone){
                   $Hashtable.Add("AvailabilityZone", $Hashtable.Placement.AvailabilityZone)
                }
                if ($Hashtable.Placement){
                    $Hashtable.Remove("Placement")
                }
            }
            default {
                throw "Unrecognized Cmdlet $CmdletName!"
            }
        }

        return $Hashtable
    }
    END {
        Log -Type Function -Message "Finished execution"
    }
}
Function New-KeyPair($Path=$script:KeyStore, $KeyName){
    if (!$Path){
        Log -Throw -Message "Unable to create new keypair $KeyName, no file specified to save the private key!"
    }
    try{
        $KeyPair = New-EC2KeyPair -KeyName $KeyName
        Log -Message "New KeyPair created Name=$KeyName Fingerprint=$($KeyPair.KeyFingerprint)"
        if ((Test-Path $Path -PathType Container) -eq $False){
            mkdir $Path | Out-Null
        }
        $Path = Join-Path -Path $Path -ChildPath "$KeyName.pem"

        $KeyPair.KeyMaterial | Out-File -Encoding ascii $Path
        Log -Message "Private key saved to $Path"
    }
    catch{
        Log -Exception $_
    }

    return $KeyPair
}
Function New-InstancesFromJSON($Instances) {
    BEGIN {
        Log -Type Function -Message "Started execution"
    }
    PROCESS {    
        $reservations = @()

        foreach($Instance in $Instances){
            Log -Message "Creating instance $($Instance.Name)"

            #Check to see if we are going to create a KeyPair
            if ($Instance.create_key){
                if ($Instance.key_store){
                    $KeyPair = New-KeyPair -Path $Instance.key_store -KeyName "$($Instance.name)_$script:SessionToken"
                }
                else{
                    $KeyPair = New-KeyPair -KeyName "$($Instance.name)_$script:SessionToken"
                }

                $Instance.config.KeyName = $KeyPair.KeyName
            }
            if (!$Instance.config.KeyName){
                Log -Type Warning -Message "This instance doesn't have a KeyPair! You will be unable to connect unless the base image comes preloaded with another connection method!"
            }
            
            #Remove null/empty JSON entries
            $Instance_Config = @{}
            ($Instance.config).psobject.Properties | % {if ($_.Value){ $Instance_Config += @{$_.Name = $_.Value }}}

            $Instance_Config = Map-JSONParamsToPowershell -CmdletName "New-EC2Instance" -Hashtable $Instance_Config

            #Splat a hashtable of paramaters into the cmdlet.
            $Reservations += New-EC2Instance @Instance_Config
        }

        return $Reservations
    }
    END {
        Log -Type Function -Message "Finished execution"
    }
}
<# End ---- AWS Functions ---- #>

#Main Execution

#Read the JSON profile data.
$AWS_Profile = Get-JSONProfile -Path $script:JSON_path

#Configure the AWS session settings from JSON profile.
Set-AWSSession -Connection $AWS_Profile.connection

#Create any instances in the JSON profile.
$Reservations = New-InstancesFromJSON -Instances $AWS_Profile.instances