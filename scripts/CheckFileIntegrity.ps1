Function Write-Log {

    <#
        .SYNOPSIS
            Cmdlet will log a message to a file.
        
        .DESCRIPTION
            Cmdlet will log a message to a file.
        
        .PARAMETER Level
            Level of logging("INFO","WARN","ERROR","FATAL","DEBUG")
        
        .PARAMETER Message
            A string representing the message that is going to be written in the file
        
        .PARAMETER logfile
            Path to the log file on the disk
        
        .EXAMPLE
            PS C:\> Write-Log -Level INFO -Message 'Some Event Happened' -Logfile 'C:\logs\logfile.log'
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
    [String]
    $Level = "INFO",

    [Parameter(Mandatory=$True)]
    [string]
    $Message,

    [Parameter(Mandatory=$False)]
    [string]
    $logfile
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If($logfile) {
        Add-Content $logfile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}

function Test-IsRegistryKey
{
    <#
        .SYNOPSIS
            Cmdlet will check if the specified registry key is valid.
        
        .DESCRIPTION
            Cmdlet will check if the specified registry path is valid.
        
        .PARAMETER KeyPath
            A string representing the registry path to check in the PSDrive format IE HKLM:\SOFTWARE
        
        .EXAMPLE
            PS C:\> Test-IsRegistryKey -KeyPath 'value1'
    #>
    
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $KeyPath
    )
    
    if (Test-Path -Path $KeyPath)
    {
        return (Get-Item -Path $KeyPath).PsProvider.Name -match 'Registry'
    }
    else
    {
        return $false
    }
}

function Export-Registry
{
    <#
        .SYNOPSIS
            Export registry item properties.
        
        .DESCRIPTION
            Export item properties for a given registry key.
            
            By default results will be written to the pipeline unless the -ExportFormat parameter is used.
        
        .PARAMETER KeyPath
            A string representing the Key(s) to export in the PsDrive format IE: HKCU:\SOFTWARE\TestSoftware
        
        .PARAMETER ExportFormat
            A string representing the format to use for the export.
        
            Possible values are: 
        
                - CSV
                - XML
        
            PArameter is used in conjunction with the ExportPath paramter.
        
        .PARAMETER ExportPath
            A string representing the path where keys should be exported.
        
        .PARAMETER NoBinaryData
            When parameter is specified any binary data present in the registry key is removed.
        
        .EXAMPLE
            PS C:\> Export-RegistryNew -KeyPath 'HKCU:\SOFTWARE\TestSoftware'
        
        .NOTES
            Additional information about the function.
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'PrintOnly')]
    param
    (
        [Parameter(ParameterSetName = 'PrintOnly',
                Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
                Position = 0,
                HelpMessage = 'Enter a registry path using the PSDrive format (IE: HKCU:\SOFTWARE\TestSoftware')]
        [Parameter(ParameterSetName = 'Export',
                Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('PSPath')]
        [string[]]
        $KeyPath,
        [Parameter(ParameterSetName = 'Export',
                Mandatory = $true)]
        [ValidateSet('xml', 'csv', 'reg', IgnoreCase = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExportFormat,
        [Parameter(ParameterSetName = 'Export',
                Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExportPath,
        [Parameter(ParameterSetName = 'Export')]
        [switch]
        $NoBinaryData
    )
    
    begin
    {
        # Initialize results array        
        [System.Collections.ArrayList]$returnData = @()
    }
    
    process
    {
        # Go through all paths
        #$subkeys = Resolve-Path "$KeyPath\*"
        $subkeys = ((Get-ChildItem $KeyPath -ErrorAction SilentlyContinue -Recurse).Name).Replace("HKEY_LOCAL_MACHINE","HKLM:")
        foreach ($path in $subkeys){
            if ((Test-IsRegistryKey -KeyPath $path) -eq $true)
            {
                Write-Verbose "Getting properties for key: $path"
                
                # Get registry item
                $paramGetItem = @{
                    Path        = $path
                    ErrorAction = 'Stop'
                }
                
                [Microsoft.Win32.RegistryKey]$regItem = Get-Item @paramGetItem
                
                #Sleep to reduce impact on CPU usage
                Sleep -Milliseconds 50
                
                # Get key properties
                [array]$regItemProperties = $regItem.'Property'
                
                if ($regItemProperties.Count -gt 0)
                {
                    # Enumerate properties
                    foreach ($property in $regItemProperties){
                        #Filter out values in binary format to reduce registry monitoring storm
                        if($regItem.GetValueKind($property) -ne 'Binary') {
                            Write-Verbose "Exporting $property"
                        
                            # Append data to return array
                            [void]($returnData.Add([pscustomobject]@{
                                        'Path'  = $regItem
                                        'Name'  = $property
                                        'Value' = $regItem.GetValue($property, $null, 'DoNotExpandEnvironmentNames')
                                        'Type'  = $regItem.GetValueKind($property)
                                    }))
                        }
                    }
                }
                else
                {
                    # Return default object
                    [void]($returnData.Add([pscustomobject]@{
                                'Path'         = $regItem
                                'Name'         = '(Default)'
                                'Value'        = $null
                                'Type'         = 'String'
                            }))
                }
            }
            else
            {
                Write-Warning -Message "Key $path does not exist"
                
                continue
            }
        }
    }
    
    end
    {
        # Check we have results
        if ($null -ne $returnData)
        {
            switch ($PSCmdlet.ParameterSetName)
            {
                'Export'
                {
                    # Remove binary data
                    if ($PSBoundParameters.ContainsKey('NoBinaryData'))
                    {
                        Write-Verbose -Message 'Removing binary data from return values'
                        
                        # Remove binary data
                        $returnData = $returnData | Where-Object { $_.Type -ne 'Binary' }
                    }
                    
                    switch ($ExportFormat)
                    {
                        'csv'
                        {
                            # Export to CSV
                            $returnData | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                        }
                        'xml'
                        {
                            # Export to XML and overwrite
                            $returnData | Export-Clixml -Path $ExportPath -Force
                        }
                    }
                    
                    Write-Verbose -Message "Data written to $ExportPath"
                }
                
                default
                {
                    Write-Verbose -Message 'No data will be exported'
                    
                    # Print on screen only
                    $returnData
                }
            }
        }
        else
        {
            Write-Warning -Message 'No found - No export will be created'
        }
    }
}

#Define variables
$makebaselinescript = "C:\programdata\fim\scripts\MakeBaselineHash.ps1"
$baseStorePath = "C:\programdata\fim\baseline_file_hashes.csv"
$currentStorePath = "C:\programdata\fim\current_file_hashes.csv"
$diffFileStorePath = "C:\programdata\fim\differences_hashes.txt"
$diffProtectedFilesStorePath = "C:\programdata\fim\differences_protected_files_hashes.txt"
$baselineRegistry  = "C:\programdata\fim\baseline_registry.reg"
$baselineProtectedFiles  = "C:\programdata\fim\baseline_protected_file_hashes.csv"
$currentRegistry = "C:\programdata\fim\current_registry.reg"
$currentprotectedfiles = "C:\programdata\fim\current_protected_file_hashes.csv"
$diffRegStorePath = "C:\programdata\fim\differences_registry.txt"
$XMLfile = "C:\programdata\fim\ossec.conf"
$fimlog = "C:\ProgramData\fim\logs\fim.log"
$fimtempFolder = 'C:\programdata\fim\temp'
$eventidstart = 111
$eventidfile = 222
$eventidreg = 333
$eventidprotected = 444
$eventidfinish = 555
$Separator = '--------------------------------------------------'

#Clear log file content 
Clear-Content -Path $fimlog -Force

#Create a dedicated source in WinEventLog
Write-Log -Level INFO -Message "Creating EventLog Source" -logfile $fimlog
New-EventLog -LogName 'Application' -Source 'FIM' -ErrorAction SilentlyContinue

#Create a baseline files if don't exist
if ((Test-Path $baseStorePath) -ne 'True'){

        & "$makebaselinescript" -filesbaseline 'True' -ErrorAction SilentlyContinue

}

if ((Test-Path $baselineRegistry) -ne 'True'){

        & "$makebaselinescript" -registrybaseline 'True' -ErrorAction SilentlyContinue

}

if ((Test-Path $baselineProtectedFiles) -ne 'True'){

        & "$makebaselinescript" -protectedfilesbaseline 'True' -ErrorAction SilentlyContinue

}

Write-Log -Level INFO -Message "Starting files integrity check..." -logfile $fimlog

Write-EventLog -LogName 'Application' -Source 'FIM' -EntryType Information -EventID $eventidstart -Message "File Integrity Scan Started"

$XMLFileContentHash = @()
$XMLFolderContent = @()

Write-Log -Level INFO -Message "Getting file list from ossec.conf" -logfile "$fimlog"
#Select the directories
Select-Xml $XMLfile -XPath '/ossec_config/syscheck/directories' | ForEach-Object { $XMLFileContentHash += $_.Node.InnerXML }

# List and include all the files in a subfolders(if folder specified as a path)
foreach ($path in $XMLFileContentHash){

        if(Test-Path $path) {

            if((Get-Item $path).PSISContainer) {
        
                $XMLFolderContent += ((Get-ChildItem -Path $path -Recurse -File).FullName).Replace("\","/")
        
            }
    }      
}

$XMLFileContentHash = $XMLFileContentHash + $XMLFolderContent

$startime = $(Get-Date)

Write-Log -Level INFO -Message "Scanning the files..." -logfile "$fimlog"
$results =foreach ($file in $XMLFileContentHash){

        #Getting the files and continue if the file is not present
        $filehash = Get-FileHash $file -Algorithm MD5 -ErrorAction SilentlyContinue
        if ($fileHash)
        {
            [PSCustomObject]@{
            Hash = $fileHash.Hash
            Path = $fileHash.Path
            }
        }
}

Write-Log -Level INFO -Message "Files integrity scan finished" -logfile "$fimlog"

Write-Log -Level INFO -Message "Saving scan results to file" -logfile "$fimlog"
#Save to CSV file
$results | Sort-Object Path | Export-Csv -Path $currentStorePath -NoTypeInformation

#Write differences between old and new hashes to a text file
Write-Log -Level INFO -Message "Comparing file baseline hashes with current state..." -logfile "$fimlog"

Compare-Object (Get-Content $baseStorePath)(Get-Content $currentStorePath) | Format-Table -Wrap | Out-File $diffFileStorePath

#Read in text file
$changes = Get-Content -Path $diffFileStorePath

#Write files hash changes in WinEventLog
if($changes) {

    Write-Log -Level WARN -Message "Drift between baseline and current state detected" -logfile "$fimlog"
    Write-EventLog -LogName 'Application' -Source 'FIM' -EntryType Information -EventID $eventidfile -Message "$changes"

}

else {

    Write-Log -Level INFO -Message "No changes made on files since last baseline creation" -logfile "$fimlog"

}

Write-Log -Level INFO -Message "File integrity check - DONE" -logfile "$fimlog"

##############################
# Get Current Registry State #
##############################
Write-Log -Level INFO -Message "Starting Registry Scan..." -logfile "$fimlog"
$XMLRegistryContent =@()
$XMLRegistryExclusions =@()
Write-Log -Level INFO -Message "Getting Registry Keys list from ossec.conf" -logfile "$fimlog"
#Select the registry keys
Select-Xml $XMLfile -XPath '/ossec_config/syscheck/windows_registry' | ForEach-Object { $XMLRegistryContent += $_.Node.InnerXML }
Select-Xml $XMLfile -XPath '/ossec_config/syscheck/registry_ignore' | ForEach-Object { $XMLRegistryExclusions += $_.Node.InnerXML }

Write-Log -Level INFO -Message "Exporting current reg state to file" -logfile "$fimlog"
$i = 0;
$XMLRegistryContent | ForEach-Object {
    $i++
    Export-Registry -KeyPath $_ -ExportFormat csv -ExportPath "$fimtempFolder\$i.reg" -ErrorAction SilentlyContinue
    Write-Log -Level INFO -Message "$_ - DONE" -logfile "$fimlog"
}

#Merge Registry Keys into single csv/reg and exclude empty registry keys
$result = $currentRegistry
$csvs = get-childItem "$fimtempFolder\*.reg" | where {$_.length -ne 0}
[System.IO.File]::WriteAllLines($result,[System.IO.File]::ReadAllLines($csvs[0])[0]) #read and write CSV header

#read and append file contents minus header
foreach ($csv in $csvs){

    $lines = [System.IO.File]::ReadAllLines($csv)
    [System.IO.File]::AppendAllText($result, ($lines[1..$lines.Length] | Out-String))

}

#Remove excluded registry keys defined in ossec.conf
foreach ($exclusion in $XMLRegistryExclusions){

    (Get-Content $currentRegistry) -notmatch "$exclusion" | Out-File $currentRegistry

}

Write-Log -Level INFO -Message "Exporting current reg state - DONE" -logfile "$fimlog"
Write-Log -Level INFO -Message "Comparing Registry current state with registry baseline..." -logfile "$fimlog"

#Write differences between old and new reg to a text file
Compare-Object (Get-Content $baselineRegistry)(Get-Content $currentRegistry) | Format-Table -Wrap -HideTableHeaders | Out-File $diffRegStorePath

#Read in text file
$regchanges = Get-Content -Path $diffRegStorePath

#Write Registry changes in WinEventLog
if($regchanges) {
    
    $characters = ($regchanges | Measure-Object -Character).Characters

    #If winevent message size limit of 32k characters is reached, split the message accross miltiple eventIDs
    if($characters -gt 32000)

        {

            $c = 0
            $k = 100
            $p = 0
            while ($k -le $regchanges.Length)
                {
                    $messagecontent = (($regchanges[$c..$k]).trim())
                    Write-EventLog -LogName 'Application' -Source 'FIM' -EntryType Warning -EventID ($eventidreg + $p) -Message "$messagecontent"
                    $c += 100
                    $k += 100
                    $p += 1
                }

        }
    
    else

        {

            $messagecontent = $regchanges.trim()
            Write-Log -Level WARN -Message "Drift between baseline and current reg state detected" -logfile "$fimlog"
            Write-EventLog -LogName 'Application' -Source 'FIM' -EntryType Warning -EventID $eventidreg -Message "$messagecontent"

        }

}

else{

    Write-Log -Level INFO -Message "No changes made since last baseline creation" -logfile "$fimlog"

}

Write-Log -Level INFO -Message "Registry integrity scan finished" -logfile "$fimlog"

#Clean up temp reg files
Write-Log -Level INFO -Message "Cleanup temp files..." -logfile "$fimlog"

Remove-Item "$fimtempFolder\*.reg" -Force -Recurse -ErrorAction SilentlyContinue

########################################
# Get Current State of protected files #
########################################
$ProtectedFiles = @("C:\programdata\fim\ossec.conf","C:\programdata\fim\baseline_file_hashes.csv","C:\programdata\fim\baseline_registry.reg","C:\programdata\fim\MakeBaselineHash.ps1","C:\programdata\fim\CheckFileIntegrity.ps1")

Write-Log -Level INFO -Message "Starting Protected Files Scan..." -logfile "$fimlog"

$protectedfileshash =foreach ($protectedfile in $ProtectedFiles){
        #Getting the files and continue if the file is not present
        $fileshash = Get-FileHash $protectedfile -Algorithm MD5 -ErrorAction SilentlyContinue
        if ($filesHash)
        {
            [PSCustomObject]@{
            Hash = $filesHash.Hash
            Path = $filesHash.Path
            }
        }
}

Write-Log -Level INFO -Message "Save Scan Results To File..." -logfile "$fimlog"
#Save to CSV file
$protectedfileshash | Sort-Object Path | Export-Csv -Path $currentprotectedfiles -NoTypeInformation

Write-Log -Level INFO -Message "Protected Files Scan Finished" -logfile "$fimlog"
#Write differences between old and new hashes to a text file
Compare-Object (Get-Content $baselineProtectedFiles)(Get-Content $currentprotectedfiles) | Format-Table -Wrap | Out-File $diffProtectedFilesStorePath

#Read in text file
$changes_protected_files = Get-Content -Path $diffProtectedFilesStorePath

#Write files hash changes in WinEventLog
if($changes_protected_files) {

    Write-EventLog -LogName 'Application' -Source 'FIM' -EntryType Information -EventID $eventidprotected -Message "$changes_protected_files"
    Write-Log -Level WARN -Message "Drift between baseline and current protected files state detected" -logfile "$fimlog"    
    
}

else {

    Write-Log -Level INFO -Message "No changes made on protected files since last baseline creation...." -logfile "$fimlog"

}

Write-Log -Level INFO -Message "File integrity check finished!!!" -logfile "$fimlog"

$fulllog = Get-Content -Path $fimlog -Force -ErrorAction SilentlyContinue
Write-EventLog -LogName 'Application' -Source 'FIM' -EntryType Information -EventID $eventidfinish -Message "File Integrity Check Finished: Full execution log: $fulllog"

Write-Log -Level INFO -Message "Creating new baselines based on current state..." -logfile "$fimlog"
& "$makebaselinescript" -filesbaseline 'True' -registrybaseline 'True' -protectedfilesbaseline 'True' -ErrorAction SilentlyContinue
Write-Log -Level INFO -Message "Creating new baselines - DONE" -logfile "$fimlog"