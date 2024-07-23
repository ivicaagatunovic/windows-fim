Param(
    [Parameter(Mandatory=$False)]
    [String] $filesbaseline='False',
    [Parameter(Mandatory=$False)]
    [String] $registrybaseline='False',
    [Parameter(Mandatory=$False)]
    [String] $protectedfilesbaseline='False'
)

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

################################################
# Make Baseline Hashes based on the ossec.conf #
################################################

#Variables
$XMLfile = 'C:\programdata\fim\ossec.conf'
$baselineFile = "C:\programdata\fim\baseline_file_hashes.csv"
$baselineRegistry  = "C:\programdata\fim\baseline_registry.reg"
$baselineProtectedFiles = 'C:\ProgramData\fim\baseline_protected_file_hashes.csv'
$tempFolder = 'C:\programdata\fim\temp'
$logfile = 'C:\ProgramData\fim\logs\baseline.log'
$Separator = '-------------------------------------------------'

#Clear log file content 
Clear-Content -Path $logfile -Force

Write-Log -Level INFO -Message "Starting Baseline Creation Script..." -logfile $logfile

if ($filesbaseline -eq 'True') {

    Write-Log -Level INFO -Message "Starting Files Baseline Creation..." -logfile $logfile

    #Create empty hash
    $XMLFileContentHash = @()
    $XMLFolderContent = @()

    Write-Log -Level INFO -Message "Getting file list from ossec.conf" -logfile $logfile

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

    Write-Log -Level INFO -Message "Calculating files hash..." -logfile $logfile
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

    Write-Log -Level INFO -Message "Exporting files hash to file..." -logfile $logfile
    $results | Sort-Object Path | Export-Csv -Path $baselineFile -NoTypeInformation
    Write-Log -Level INFO -Message "Creating Files Baseline - DONE" -logfile $logfile
}
############################
# Create Registry baseline #
############################
if ($registrybaseline -eq 'True') {

    $XMLRegistryContentHash =@()
    $XMLRegistryExclusions =@()

    #Select the registry keys
    Select-Xml $XMLfile -XPath '/ossec_config/syscheck/windows_registry' | ForEach-Object { $XMLRegistryContentHash += $_.Node.InnerXML }
    Select-Xml $XMLfile -XPath '/ossec_config/syscheck/registry_ignore' | ForEach-Object { $XMLRegistryExclusions += $_.Node.InnerXML }

    Write-Log -Level INFO -Message "Starting Registry Baseline Creation..." -logfile $logfile
    Write-Log -Level INFO -Message "Exporting Registry keys to file..." -logfile $logfile

    #Export registry keys to .reg
    $counter = 0;
    $XMLRegistryContentHash | ForEach-Object {

            $counter++
            Export-Registry -KeyPath $_ -ExportFormat csv -ExportPath "$tempFolder\$counter.reg" -ErrorAction SilentlyContinue
            Write-Log -Level INFO -Message "$_ - DONE" -logfile $logfile
        }

    #Merge Registry Keys into single csv/reg and exclude empty registry keys
    $result = $baselineRegistry
    $csvs = get-childItem "$tempFolder\*.reg" | where {$_.length -ne 0}
    #read and write CSV header
    [System.IO.File]::WriteAllLines($result,[System.IO.File]::ReadAllLines($csvs[0])[0])

    #read and append file contents minus header
    foreach ($csv in $csvs){

            $lines = [System.IO.File]::ReadAllLines($csv)
            [System.IO.File]::AppendAllText($result, ($lines[1..$lines.Length] | Out-String))
        }

    #Remove excluded registry keys defined in ossec.conf
    foreach ($exclusion in $XMLRegistryExclusions){

            (Get-Content $baselineRegistry) -notmatch "$exclusion" | Out-File $baselineRegistry

        }

    Write-Log -Level INFO -Message "Creating Registry Baseline - DONE" -logfile $logfile

}
##########################################################
# Make a baseline for integrity check of protected files #
##########################################################

#Variables
$FilesToMonitor = @("C:\programdata\fim\ossec.conf","C:\programdata\fim\baseline_file_hashes.csv","C:\programdata\fim\baseline_registry.reg","C:\programdata\fim\MakeBaselineHash.ps1","C:\programdata\fim\CheckFileIntegrity.ps1")

if ($protectedfilesbaseline -eq 'True') {

    Write-Log -Level INFO -Message "Starting Protected Files Baseline Creation..." -logfile $logfile
    Write-Log -Level INFO -Message "Calculating files hash..." -logfile $logfile

    #Calculate hashes of provided files
    $hashes =foreach ($item in $FilesToMonitor){

                #Getting the files and continue if the file is not present
                $filehash = Get-FileHash $item -Algorithm MD5 -ErrorAction SilentlyContinue
                if ($fileHash)
                    {
                        [PSCustomObject]@{
                        Hash = $fileHash.Hash
                        Path = $fileHash.Path
                        }
                    }
        }

    #Export file hashes to CSV file
    Write-Log -Level INFO -Message "Exporting files hash to file..." -logfile $logfile

    $hashes | Sort-Object Path | Export-Csv -Path $baselineProtectedFiles -NoTypeInformation

    Write-Log -Level INFO -Message "Creating Protected Files Baseline - DONE" -logfile $logfile

}

#Clean up temp files
Write-Log -Level INFO -Message "Cleaning up temp files..." -logfile $logfile
Remove-Item "$tempFolder\*.reg"

Write-Log -Level INFO -Message "Ending a Baseline Script!!!" -logfile $logfile