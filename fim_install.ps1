# Define variables
$powershell_arguments = '-NoProfile -ExecutionPolicy Bypass -File'
$check_file_integrity_script = 'C:\ProgramData\fim\scripts\CheckFileIntegrity.ps1'
$fimscanscheduletime = '3:00AM' # Adjust this value as needed

# Define paths
$fimFolderPath = 'C:\ProgramData\fim'
$logsFolderPath = 'C:\ProgramData\fim\logs'
$scriptsFolderPath = 'C:\ProgramData\fim\scripts'
$tempFolderPath = 'C:\ProgramData\fim\temp'
$differencesHashesPath = 'C:\ProgramData\fim\differences_hashes.txt'
$differencesRegistryPath = 'C:\ProgramData\fim\differences_registry.txt'
$localScriptsPath = '.\scripts'
$localConfigPath = '.\config'

# Create FIM folder
if (-Not (Test-Path -Path $fimFolderPath)) {
    New-Item -Path $fimFolderPath -ItemType Directory
}

# Set correct rights on folder
$acl = Get-Acl -Path $fimFolderPath
$acl.SetAccessRuleProtection($True, $False)
@(
    [System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'),
    [System.Security.AccessControl.FileSystemAccessRule]::new('Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
) | ForEach-Object { $acl.AddAccessRule($_) }
Set-Acl -Path $fimFolderPath -AclObject $acl

# Create logs folder
if (-Not (Test-Path -Path $logsFolderPath)) {
    New-Item -Path $logsFolderPath -ItemType Directory
}

# Create scripts folder
if (-Not (Test-Path -Path $scriptsFolderPath)) {
    New-Item -Path $scriptsFolderPath -ItemType Directory
}

# Copy scripts to destination folder
Copy-Item -Path "$localScriptsPath\*" -Destination $scriptsFolderPath -Recurse -Force

# Create temp folder
if (-Not (Test-Path -Path $tempFolderPath)) {
    New-Item -Path $tempFolderPath -ItemType Directory
}

# Create differences_hashes.txt
if (-Not (Test-Path -Path $differencesHashesPath)) {
    New-Item -Path $differencesHashesPath -ItemType File
}

# Create differences_registry.txt
if (-Not (Test-Path -Path $differencesRegistryPath)) {
    New-Item -Path $differencesRegistryPath -ItemType File
}

# Copy config files to root of C:\ProgramData\fim
Copy-Item -Path "$localConfigPath\*" -Destination $fimFolderPath -Recurse -Force

# Create the scheduled task for file/registry integrity check
$scheduleTaskName = 'FIM - Check File Integrity'
$scheduleTaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "$powershell_arguments `"$check_file_integrity_script`""
$scheduleTaskTrigger = New-ScheduledTaskTrigger -Daily -At $fimscanscheduletime
$scheduleTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount

Register-ScheduledTask -Action $scheduleTaskAction -Trigger $scheduleTaskTrigger -Principal $scheduleTaskPrincipal -TaskName $scheduleTaskName -Description 'FIM - Check File Integrity' -RunLevel Highest