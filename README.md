# Windows-Fim
File Integrity Monitoring (FIM) PowerShell Scripts

# Overview
These PowerShell scripts are designed to provide File Integrity Monitoring (FIM) capabilities. The primary script, CheckFileIntegrity.ps1, checks the integrity of specified files and registry keys by comparing their current state with a previously saved baseline. The second script, MakeBaselineHash.ps1, generates the initial baselines for files and registry keys.

# Configuration
The script relies on an XML configuration file (wazuh ossec.conf) to specify the directories and registry keys to monitor.

# XML Configuration (ossec.conf)
- Directories: <syscheck><directories>...</directories></syscheck>
- Registry Keys: <syscheck><windows_registry>...</windows_registry></syscheck>
- Registry Exclusions: <syscheck><registry_ignore>...</registry_ignore></syscheck>

# Installation
Fim_Install.ps1 script will create a folder structure, create/copy all needed files to ProgramData and create a schedule task to execute FIM scan

# Local log
All log messages are written to a log file located at C:\ProgramData\fim\logs\fim.log.

# Windows Event Log
Events are logged to the Windows Event Log under the Application log with the source FIM.
Event IDs
- 111: File Integrity Scan Started
- 222: File changes detected
- 333: Registry changes detected
- 444: Protected files changes detected
- 555: File Integrity Check Finished

# File Paths
- Baseline File Hashes: C:\programdata\fim\baseline_file_hashes.csv
- Current File Hashes: C:\programdata\fim\current_file_hashes.csv
- Differences in File Hashes: C:\programdata\fim\differences_hashes.txt
- Baseline Registry: C:\programdata\fim\baseline_registry.reg
- Current Registry: C:\programdata\fim\current_registry.reg
- Differences in Registry: C:\programdata\fim\differences_registry.txt
- Baseline Protected Files: C:\programdata\fim\baseline_protected_file_hashes.csv
- Current Protected Files: C:\programdata\fim\current_protected_file_hashes.csv
- Differences in Protected Files: C:\programdata\fim\differences_protected_files_hashes.txt
- Log File: C:\ProgramData\fim\logs\fim.log
- Temp Folder: C:\programdata\fim\temp

# Notes
Ensure you have the necessary permissions to read the files and registry keys and to write to the log and baseline files.
The scripts are designed to handle large amounts of data, but performance may vary based on the system and number of items monitored.

# Contributing
Feel free to contribute by opening issues or submitting pull requests. Make sure to follow the existing code style and add comments for any new functionality.