<#
    Author:  Frank Trout
             CTGlobal Services
             ftr@ctglobalservices.com
    Script:  Convert-ISO2USB.ps1
    Version: 1809 

    This script will format and configure a bootable USB from either a Windows 10 or 
    Server 2016 ISO - splitting the WIM to resolve FAT32 limitations if needed. The 
    script can also import a custom WIM, or autounattend.xml file for automated builds.
#>

Param (
    [Parameter(Mandatory = $true, HelpMessage = "Drive letter of the external USB drive, for example `"E:`" or `"E`" or `"E:\`".")]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1,3)]
    [String]$USBDriveLetter,

    [Parameter(Mandatory = $false, HelpMessage = "Path to custom WIM file.")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('\.wim$')]
    [String]$CustomWIMFile,

    [Parameter(Mandatory = $false, HelpMessage = "Path to autounattend.xml file.")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('\.xml$')]
    [String]$AutoUnattendXML,
    
    [Parameter(Mandatory = $true, HelpMessage = "Path to Windows 10/Server 2016 ISO file.")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('\.iso$')]
    [String]$ISO
)

function Mount-ISO {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path
    )

    $mount = Mount-DiskImage $Path -PassThru
    if(-not($mount)) {
        Write-Warning ($(Get-Date).ToString() +" >> Unable to mount '"+ $Path +"' to system. Script cannot continue.")
        break
    }
    else {
        $result = ($mount | Get-Volume).DriveLetter
        return $result
    }
}

function Format-USBDrive {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$DriveLetter,

        [Parameter(Mandatory = $true)]
        [int]$Size,
    
        [Parameter(Mandatory = $true)]
        [String]$Index
    )
    
    if($Size -gt 32) {
        New-Partition -DiskNumber $Index -Size 32GB -IsActive -DriveLetter $DriveLetter | Out-Null
        Format-Volume -DriveLetter $DriveLetter -FileSystem FAT32 -Confirm:$false -ErrorAction Stop | Out-Null
    }
    else {
        New-Partition -DiskNumber $Index -UseMaximumSize -IsActive -DriveLetter $DriveLetter | Out-Null
        Format-Volume -DriveLetter $DriveLetter -FileSystem FAT32 -Confirm:$false -ErrorAction Stop | Out-Null
    }
}

[int]$usbIndexNumber  = $null
$usbDriveLetter  = $USBDriveLetter.Substring(0,1).ToUpper()
[int]$usbDiskSize     = $null
$tempDirPath     = ($env:windir +"\Temp\"+ $(New-Guid))

#// Validate script runs with elevated permissions
if(-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
    Write-Warning ($(Get-Date).ToString() +" >> This script requires Powershell to be executed with elevated privileges. Launch PowerShell as an administrator and run the script again.")
    break 
}
Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> "+ $(Split-Path $SCRIPT:MyInvocation.MyCommand.Path -Leaf) +" executed successfully.") -ForegroundColor Cyan

#// Make sure the USB drive exists and has enough space.
try {
    Get-WmiObject -Class Win32_DiskDrive -ErrorAction Stop | Where-Object { ($_.InterfaceType -eq 'USB') -and ($_.MediaType -eq 'Removable Media') } | % {
        if($(Get-Partition -DiskNumber $_.Index -ErrorAction Stop).DriveLetter -eq $USBDriveLetter) {
            $usbIndexNumber = $_.Index
            $usbDiskSize = [math]::Round($_.Size / 1024MB)
        }
        else {
            Write-Warning ($(Get-Date).ToString() +" >> Unable to locate a compatible USB drive with drive letter '"+ $Script:usbDriveLetter +":'. Make sure you are using the correct format, for example `"E:`" or `"E`" or `"E:\`".")
            break
        }
    }
}
catch {
    Write-Warning ($(Get-Date).ToString() +" >> "+ $Error[0].Exception.Message)
    break
}

if($usbDiskSize -lt 5) {
    Write-Warning ($(Get-Date).ToString() +" >> The USB drive does not have enough space, it is recommended to use a drive with at least 5GB of storage. Script cannot continue.")
    break
}

$wShell = New-Object -ComObject Wscript.Shell
$initAnswer = $wShell.Popup("If you choose to continue, all the data on your USB drive will be deleted.`n`nDo you wish to continue?",0,"Warning",48+4)
if($initAnswer -ne 6) {
    Write-Warning ($(Get-Date).ToString() +" >> User cancelled operation, script has been terminated.")
    break
}
else {
    Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Prepping USB drive at drive index $usbIndexNumber.") -ForegroundColor Cyan
    Update-Disk -Number $usbIndexNumber
    $disk = Get-Disk -Number $usbIndexNumber

    if ($disk.PartitionStyle -ne "RAW") {
        Clear-Disk -Number $usbIndexNumber -RemoveData -RemoveOEM -Confirm:$false
    }
}

#// Create temporary scratch directory
if(Test-Path $tempDirPath) {
    Remove-Item $tempDirPath -Recurse -Force
}

Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Creating temporary working directory at '"+ $tempDirPath +"'.") -ForegroundColor Cyan
try {
    New-Item $tempDirPath -ItemType Dir -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Warning $Error[0].Exception.Message
    break
}
    
#// Mount ISO and get drive letter
$isoDriveLetter = Mount-ISO -Path $ISO
if($isoDriveLetter) {
    Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> ISO successfully mounted to '"+ $isoDriveLetter +":' drive.") -ForegroundColor Cyan
}
else {
    Write-Warning ($(Get-Date).ToString() +" >> Unable to retrive drive letter of mounted ISO. Script cannot continue.")
    #Dismount-DiskImage $ISO -ErrorAction SilentlyContinue
    Remove-Item $tempDirPath -Recurse -Force
    break
}

#// Copy ISO binaries to temp directory
Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Copying the ISO binaries to '"+ $tempDirPath +"'. Please wait...") -ForegroundColor Cyan
try {
    Copy-Item -Path ($isoDriveLetter +":\*") -Destination $tempDirPath -Recurse -Force -ErrorAction Stop
} 
catch {
    Write-Warning  ($(Get-Date).ToString() +" >> "+ $Error[0].Exception.Message)
    Dismount-DiskImage $ISO -ErrorAction SilentlyContinue
    Remove-Item $tempDirPath -Recurse -Force
    break
}

#// Dismount ISO
Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Copy operation completed successfully. Dismounting ISO from '"+ $isoDriveLetter +":' drive.") -ForegroundColor Cyan
try {
    Dismount-DiskImage $ISO -ErrorAction Stop | Out-Null
} 
catch {
    Write-Warning  ($(Get-Date).ToString() +" >> "+ $Error[0].Exception.Message)
    Remove-Item $tempDirPath -Recurse -Force | Out-Null
    break
}

#// Create USB drive
Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Creating the bootable USB drive. Please wait...") -ForegroundColor Cyan
Format-USBDrive -DriveLetter $usbDriveLetter -Index $usbIndexNumber -Size $usbDiskSize
Copy-Item -Path "$tempDirPath\*" -Destination ($usbDriveLetter +":\") -Exclude "install.wim" -Recurse -Force

if($CustomWIMFile) {
    [int]$wimSize = [math]::Round($((Get-ChildItem $CustomWIMFile).Length) / 1MB)
    if($wimSize -gt 4096) {
        Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Custom WIM file exceeds the FAT32 file limitation of 4GB. Splitting WIM before moving to USB. Please wait...")
        New-Item "$tempDirPath\split" -ItemType Dir -Force | Out-Null
        Dism /Split-Image /ImageFile:$CustomWIMFile /SWMFile:"$tempDirPath\split\install.swm" /FileSize:4096 >> $env:windir\Temp\Dism.log
        Copy-Item -Path "$tempDirPath\split\*.swm" -Destination ($usbDriveLetter +":\sources\") -Recurse -Force
    }
    else {
        Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Copying custom WIM file to USB drive. Please wait...") -ForegroundColor Cyan
        Copy-Item -Path $CustomWIMFile -Destination ($usbDriveLetter +":\sources\install.wim") -Force
    }
}
else {
    [int]$wimSize = [math]::Round($((Get-ChildItem "$tempDirPath\sources\install.wim").Length) / 1MB)
    if($wimSize -gt 4096) {
        Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> WIM file exceeds the FAT32 file limitation of 4GB. Splitting WIM before moving to USB. Please wait...") -ForegroundColor Cyan
        New-Item "$tempDirPath\split" -ItemType Dir -Force | Out-Null
        Dism /Split-Image /ImageFile:"$tempDirPath\sources\install.wim" /SWMFile:"$tempDirPath\split\install.swm" /FileSize:4096 >> $env:windir\Temp\Dism.log
        Copy-Item -Path "$tempDirPath\split\*.swm" -Destination ($usbDriveLetter +":\sources\") -Recurse -Force
    }
    else {
        Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Copying WIM file to USB drive. Please wait...") -ForegroundColor Cyan
        Copy-Item -Path "$tempDirPath\sources\install.wim" -Destination ($usbDriveLetter +":\sources\install.wim") -Force
    }
}

if($AutoUnattendXML) {
    Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Moving AutoUnattend.xml file to the root of the USB drive.") -ForegroundColor Cyan
    Copy-Item -Path $AutoUnattendXML -Destination ($usbDriveLetter +":\autounattend.xml") -Force
}

Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Cleaning up temporary files and directories...") -ForegroundColor Cyan
try {
    Remove-Item $tempDirPath -Recurse -Force -ErrorAction Stop
}
catch {
    Write-Warning ("INFORMATION: "+ $(Get-Date).ToString() +" >> "+ $Error[0].Exception.Message) -ForegroundColor Cyan
    break
}
Write-Host ("INFORMATION: "+ $(Get-Date).ToString() +" >> Operation completed successfully.") -ForegroundColor Cyan