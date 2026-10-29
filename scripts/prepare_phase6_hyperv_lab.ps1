[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Create', 'Checkpoint', 'Restore')]
    [string]$Action = 'Create',

    [string]$VmName = 'BKSecurity-Phase6-Lab',
    [string]$SwitchName = 'BKSecurity-Lab-Private',
    [string]$WindowsIsoPath,
    [string]$ProductInstallerPath,
    [string]$CheckpointName = 'BKSecurity-Phase6-Baseline',
    [string]$VmRoot = (Join-Path $env:ProgramData 'BKSecurity\Phase6-VMs'),
    [ValidateRange(4, 8)]
    [int]$MemoryStartupGB = 4,
    [ValidateRange(64, 256)]
    [int]$DiskSizeGB = 80
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell window after restarting Windows.'
    }
}

function Assert-HyperVReady {
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        throw 'Hyper-V PowerShell tools are unavailable. Complete the Windows restart after enabling Hyper-V, then run again.'
    }

    $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
    if ($feature.State -ne 'Enabled') {
        throw "Microsoft-Hyper-V-All is $($feature.State). Enable it and restart Windows before continuing."
    }

    $vmms = Get-Service -Name vmms -ErrorAction Stop
    if ($vmms.Status -ne 'Running') {
        Start-Service -Name vmms
        $vmms = Get-Service -Name vmms
    }
    if ($vmms.Status -ne 'Running') {
        throw 'The Hyper-V Virtual Machine Management service (vmms) is not running.'
    }
}

function Get-FreeBytesForPath([string]$Path) {
    $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    $driveLetter = $root.TrimEnd('\').TrimEnd(':')
    $drive = Get-PSDrive -Name $driveLetter -ErrorAction Stop
    return [int64]$drive.Free
}

function Assert-HostCapacity {
    param([string]$TargetPath)

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $availableBytes = [int64]$os.FreePhysicalMemory * 1KB
    $requiredBytes = [int64]($MemoryStartupGB + 1) * 1GB
    if ($availableBytes -lt $requiredBytes) {
        $availableGB = [math]::Round($availableBytes / 1GB, 1)
        throw "Only $availableGB GB RAM is available. Free at least $($MemoryStartupGB + 1) GB before starting a $MemoryStartupGB GB Windows guest."
    }

    $freeBytes = Get-FreeBytesForPath -Path $TargetPath
    $requiredDiskBytes = 35GB
    if ($freeBytes -lt $requiredDiskBytes) {
        $freeGB = [math]::Round($freeBytes / 1GB, 1)
        throw "Only $freeGB GB is free on the VM volume. Free at least 35 GB for the dynamic guest disk and a restorable checkpoint."
    }

    $totalMemoryGB = [math]::Round(([int64]$os.TotalVisibleMemorySize * 1KB) / 1GB, 1)
    if ($totalMemoryGB -lt 12) {
        Write-Warning "This host has about $totalMemoryGB GB RAM. The 4 GB Windows guest may run slowly; close other apps before starting it."
    }
}

function Assert-Iso([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Provide a downloaded Windows 11 ISO with -WindowsIsoPath. This script does not download an operating system.'
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if ([IO.Path]::GetExtension($resolved) -ne '.iso') {
        throw "The Windows image must be an ISO file: $resolved"
    }
    if ((Get-Item -LiteralPath $resolved).Length -lt 1GB) {
        throw 'The ISO is unexpectedly small. Check that the official Windows installer image finished downloading.'
    }
    return $resolved
}

function Add-InstallerTransferDisk {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Product installer not found: $Path"
    }
    if (-not (Get-Command Mount-VHD -ErrorAction SilentlyContinue)) {
        throw 'Hyper-V storage tools are unavailable; cannot prepare the optional installer transfer disk.'
    }

    $transferPath = Join-Path $VmRoot "$VmName-installer-transfer.vhdx"
    if (Test-Path -LiteralPath $transferPath) {
        throw "Transfer disk already exists; inspect it before retrying: $transferPath"
    }

    New-VHD -Path $transferPath -SizeBytes 2GB -Dynamic | Out-Null
    $mounted = $false
    try {
        $diskImage = Mount-VHD -Path $transferPath -PassThru
        $mounted = $true
        $disk = $diskImage | Get-Disk
        if ($disk.PartitionStyle -eq 'RAW') {
            Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null
        }
        $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
        Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'BK_INSTALLER' -Confirm:$false | Out-Null
        $destination = Join-Path ($partition.DriveLetter + ':\') 'BK Security Setup.exe'
        Copy-Item -LiteralPath $Path -Destination $destination
    }
    finally {
        if ($mounted) { Dismount-VHD -Path $transferPath }
    }
    Add-VMHardDiskDrive -VMName $VmName -Path $transferPath | Out-Null
}

Assert-Administrator
Assert-HyperVReady

switch ($Action) {
    'Create' {
        $resolvedIso = Assert-Iso -Path $WindowsIsoPath
        if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
            throw "VM '$VmName' already exists. Inspect it first; this script will not overwrite or delete it."
        }

        Assert-HostCapacity -TargetPath $VmRoot
        New-Item -ItemType Directory -Path $VmRoot -Force | Out-Null

        $existingSwitch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
        if ($existingSwitch -and $existingSwitch.SwitchType -ne 'Private') {
            throw "Switch '$SwitchName' already exists as $($existingSwitch.SwitchType). Choose a new name; the script will not modify an existing switch."
        }

        $installerPath = $null
        if (-not [string]::IsNullOrWhiteSpace($ProductInstallerPath)) {
            $installerPath = (Resolve-Path -LiteralPath $ProductInstallerPath -ErrorAction Stop).Path
        }

        if ($PSCmdlet.ShouldProcess("VM '$VmName'", 'Create an isolated Windows 11 lab VM and start its installer')) {
            if (-not $existingSwitch) {
                New-VMSwitch -Name $SwitchName -SwitchType Private | Out-Null
            }

            $vhdPath = Join-Path $VmRoot "$VmName.vhdx"
            $vm = New-VM -Name $VmName -Generation 2 -MemoryStartupBytes ($MemoryStartupGB * 1GB) `
                -NewVHDPath $vhdPath -NewVHDSizeBytes ($DiskSizeGB * 1GB) -Path $VmRoot -SwitchName $SwitchName
            Set-VMProcessor -VMName $VmName -Count 2
            Set-VMMemory -VMName $VmName -DynamicMemoryEnabled $false
            Set-VM -VMName $VmName -AutomaticCheckpointsEnabled $false -CheckpointType ProductionOnly
            Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
            Set-VMKeyProtector -VMName $VmName -NewLocalKeyProtector
            Enable-VMTPM -VMName $VmName

            $dvd = Add-VMDvdDrive -VMName $VmName -Path $resolvedIso -PassThru
            Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd
            Add-InstallerTransferDisk -Path $installerPath

            Write-Output "Created '$VmName' on private switch '$SwitchName'; it has no host or internet uplink."
            Write-Output 'The VMConnect console is the out-of-band console. Complete Windows setup there, then install BK Security from the optional read-only installer transfer disk.'
            Start-VM -Name $VmName | Out-Null
            $vmConnect = Join-Path $env:SystemRoot 'System32\vmconnect.exe'
            if (-not (Test-Path -LiteralPath $vmConnect)) {
                throw 'The VM was created and started, but vmconnect.exe was not found. Open Hyper-V Manager and Connect to the VM manually.'
            }
            Start-Process -FilePath $vmConnect -ArgumentList @('localhost', $VmName)
        }
    }

    'Checkpoint' {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        if ($vm.State -ne 'Off') {
            throw "Shut down '$VmName' cleanly before creating the baseline checkpoint; current state is $($vm.State)."
        }
        if (Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction SilentlyContinue) {
            throw "Checkpoint '$CheckpointName' already exists. Choose a new name; existing checkpoints are never replaced."
        }
        if ($PSCmdlet.ShouldProcess("VM '$VmName'", "Create restorable baseline checkpoint '$CheckpointName'")) {
            Checkpoint-VM -VMName $VmName -SnapshotName $CheckpointName -Confirm:$false | Out-Null
            Get-VMSnapshot -VMName $VmName -Name $CheckpointName | Select-Object VMName, Name, CreationTime, SnapshotType
        }
    }

    'Restore' {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        if ($vm.State -ne 'Off') {
            throw "Shut down '$VmName' before restoring a checkpoint; current state is $($vm.State)."
        }
        $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction Stop
        if ($PSCmdlet.ShouldProcess("VM '$VmName'", "Discard post-checkpoint VM changes and restore '$CheckpointName'")) {
            $snapshot | Restore-VMSnapshot -Confirm:$false
        }
    }
}
