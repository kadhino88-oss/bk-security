# Phase 6 Hyper-V lab setup

This prepares a disposable Windows 11 guest for controlled Phase 6 validation. It does not enable Hyper-V, join the guest to a production network, start packet capture, or enable Windows response actions.

## Before creating the VM

1. Enable the Hyper-V Windows feature, then restart Windows. Hyper-V PowerShell tools and the `vmms` service must be available after that restart.
2. Download a Windows 11 ISO from Microsoft's official [Windows 11 download page](https://www.microsoft.com/software-download/windows11).
3. Confirm that the physical host CPU is on Microsoft's [supported Windows 11 processor list](https://learn.microsoft.com/en-us/windows-hardware/design/minimum/supported/windows-11-supported-intel-processors). A Windows 11 VM requires a supported host CPU; this script's virtual TPM and Secure Boot settings do not bypass that requirement.
4. Keep at least 5 GB of host RAM available and 35 GB free on the volume used for the VM. This host has 8 GB total RAM. On 2026-10-19, available RAM was 0.94 GB before and 2.69 GB after closing Claude and browser processes; it still did not meet the script's memory preflight. 16 GB or more is more comfortable.
5. Pass the ISO path to this script. Do not open the ISO's setup program on the physical host; that starts Windows Setup on the host instead of creating the isolated guest.
6. Run PowerShell as Administrator from the project directory.

## Current host assessment — 2026-10-19

The current host reports an Intel Core i5-6300U. This model is not listed as a supported Windows 11 processor, so this host cannot provide a supported Windows 11 guest for Phase 6 validation. The CPU does advertise Intel VT-x with EPT, which may allow Hyper-V itself to run, but that does not satisfy Windows 11's guest CPU requirement. Do not bypass Windows Setup's CPU check for release validation. Use a separate Hyper-V host with a supported Windows 11 processor and sufficient free RAM for the VM.

The host TPM is distinct from the guest TPM: the script enables a virtual TPM for the Generation 2 guest. This satisfies the guest TPM configuration requirement independently of whether the physical host exposes TPM 2.0; it does not make an unsupported host processor supported. See Microsoft's [Windows 11 VM requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements) and Intel's [i5-6300U specifications](https://www.intel.com/content/www/us/en/products/sku/88190/intel-core-i56300u-processor-3m-cache-up-to-3-00-ghz/specifications.html).

## Create the isolated guest

The private virtual switch has no host adapter or external uplink. The guest cannot reach the host LAN or the Internet. VMConnect provides the host's out-of-band console.

```powershell
pwsh -File .\scripts\prepare_phase6_hyperv_lab.ps1 `
  -Action Create `
  -WindowsIsoPath 'C:\path\to\Windows11.iso' `
  -ProductInstallerPath '.\dist\windows-20261018-230555-2ab368\BK Security Setup 1.0.0.exe'
```

The optional product installer is copied to a separate 2 GB transfer VHDX containing only that installer and attached to the VM. In Windows Setup, install Windows, then install BK Security from the transfer disk. The VM is Gen 2, Secure Boot enabled, vTPM enabled, two vCPUs, 4 GB fixed RAM, and an 80 GB dynamically allocated disk.

Do not run live response tests just because the VM exists. The Phase 6 protocol remains NO-GO until a reviewed, reversible adapter, audit checks, rollback, a successful baseline checkpoint, and a separate target-and-window approval are in place.

## Record and restore a baseline

After installing Windows and BK Security, cleanly shut down the guest and create a named checkpoint:

```powershell
pwsh -File .\scripts\prepare_phase6_hyperv_lab.ps1 -Action Checkpoint
```

Verify the checkpoint appears in Hyper-V Manager before testing. To restore the baseline later, shut down the guest and run this command; it asks for confirmation because it discards VM changes made after the checkpoint:

```powershell
pwsh -File .\scripts\prepare_phase6_hyperv_lab.ps1 -Action Restore -Confirm
```

The script refuses to overwrite an existing VM, switch, transfer disk, or checkpoint. It fails if Hyper-V is not fully active after restart, if the ISO is missing, or if the host lacks the required free memory or disk space.
