packer {
  required_plugins {
    vmware = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/vmware"
    }
    vagrant = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/vagrant"
    }
  }
}

variable "iso_path" {
  type        = string
  description = "Path to Windows 11 ISO"
}

variable "output_directory" {
  type        = string
  default     = "../boxes"
  description = "Output directory for the Vagrant box"
}

variable "vm_name" {
  type    = string
  default = "WS01"
}

variable "winrm_username" {
  type    = string
  default = "vagrant"
}

variable "winrm_password" {
  type    = string
  default = "vagrant"
}

source "vmware-iso" "windows-11" {
  iso_url      = var.iso_path
  iso_checksum = "none"

  vm_name          = var.vm_name
  guest_os_type    = "windows9-64"
  version          = "19"
  headless         = false
  output_directory = "${var.output_directory}/vmware-${var.vm_name}"

  cpus      = 2
  memory    = 8192
  disk_size = 61440

  disk_adapter_type = "nvme"

  network_adapter_type = "e1000e"
  network              = "nat"

  # Boot command - press keys to boot from CD and start install
  boot_wait    = "5s"
  boot_command = ["<spacebar><wait><spacebar><wait><spacebar><wait5><enter><wait><enter>"]

  # Windows 11 requires TPM - using workaround via registry
  vmx_data = {
    "firmware"           = "efi"
    "uefi.secureBoot.enabled" = "FALSE"
  }

  floppy_files = [
    "../answer_files/win11/autounattend.xml",
    "../scripts/provision/setup-winrm.ps1",
    "../scripts/provision/bypass-tpm.reg"
  ]

  communicator   = "winrm"
  winrm_username = var.winrm_username
  winrm_password = var.winrm_password
  winrm_timeout  = "12h"

  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer Shutdown\""
  shutdown_timeout = "15m"
}

build {
  sources = ["source.vmware-iso.windows-11"]

  provisioner "powershell" {
    inline = [
      "Write-Host 'Disabling Windows Firewall for lab environment...'",
      "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False",
      "",
      "Write-Host 'Enabling Remote Desktop...'",
      "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0",
      "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'",
      "",
      "Write-Host 'Configuring WinRM for Vagrant...'",
      "winrm quickconfig -q",
      "winrm set winrm/config/winrs '@{MaxMemoryPerShellMB=\"2048\"}'",
      "winrm set winrm/config '@{MaxTimeoutms=\"7200000\"}'",
      "winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'",
      "winrm set winrm/config/service/auth '@{Basic=\"true\"}'",
      "Set-Service -Name WinRM -StartupType Automatic",
      "",
      "Write-Host 'Provisioning complete!'"
    ]
  }

  provisioner "windows-restart" {
    restart_timeout = "15m"
  }

  post-processor "vagrant" {
    output               = "${var.output_directory}/windows-11.box"
    vagrantfile_template = "vagrantfile-windows.template"
  }
}
