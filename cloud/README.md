# Cloud security

AWS ScoutSuite wrappers, Azure checks, Entra ID snippets and Azure DevOps rules.

[Back to repository index](../README.md)

## Contents

| File or folder | Description |
| --- | --- |
| [aws/scoutsuite/scout.ps1](aws/scoutsuite/scout.ps1) | Per-service ScoutSuite wrapper; prompts for credentials. |
| [aws/scoutsuite/scout.txt](aws/scoutsuite/scout.txt) | Distinct, parameterised PowerShell variant with profile and process handling options. |
| [azure/azure-devops/PSRule.Rules.AzureDevOps.zip](azure/azure-devops/PSRule.Rules.AzureDevOps.zip) | Packaged Azure DevOps PSRule rules. |
| [azure/checks/Defender_Standard_Tier_Not_Enabled.txt](azure/checks/Defender_Standard_Tier_Not_Enabled.txt) | Azure configuration review snippet; original filename retained. |
| [azure/checks/OS_and_Data_Disks_Not_Encrypted_with_CMK.txt](azure/checks/OS_and_Data_Disks_Not_Encrypted_with_CMK.txt) | Azure configuration review snippet; original filename retained. |
| [azure/checks/Storage_Not_Encrypted_with_CMK.txt](azure/checks/Storage_Not_Encrypted_with_CMK.txt) | Azure configuration review snippet; original filename retained. |
| [azure/checks/Virtual_Machine_Extensions_Installed.txt](azure/checks/Virtual_Machine_Extensions_Installed.txt) | Azure configuration review snippet; original filename retained. |
| [azure/checks/access_keys_not_rotated_90_days.txt](azure/checks/access_keys_not_rotated_90_days.txt) | Azure configuration review snippet; original filename retained. |
| [azure/checks/activity_log_alert_rules.txt](azure/checks/activity_log_alert_rules.txt) | Azure configuration review snippet; original filename retained. |
| [azure/checks/public_anonymous_access_blob_containers.txt](azure/checks/public_anonymous_access_blob_containers.txt) | Azure configuration review snippet; original filename retained. |
| [azure/snippets/try.txt](azure/snippets/try.txt) | Mixed Entra ID/group and Key Vault snippets, including group membership changes; not solely an audit script. |

## ScoutSuite paths

`aws/scoutsuite/scout.ps1` expects `.\Scripts\scout.exe` relative to the working directory. The `scout.txt` variant defaults to `Scripts\scout.exe` alongside the script and accepts `-ScoutExe` to supply the actual executable path. ScoutSuite itself is not bundled. These existing path assumptions were not changed during categorisation.

The `.txt` variant contains PowerShell source and keeps its original extension.
