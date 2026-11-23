$key = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\Security\TrustManager\PromptingLevel'

$defaults = [ordered]@{
MyComputer = 'Enabled'; LocalIntranet = 'Enabled'; Internet = 'AuthenticodeRequired'
TrustedSites = 'Enabled'; UntrustedSites = 'Disabled'
}
$desc = @{
'Enabled' = 'The ClickOnce trust prompt is displayed so that end users can grant trust to ClickOnce applications.'
'Disabled' = "The ClickOnce trust prompt isn't displayed. Only ClickOnce applications that are signed with an explicitly trusted certificate will be installed."
'AuthenticodeRequired' = "The ClickOnce trust prompt is only displayed if ClickOnce applications are signed with a certificate that identifies the publisher. Otherwise, the ClickOnce application won't be installed."
}

$props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
$internet = $null
$rows = foreach ($zone in $defaults.Keys) {
$configured = $props.$zone
$value = if ($configured) { $configured } else { $defaults[$zone] }
$tag = if ($configured) { '' } else { ' (default)' }
if ($zone -eq 'Internet') { $internet = $value }
[PSCustomObject]@{ Zone = $zone; Value = "$value$tag"; Description = $desc[$value] }
}
$rows | Format-List
if ($internet -ne 'Disabled') {
"RESULT: Internet zone is '$internet' (not 'Disabled') - ClickOnce execution from the Internet zone is permitted."
} else {
"RESULT: Internet zone is 'Disabled' - ClickOnce execution from the Internet zone is prevented."
}