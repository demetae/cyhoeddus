$srv = Get-SmbServerConfiguration
$cli = Get-SmbClientConfiguration

$rows = @(
[PSCustomObject]@{
Role='Server'; Parameter='EnableSMB1Protocol'; Value=$srv.EnableSMB1Protocol; Expected='<False>'
Description = if ($srv.EnableSMB1Protocol) { 'The SMB1 protocol is enabled.' } else { 'The SMB1 protocol is disabled.' }
}
[PSCustomObject]@{
Role='Server'; Parameter='RequireSecuritySignature'; Value=$srv.RequireSecuritySignature; Expected='<True>'
Description = if ($srv.RequireSecuritySignature) { 'Security signature (SMB signing) is required.' } else { 'Security signature (SMB signing) is not required.' }
}
[PSCustomObject]@{
Role='Server'; Parameter='SmbServerNameHardeningLevel'; Value=$srv.SmbServerNameHardeningLevel; Expected='<1|2>'
Description = switch ($srv.SmbServerNameHardeningLevel) {
1 { 'Accept if provided by client. The SPN is validated by the SMB server if sent by the client.' }
2 { 'Required from client. The SPN must be sent by the client and is validated by the SMB server.' }
default { 'Off (default). An SPN does not need to be sent by the SMB client. It is not required or validated by the SMB server.' }
}
}
[PSCustomObject]@{
Role='Client'; Parameter='RequireSecuritySignature'; Value=$cli.RequireSecuritySignature; Expected='<True>'
Description = if ($cli.RequireSecuritySignature) { 'Security signature (SMB signing) is required.' } else { 'Security signature (SMB signing) is not required.' }
}
)
$rows | Format-List Role, Parameter, Value, Expected, Description