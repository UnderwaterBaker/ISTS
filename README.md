*works on my machine*

1. Download and install MSBuild tools https://aka.ms/vs/17/release/vs_BuildTools.exe
2. Download this repo
3. Open "x64 Native Tools Command Prompt for VS 2022"
4. Go to downloaded repo
5. Run `powershell.exe builder.ps1 <PATH_TO_SHELLCODE> <SHELLCODE_SIZE>` (msfvenom tells you the size)
6. Payload will be in `<REPO LOCATION>\src\sus.exe` (dont touch anything else in there or it will explode and kill everyone in the room)
7. Hopefulyl it works :)

