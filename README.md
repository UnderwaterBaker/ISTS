*works on my machine*

1. Download and install MSBuild tools https://aka.ms/vs/17/release/vs_BuildTools.exe
    - Under "Individual Components" in the installer check the latest version of MSVC.
3. Download this repo
4. Open "x64 Native Tools Command Prompt for VS 2022"
5. Go to downloaded repo
6. Run `powershell.exe builder.ps1 <PATH_TO_SHELLCODE> <SHELLCODE_SIZE>` (msfvenom tells you the size)
7. Payload will be in `<REPO LOCATION>\src\sus.exe` (dont touch anything else in there or it will explode and kill everyone in the room)
8. Hopefulyl it works :)

Note:
1. You may need to disable defender when creating your executable as you will have to provide raw shellcode which defender will throw a fit about.
