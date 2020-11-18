#include <windows.h>
#include <iostream>
#include <atlbase.h>

std::wstring dllName = L"";
std::wstring processName = L"";
STARTUPINFO processStartupInfo = {0};
PROCESS_INFORMATION processInfo = {0};

int main()
{
	USES_CONVERSION;
	processName = (std::wstring)A2W(SOLUTION_DIR) + L"Dependencies\\InterceptionTest\\InterceptionTest.exe";
	dllName = (std::wstring)A2W(SOLUTION_DIR) + L"Dependencies\\InterceptionDll\\InterceptionDll.dll";
	processStartupInfo.cb = sizeof(processStartupInfo);

	if (CreateProcess(processName.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &processStartupInfo, &processInfo)) {
		HMODULE hKernel = GetModuleHandle(L"KERNEL32.DLL");
		if (hKernel != NULL) {
			FARPROC loadLibrary = GetProcAddress(hKernel, "LoadLibraryW");
			LPVOID vMem = VirtualAllocEx(processInfo.hProcess, NULL, dllName.size() * sizeof(wchar_t) + 1, MEM_COMMIT, PAGE_READWRITE);
			if (vMem != NULL) {
				if (WriteProcessMemory(processInfo.hProcess, vMem, dllName.c_str(), dllName.size() * sizeof(wchar_t) + 1, NULL)) {
					HANDLE hThread = CreateRemoteThread(processInfo.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibrary, vMem, NULL, NULL);
					if (hThread != NULL) {
						WaitForSingleObject(hThread, INFINITE);
						CloseHandle(hThread);

						ResumeThread(processInfo.hThread);
						WaitForSingleObject(processInfo.hProcess, INFINITE);
					}
				}
				VirtualFreeEx(processInfo.hProcess, vMem, 0, MEM_RELEASE);
			}
		}
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
}