#include <windows.h>
#include <iostream>
#include <string>

HANDLE hFile;

int main()
{
	char buffer[16] = {0};
	std::string str = "nice";
	
	hFile = CreateFile(L"db.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	WriteFile(hFile, str.c_str(), str.size(), NULL, NULL);
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	ReadFile(hFile, buffer, 1, NULL, NULL);

	CloseHandle(hFile);
	DeleteFile(L"db.txt");

	HKEY openResult;
	if (RegOpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", &openResult) == ERROR_SUCCESS)
	{
		RegCloseKey(openResult);
	}

	return 0;
}