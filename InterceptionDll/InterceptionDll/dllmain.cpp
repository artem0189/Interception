// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include <string>
#include <sstream>
#include <filesystem>
#include <detours.h>

typedef LONG NTSTATUS;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

HANDLE hStdOut;

template <typename T>
std::wstring ConvertToWstring(T value);
std::wstring GetFileName(HANDLE hFile);
std::wstring GetKeyPath(HKEY key);
VOID Detach(PVOID* ppPointer, PVOID pDetour);
VOID Attach(PVOID* ppPointer, PVOID pDetour);
VOID LogMessage(std::wstring message);

HANDLE(WINAPI* PCreateFile) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFile;

HANDLE WINAPI HookCreateFile(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    LogMessage(L"Create file: " + ConvertToWstring(lpFileName));
    return PCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


HFILE(WINAPI* POpenFile) (LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) = OpenFile;

HFILE WINAPI HookOpenFile(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle)
{
    LogMessage(L"Open file: " + ConvertToWstring(lpFileName));
    return POpenFile(lpFileName, lpReOpenBuff, uStyle);
}


BOOL(WINAPI* PReadFile) (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = ReadFile;

BOOL WINAPI HookReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    LogMessage(L"Read from file(" + GetFileName(hFile) + L") " + ConvertToWstring(nNumberOfBytesToRead) + L" bytes");
    return PReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}


BOOL(WINAPI* PWriteFile) (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) = WriteFile;

BOOL WINAPI HookWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    LogMessage(L"Write to file("+ GetFileName(hFile) + L") " + ConvertToWstring(nNumberOfBytesToWrite) + L" bytes");
    return PWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


BOOL(WINAPI* PDeleteFile) (LPCWSTR lpFileName) = DeleteFile;

BOOL WINAPI HookDeleteFile(LPCWSTR lpFileName)
{
    LogMessage(L"Delete file: " + ConvertToWstring(lpFileName));
    return PDeleteFile(lpFileName);
}


LSTATUS(WINAPI* PRegCreateKey) (HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) = RegCreateKey;

LSTATUS WINAPI HookRegCreateKey(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    LogMessage(L"Create key " + ConvertToWstring(lpSubKey));
    return PRegCreateKey(hKey, lpSubKey, phkResult);
}


LSTATUS(WINAPI* PRegOpenKey) (HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) = RegOpenKey;

LSTATUS WINAPI HookRegOpenKey(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    LogMessage(L"Open key " + ConvertToWstring(lpSubKey));
    return PRegOpenKey(hKey, lpSubKey, phkResult);
}


LSTATUS(WINAPI* PRegGetValue) (HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData) = RegGetValue;

LSTATUS WINAPI HookRegGetValue(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
    LogMessage(L"Get value from key" + GetKeyPath(hKey));
    return PRegGetValue(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
}


LSTATUS(WINAPI* PRegSetValue) (HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData) = RegSetValue;

LSTATUS WINAPI HookRegSetValue(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData)
{
    LogMessage(L"Set value " + ConvertToWstring(lpData) + L" to key " + GetKeyPath(hKey));
    return PRegSetValue(hKey, lpSubKey, dwType, lpData, cbData);
}


LSTATUS(WINAPI* PRegCloseKey) (HKEY hKey) = RegCloseKey;

LSTATUS WINAPI HookRegCloseKey(HKEY hKey)
{
    LogMessage(L"Close key " + GetKeyPath(hKey));
    return PRegCloseKey(hKey);
}


LSTATUS(WINAPI* PRegDeleteKey) (HKEY hKey, LPCWSTR lpSubKey) = RegDeleteKey;

LSTATUS WINAPI HookRegDeleteKey(HKEY hKey, LPCWSTR lpSubKey)
{
    LogMessage(L"Delete key" + GetKeyPath(hKey));
    return PRegDeleteKey(hKey, lpSubKey);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

        DisableThreadLibraryCalls(hModule);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        //
        DetourAttach(&(PVOID&)PCreateFile, HookCreateFile);
        DetourAttach(&(PVOID&)POpenFile, HookOpenFile);
        DetourAttach(&(PVOID&)PReadFile, HookReadFile);
        DetourAttach(&(PVOID&)PWriteFile, HookWriteFile);
        DetourAttach(&(PVOID&)PDeleteFile, HookDeleteFile);
        DetourAttach(&(PVOID&)PRegCreateKey, HookRegCreateKey);
        DetourAttach(&(PVOID&)PRegOpenKey, HookRegOpenKey);
        DetourAttach(&(PVOID&)PRegGetValue, HookRegGetValue);
        DetourAttach(&(PVOID&)PRegSetValue, HookRegSetValue);
        DetourAttach(&(PVOID&)PRegCloseKey, HookRegCloseKey);
        DetourAttach(&(PVOID&)PRegDeleteKey, HookRegDeleteKey);
        //
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        //
        DetourDetach(&(PVOID&)PCreateFile, HookCreateFile);
        DetourDetach(&(PVOID&)POpenFile, HookOpenFile);
        DetourDetach(&(PVOID&)PReadFile, HookReadFile);
        DetourDetach(&(PVOID&)PWriteFile, HookWriteFile);
        DetourDetach(&(PVOID&)PDeleteFile, HookDeleteFile);
        DetourDetach(&(PVOID&)PRegCreateKey, HookRegCreateKey);
        DetourDetach(&(PVOID&)PRegOpenKey, HookRegOpenKey);
        DetourDetach(&(PVOID&)PRegGetValue, HookRegGetValue);
        DetourDetach(&(PVOID&)PRegSetValue, HookRegSetValue);
        DetourDetach(&(PVOID&)PRegCloseKey, HookRegCloseKey);
        DetourDetach(&(PVOID&)PRegDeleteKey, HookRegDeleteKey);
        //
        DetourTransactionCommit();

        CloseHandle(hStdOut);
        break;
    }
    return TRUE;
}

template <typename T>
std::wstring ConvertToWstring(T value)
{
    std::wostringstream wss;
    wss << value;
    return wss.str();
}

std::wstring GetFileName(HANDLE hFile)
{
    Detach(&(PVOID&)PCreateFile, HookCreateFile);

    WCHAR buffer[MAX_PATH];
    GetFinalPathNameByHandle(hFile, buffer, MAX_PATH, FILE_NAME_NORMALIZED);

    Attach(&(PVOID&)PCreateFile, HookCreateFile);

    std::wstring filePath = buffer;
    size_t i = filePath.rfind('\\', filePath.length());
    if (i != std::wstring::npos) {
        return(filePath.substr(i + 1, filePath.length() - i));
    }
    return L"Console";
}

std::wstring GetKeyPath(HKEY key)
{
    std::wstring keyPath;
    if (key != NULL)
    {
        HMODULE dll = LoadLibrary(L"ntdll.dll");
        if (dll != NULL) {
            typedef DWORD(__stdcall* NtQueryKeyType) (HANDLE  KeyHandle, int KeyInformationClass, PVOID  KeyInformation, ULONG  Length, PULONG  ResultLength);

            NtQueryKeyType ntQueryKeyAddress = reinterpret_cast<NtQueryKeyType>(::GetProcAddress(dll, "NtQueryKey"));

            if (ntQueryKeyAddress != NULL) {
                DWORD size = 0;
                DWORD result = 0;
                result = ntQueryKeyAddress(key, 3, 0, 0, &size);
                if (result == STATUS_BUFFER_TOO_SMALL)
                {
                    size = size + 2;
                    wchar_t* buffer = new (std::nothrow) wchar_t[size / sizeof(wchar_t)]; // size is in bytes
                    if (buffer != NULL)
                    {
                        result = ntQueryKeyAddress(key, 3, buffer, size, &size);
                        if (result == STATUS_SUCCESS)
                        {
                            buffer[size / sizeof(wchar_t)] = L'\0';
                            keyPath = std::wstring(buffer + 2);
                        }

                        delete[] buffer;
                    }
                }
            }

            FreeLibrary(dll);
        }
    }
    return keyPath;
}

VOID Detach(PVOID* ppPointer, PVOID pDetour)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(ppPointer, pDetour);
    DetourTransactionCommit();
}

VOID Attach(PVOID* ppPointer, PVOID pDetour)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(ppPointer, pDetour);
    DetourTransactionCommit();
}

VOID LogMessage(std::wstring message)
{
    message += L'\n';
    WriteConsole(hStdOut, message.c_str(), message.size(), NULL, NULL);
}

