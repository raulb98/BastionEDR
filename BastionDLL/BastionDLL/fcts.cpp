#include "pch.h"

Data data;

FARPROC my_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    data.fcts.append("GetProcAddress|");
    data.mp["GetProcAddress"] = lpProcName;
    data.file << "GetProcAddress: " << data.mp["GetProcAddress"] << "\n";

    return GetProcAddress(hModule, lpProcName);
}

HANDLE my_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    data.fcts.append("CreateFileA|");
    data.mp["CreateFileA"] = lpFileName;
    data.file << "CreateFileA :" << data.mp["CreateFileA"] << "\n";

    return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL my_ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
)
{
    data.fcts.append("ReadFile|");
    BOOL rez = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    data.mp["ReadFile"] = std::string((char*)lpBuffer);
    data.file << "ReadFile :" << data.mp["ReadFile"] << "\n";

    return rez;
}

BOOL my_WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
)
{
    data.fcts.append("WriteFile|");
    data.mp["WriteFile"] = std::string((char*)lpBuffer);
    data.file << "WriteFile :" << data.mp["WriteFile"] << "\n";

    return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

HANDLE my_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
)
{
    data.fcts.append("OpenProcess|");
    char buffer[10];
    sprintf_s(buffer, "%u", dwProcessId);
    data.mp["OpenProcess"] = std::string(buffer);
    data.file << "OpenProcess :" << data.mp["OpenProcess"] << "\n";

    return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}