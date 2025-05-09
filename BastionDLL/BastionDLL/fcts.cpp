#include "pch.h"

Data data;

FARPROC my_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    data.fcts.append("GetProcAddress|");
    data.mp["GetProcAddress"] = lpProcName;
    data.file << "GetProcAddress: " << data.mp["GetProcAddress"] << "\n";
    if (is_infected(&data))
    {
        HANDLE hProcess = GetCurrentProcess();
        TerminateProcess(hProcess, 0);
    }
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
    if (is_infected(&data))
    {
        HANDLE hProcess = GetCurrentProcess();
        TerminateProcess(hProcess, 0);
    }
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
    is_infected(&data);

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
    if (is_infected(&data))
    {
        HANDLE hProcess = GetCurrentProcess();
        TerminateProcess(hProcess, 0);
    }
    return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

HANDLE my_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
)
{
    data.fcts.append("OpenProcess|");
    char buffer[255];
    sprintf_s(buffer, "%u", dwProcessId);
    data.mp["OpenProcess"] = std::string(buffer);
    data.file << "OpenProcess :" << data.mp["OpenProcess"] << "\n";
    if (is_infected(&data))
    {
        HANDLE hProcess = GetCurrentProcess();
        TerminateProcess(hProcess, 0);
    }
    return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

BOOL my_CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    data.fcts.append("CreateProcessA|");
    char buffer[255];
    sprintf_s(buffer, "%s", lpApplicationName);
    data.mp["CreateProcessA"] = std::string(buffer);
    data.file << "CreateProcessA :" << data.mp["CreateProcessA"] << "\n";
    return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
        dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

VOID my_ExitProcess(
    UINT uExitCode
)
{
    data.fcts.append("ExitProcess|");
    char buffer[255];
    sprintf_s(buffer, "%u", uExitCode);
    data.mp["ExitProcess"] = std::string(buffer);
    data.file << "ExitProcess :" << data.mp["ExitProcess"] << "\n";
    return ExitProcess(uExitCode);
}


BOOL my_TerminateProcess(
    HANDLE hProcess,
    UINT uExitCode
)
{
    data.fcts.append("TerminateProcess|");
    char buffer[255];
    sprintf_s(buffer, "TerminateProcess Handle : %p", hProcess);
    data.mp["TerminateProcess"] = std::string(buffer);
    data.file << "TerminateProcess :" << data.mp["TerminateProcess"] << "\n";
    return TerminateProcess(hProcess, uExitCode);
}


DWORD my_SetFilePointer(
    HANDLE hFile,
    LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod
)
{
    data.fcts.append("SetFilePointer|");
    char buffer[255];
    sprintf_s(buffer, "SetFilePointer Handle : %p", hFile);
    data.mp["SetFilePointer"] = std::string(buffer);
    data.file << "SetFilePointer :" << data.mp["SetFilePointer"] << "\n";

    return SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

LPVOID my_VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
)
{
    data.fcts.append("VirtualAlloc|");
    char buffer[255];
    sprintf_s(buffer, "VirtualAlloc Handle : %p sz :%lu", lpAddress, dwSize);
    data.mp["VirtualAlloc"] = std::string(buffer);
    data.file << "VirtualAlloc :" << data.mp["VirtualAlloc"] << "\n";


    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL my_VirtualFree(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
)
{    
    data.fcts.append("VirtualFree|");
    char buffer[255];
    sprintf_s(buffer, "VirtualFree Handle : %p sz :%lu", lpAddress, dwSize);
    data.mp["VirtualFree"] = std::string(buffer);
    data.file << "VirtualFree :" << data.mp["VirtualFree"] << "\n";

    return VirtualFree(lpAddress, dwSize, dwFreeType);
}

BOOL my_VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
)
{
    data.fcts.append("VirtualProtect|");
    char buffer[255];
    sprintf_s(buffer, "VirtualProtect Handle : %p sz :%lu PROTECT : [%08X]", lpAddress, dwSize, flNewProtect);
    data.mp["VirtualProtect"] = std::string(buffer);
    data.file << "VirtualProtect :" << data.mp["VirtualProtect"] << "\n";

    return my_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

VOID my_Sleep(
    DWORD dwMilliseconds
)
{
    data.fcts.append("Sleep|");
    char buffer[255];
    sprintf_s(buffer, "Sleep Miliseconds : %u", dwMilliseconds);
    data.mp["Sleep"] = std::string(buffer);
    data.file << "Sleep :" << data.mp["Sleep"] << "\n";

    Sleep(dwMilliseconds);
}

HMODULE my_LoadLibraryA(
    LPCSTR lpLibFileName
)
{
    data.fcts.append("LoadLibraryA|");
    char buffer[255];
    sprintf_s(buffer, "LoadLibraryA Lib: %s", lpLibFileName);
    data.mp["LoadLibraryA "] = std::string(buffer);
    data.file << "LoadLibraryA  :" << data.mp["LoadLibraryA "] << "\n";

    return LoadLibraryA(lpLibFileName);
}