// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"

void on_load();
void change_fct(PIMAGE_IMPORT_DESCRIPTOR iat, PIMAGE_DOS_HEADER dos_hdr, const char* lib, const char* fct, DWORD_PTR new_fct);
DWORD communicate_pipe();

BOOL is_infected(Data* data);
BOOL is_injection(Data* data);

FARPROC my_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HANDLE my_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
BOOL my_ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);
BOOL my_WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);
HANDLE my_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

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
);

VOID my_ExitProcess(
    UINT uExitCode
);

BOOL my_TerminateProcess(
    HANDLE hProcess,
    UINT uExitCode
);

DWORD my_SetFilePointer(
    HANDLE hFile,
    LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod
);

LPVOID my_VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);

BOOL my_VirtualFree(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
);

BOOL my_VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);

VOID my_Sleep(
    DWORD dwMilliseconds
);

HMODULE my_LoadLibraryA(
    LPCSTR lpLibFileName
);

#endif //PCH_H
