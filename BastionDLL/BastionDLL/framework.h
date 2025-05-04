#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <intrin.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <map>
#include <fstream>

class Data {
public:
    std::string fcts;
    std::map<std::string, std::string> mp;
    std::fstream file;

    Data()
    {
        file.open("C:\\Users\\bucur\\source\\repos\\SanctumEDR\\SanctumEDR\\SactumDllEDR_log.txt", std::ios::in | std::ios::out | std::ios::app);
        if (!file.is_open())
        {
            printf("Could not open log file!\n");
            exit(1);
        }
        file << "Injected in new Process!\n";
    }
};

extern Data data;

void on_load();
void change_fct(PIMAGE_IMPORT_DESCRIPTOR iat, PIMAGE_DOS_HEADER dos_hdr, const char* lib, const char* fct, DWORD_PTR new_fct);

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