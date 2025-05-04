#pragma once

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <winsvc.h>
#include <stdio.h>


BOOL inject_dll(DWORD dwPID, const char* dllPath);
void inject(DWORD pid);
void monitor();
void saveProcessList(DWORD* pids, int count);
int processExists(DWORD pid);
BOOL is_process_a_service(DWORD pid);

#define MAX_PROCESSES 4096

extern DWORD previousPIDs[MAX_PROCESSES];
extern int previousCount;
