#include "hdr.h"

DWORD previousPIDs[MAX_PROCESSES] = { 0 };
int previousCount = 0;

BOOL inject_dll(DWORD dwPID, const char* dllPath) {
    
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ, FALSE, dwPID);
    if (hProcess == NULL) {
        printf("Error: Could not open process with PID %lu. Error code: %lu\n", dwPID, GetLastError());
        return FALSE;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress == NULL) {
        printf("Error: Could not allocate memory in target process. Error code: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, lpBaseAddress, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("Error: Could not write memory to target process. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Get the address of LoadLibraryA
    LPVOID lpLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (lpLoadLibrary == NULL) {
        printf("Error: Could not find LoadLibraryA address. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create a remote thread in the target process to execute LoadLibraryA with the DLL path
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibrary, lpBaseAddress, 0, NULL);
    if (hThread == NULL) {
        printf("Error: Could not create remote thread. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

void inject(DWORD pid)
{
    char dllPath[MAX_PATH];
    memcpy(dllPath, "BastionDLL.dll",
        sizeof("BastionDLL.dll") - 1);

    // Perform the DLL injection
    if (inject_dll(pid, dllPath)) {
        printf("DLL injected successfully.\n");
    }
    else {
        printf("Failed to inject DLL.\n");
    }
}

int processExists(DWORD pid) {
    for (int i = 0; i < previousCount; i++) {
        if (previousPIDs[i] == pid) 
            return 1;
    }
    return 0;
}

void saveProcessList(DWORD* pids, int count) {
    memcpy(previousPIDs, pids, count * sizeof(DWORD));
    previousCount = count;
}

BOOL is_process_a_service(DWORD pid)
{
    SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc_manager)
    {
        printf("Failed to open OpenSCManager : [%u]\n", GetLastError());
        return FALSE;
    }

    DWORD bytesNeeded, servicesReturned, resumeHandle = 0;
    DWORD bufferSize = 0;
    LPBYTE buffer = NULL;
    BOOL isService = FALSE;

    EnumServicesStatusEx(sc_manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned,
        &resumeHandle, NULL);

    if (GetLastError() != ERROR_MORE_DATA) {
        printf("EnumServicesStatusEx failed: %lu\n", GetLastError());
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    bufferSize = bytesNeeded;
    buffer = (LPBYTE)malloc(bufferSize);
    if (!buffer) {
        printf("Memory allocation failed\n");
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    if (EnumServicesStatusEx(sc_manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_ACTIVE, buffer, bufferSize, &bytesNeeded,
        &servicesReturned, &resumeHandle, NULL)) {

        LPENUM_SERVICE_STATUS_PROCESS services = (LPENUM_SERVICE_STATUS_PROCESS)buffer;
        for (DWORD i = 0; i < servicesReturned; ++i) {
            if (services[i].ServiceStatusProcess.dwProcessId == pid) {
                isService = TRUE;
                printf("[is_process_a_service] Process ID %lu is running as a service: %ws\n",
                    pid, services[i].lpServiceName);
                break;
            }
        }
    }
    else {
        printf("EnumServicesStatusEx failed on second call: %lu\n", GetLastError());
    }

    free(buffer);
    CloseServiceHandle(sc_manager);
    return isService;
}

void monitor(DWORD pid, const char* name)
{
    DWORD currentPIDs[MAX_PROCESSES];
    char proc_name[100] = { 0 };
    int currentCount = 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Snapshot error: %lu\n", GetLastError());
        return;

    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            currentPIDs[currentCount++] = pe32.th32ProcessID;
            if (!processExists(pe32.th32ProcessID)) {
                _tprintf(TEXT("New process: %s (PID %u) [%d]\n"), pe32.szExeFile, pe32.th32ProcessID, 
                    is_process_a_service(pe32.th32ProcessID));
                if ((pid != 0 ) && (pid == pe32.th32ProcessID))
                {
                    if(!is_process_a_service(pe32.th32ProcessID))
                        inject(pe32.th32ProcessID);
                }
                else
                {
                    WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, proc_name, 100, NULL, NULL);
                    if (strcmp(proc_name, name) == 0)
                    {
                        if (!is_process_a_service(pe32.th32ProcessID))
                            inject(pe32.th32ProcessID);
                    }

                }
            }
        } while (Process32Next(hSnapshot, &pe32));
        saveProcessList(currentPIDs, currentCount);
    }
}

int main(int argc, const char* argv[])
{
    printf("Start Bastion EDR!\n");

    DWORD pid = 0;
    char proc_name[100] = { 0 };

    if (argc == 3)
    {
        if(strcmp(argv[1], "-pid") == 0)
            pid = atoi(argv[2]);
        if (strcmp(argv[1], "-name") == 0)
            memcpy(proc_name, argv[2], strlen(argv[2]));
    
        while (1) {
            monitor(pid, proc_name);
            Sleep(1000);
        }
    }
    else
    {
        printf("Incorrect usage:\n");
        printf("Use: -pid <pid>");
        printf("Use: -name <name>");
    }

    system("pause");
    return 0;
}
