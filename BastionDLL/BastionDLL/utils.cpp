#include "pch.h"


void change_fct(PIMAGE_IMPORT_DESCRIPTOR iat, PIMAGE_DOS_HEADER dos_hdr, const char* lib, const char* fct, DWORD_PTR new_fct)
{
    while (iat->Name)
    {
        char* dllName = (char*)((size_t)dos_hdr + iat->Name);
        if (memcmp(dllName, lib, strlen(lib)) == 0)
        {
            PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)((size_t)dos_hdr + iat->OriginalFirstThunk);
            PIMAGE_THUNK_DATA64 p_IAT = (PIMAGE_THUNK_DATA64)((size_t)dos_hdr + iat->FirstThunk);

            while (pThunk->u1.AddressOfData)
            {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {

                }
                else {
                    // It's a named import, so retrieve the function name
                    IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)((size_t)dos_hdr + (size_t)pThunk->u1.AddressOfData);
                    if (pImportByName && pImportByName->Name)
                    {
                        if (memcmp(pImportByName->Name, fct, strlen(fct)) == 0)
                        {
                            DWORD old_prc = 0;
                            VirtualProtect(&p_IAT->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &old_prc);
                            p_IAT->u1.Function = new_fct;
                        }
                    }
                }
                pThunk++;
                p_IAT++;
            }
        }
        iat++;
    }

}

void on_load()
{

    PEB* pb = (PEB*)__readgsqword(0x60);
    pb->ProcessParameters->ImagePathName.Buffer;
    char path_name[2048] = { 0 };
    DWORD sz_path_name = 2048;
    char* ptr_name = NULL;
    WideCharToMultiByte(CP_ACP, 0, pb->ProcessParameters->ImagePathName.Buffer, sz_path_name, path_name, sz_path_name, NULL, NULL);

    for (size_t idx = strlen(path_name); idx > 0; idx--)
    {
        if ((path_name[idx] == '\\') or (path_name[idx] == '/'))
        {
            ptr_name = &path_name[idx];
            ptr_name++;
            break;
        }
    }

    if (ptr_name == NULL)
        return;

    LIST_ENTRY* ldr_table_entry = &pb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* p = ldr_table_entry->Flink;
    while (ldr_table_entry != p)
    {

        LDR_DATA_TABLE_ENTRY* item = (LDR_DATA_TABLE_ENTRY*)((BYTE*)p - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        DWORD sz = item->FullDllName.Length / sizeof(WCHAR);
        char* lib_path = (char*)malloc(sz);
        if (!lib_path)
        {
            p = p->Flink;
            continue;
        }
        WideCharToMultiByte(CP_ACP, 0, item->FullDllName.Buffer, sz, lib_path, sz, NULL, NULL);
        char* lib_name = NULL;
        for (unsigned int idx = sz - 1; idx > 0; idx--)
        {
            if ((lib_path[idx] == '\\') or (lib_path[idx] == '/'))
            {
                lib_name = &lib_path[idx];
                lib_name++;
                break;
            }
        }

        if (lib_name == NULL)
        {
            free(lib_path);
            p = p->Flink;
            continue;
        }

        if (_memicmp(lib_name, ptr_name, strlen(ptr_name)))
        {
            free(lib_path);
            p = p->Flink;
            continue;
        }

        PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)item->DllBase;
        PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)((size_t)item->DllBase + dos_hdr->e_lfanew);
        size_t rva_import = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        size_t sz_import = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;


        PIMAGE_IMPORT_DESCRIPTOR ptr_iat = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)dos_hdr + rva_import);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "GetProcAddress", (DWORD_PTR)my_GetProcAddress);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "CreateFileA", (DWORD_PTR)my_CreateFileA);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "ReadFile", (DWORD_PTR)my_ReadFile);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "WriteFile", (DWORD_PTR)my_WriteFile);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "CreateProcessA", (DWORD_PTR)my_CreateProcessA);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "ExitProcess", (DWORD_PTR)my_ExitProcess);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "TerminateProcess", (DWORD_PTR)my_TerminateProcess);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "VirtualAlloc", (DWORD_PTR)my_VirtualAlloc);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "VirtualFree", (DWORD_PTR)my_VirtualFree);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "VirtualProtect", (DWORD_PTR)my_VirtualProtect);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "Sleep", (DWORD_PTR)my_Sleep);
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "LoadLibraryA", (DWORD_PTR)my_LoadLibraryA);
        break;
    }
}

BOOL is_infected(Data* data)
{
    if (is_injection(data))
    {
        data->flags[TERMINATE] = 1;
        return true;
    }

    return false;
}

DWORD communicate_pipe()
{
    HANDLE pipe;
    std::string pipeName = "\\\\.\\pipe\\pid_" + GetCurrentProcessId();
    while (1) {
        
        pipe = CreateFileA(
            pipeName.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        DWORD written;
        WriteFile(pipe, data.flags, (DWORD)strlen(data.flags) + 1, &written, NULL);

        Sleep(100);
    }

    CloseHandle(pipe);
    return 0;
}