// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stddef.h>

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
        change_fct(ptr_iat, dos_hdr, "KERNEL32.dll", "OpenProcess", (DWORD_PTR)my_OpenProcess);
        break;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        on_load();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

