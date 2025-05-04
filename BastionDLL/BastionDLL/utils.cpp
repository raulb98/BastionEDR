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