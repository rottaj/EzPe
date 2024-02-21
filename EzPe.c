//
// Created by j4ck on 2/15/24.
//
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

typedef struct __PE_HDRS {
    PVOID lpFileBuffer; // Pointer to Buffer of entire File
    DWORD ulFileSize; // Size of File buffer

    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader;

    PIMAGE_DATA_DIRECTORY pImportDataDir;

} PE_HDRS, *PP_HDRS;

PE_HDRS myPe = { 0 };
PP_HDRS pPe = &myPe;


BOOL ReadFileIntoBuffer() {
    HANDLE hFile = NULL;
    hFile = CreateFileW(L"mimikatz.exe",
                        GENERIC_READ,
                        0,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] CreateFileW Failed to Open File GetLastError %d\n", GetLastError);
        return FALSE;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == 0) {
        wprintf(L"[!] GetFileSize Failed GetLastError %d\n", GetLastError());
        return FALSE;
    }


    LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwFileSize);
    if (lpBuffer == NULL) {
        wprintf(L"[!] HeapAlloc Failed GetLastError %d\n", GetLastError());
        return FALSE;
    }

    DWORD dwBytesRead = 0;

    if (!ReadFile(hFile, lpBuffer, dwFileSize, &dwBytesRead, NULL)) {
        wprintf(L"[!] ReadFile Failed %d\n", GetLastError);
        return FALSE;
    }

    // Cleanup
    pPe->lpFileBuffer = lpBuffer;
    pPe->ulFileSize = dwFileSize;
    CloseHandle(hFile);

    return TRUE;
}


PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pPe->pNtHeader);
    unsigned i;

    for ( i=0; i < pPe->pNtHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        // Is the RVA within this section?
        if ( (rva >= section->VirtualAddress) &&
             (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
            return section;
    }

    return 0;
}

LPVOID GetPtrFromRVA( DWORD rva)
{
    PIMAGE_SECTION_HEADER pSectionHdr;
    INT delta;

    pSectionHdr = GetEnclosingSectionHeader( rva );
    if ( !pSectionHdr )
        return 0;

    delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);

    return (PVOID)(pPe->lpFileBuffer+ rva - delta);
}

BOOL ParseOptionalHeader() {
    wprintf(L"OS Version Major %d\n", pPe->pOptionalHeader->MajorOperatingSystemVersion);
    wprintf(L"Subsystem %d\n", pPe->pOptionalHeader->Subsystem);
    wprintf(L"Size of Image %d\n", pPe->pOptionalHeader->SizeOfImage);
    wprintf(L"Checksum %d\n", pPe->pOptionalHeader->CheckSum);
    wprintf(L"Number of RVA's and Sizes %d\n", pPe->pOptionalHeader->NumberOfRvaAndSizes);
}


BOOL ParseImports() {
    // Get RVA of ImportStartDesc
    DWORD importStartDesc = (pPe->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!importStartDesc) {
        return FALSE;
    }

    LPVOID test = GetPtrFromRVA(importStartDesc);

    PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)test;

    while (1) {
        if (import->TimeDateStamp == 0 && import->Name == 0) {
            break;
        }

        /* # Uncomment this if building parser for IAT/ILT.
        PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)import->FirstThunk;
        while (1) {
            thunkIAT++
        }
        */

        wprintf(L"[+] %s\n", GetPtrFromRVA(import->Name));
        import++;
    }
    return TRUE;
}

BOOL ParseExports() {
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPe->lpFileBuffer + pPe->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
}

LPVOID MakePtr(PVOID ptr, DWORD_PTR addValue) {
    return (LPVOID)((DWORD_PTR)ptr + addValue);
}


// The names of the available base relocations
char *SzRelocTypes[] = {
        "ABSOLUTE","HIGH","LOW","HIGHLOW","HIGHADJ","MIPS_JMPADDR",
        "SECTION","REL32" };



BOOL ParseRelocations() {
    PIMAGE_BASE_RELOCATION baseReloc;
    DWORD dwBaseRelocRVA = (pPe->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    if ( !dwBaseRelocRVA )
        return FALSE;

    baseReloc = (PIMAGE_BASE_RELOCATION) GetPtrFromRVA( dwBaseRelocRVA );
    if ( !baseReloc )
        return FALSE;
    while ( baseReloc->SizeOfBlock != 0 )
    {
        unsigned i,cEntries;
        PWORD pEntry;
        char *szRelocType;
        WORD relocType;

        // Sanity check to make sure the data looks OK.
        if ( 0 == baseReloc->VirtualAddress )
            break;
        if ( baseReloc->SizeOfBlock < sizeof(*baseReloc) )
            break;

        cEntries = (baseReloc->SizeOfBlock-sizeof(*baseReloc))/sizeof(WORD);
        pEntry = MakePtr( baseReloc, sizeof(*baseReloc) );

        printf("Virtual Address: %08X  size: %08X\n",
               baseReloc->VirtualAddress, baseReloc->SizeOfBlock);

        for ( i=0; i < cEntries; i++ )
        {
            // Extract the top 4 bits of the relocation entry.  Turn those 4
            // bits into an appropriate descriptive string (szRelocType)
            relocType = (*pEntry & 0xF000) >> 12;
            szRelocType = relocType < 8 ? SzRelocTypes[relocType] : "unknown";

            printf("  %08X %s",
                   (*pEntry & 0x0FFF) + baseReloc->VirtualAddress,
                   szRelocType);

            if ( IMAGE_REL_BASED_HIGHADJ == relocType )
            {
                pEntry++;
                cEntries--;
                printf( " (%X)", *pEntry );
            }

            printf( "\n" );
            pEntry++;   // Advance to next relocation entry
        }

        baseReloc = MakePtr( baseReloc,
                             baseReloc->SizeOfBlock);
    }
    wprintf(L"Base Reloc %p", baseReloc);
}

/* All the code below just initializes the parsing functions. */
BOOL ParsePEHeaders() {
    pPe->pDosHeader = (PIMAGE_DOS_HEADER)pPe->lpFileBuffer; // DOS header starts immediately at PE file

    pPe->pNtHeader = (PIMAGE_NT_HEADERS)(pPe->lpFileBuffer + pPe->pDosHeader->e_lfanew); // Base Image + e_lfanew offset

    if (pPe->pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        wprintf(L"[!] Not a Portable Executable \n");
        return FALSE;
    }

    pPe->pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pPe->pNtHeader->OptionalHeader;
    if (pPe->pOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        wprintf(L"[!] Incorrect Optional Header Magic Byte");
        return FALSE;
    }


    /*
     * 1.) Parse Imports with ParseImports()
    */

    wprintf(L"\n\n[1] Parsing Import Section (.idata)\n\n");
    if (!ParseImports()) {
        wprintf(L"[!] ParseImports() Failed!\n");
        return FALSE;
    }

    /*
     * 2.)Parse Exports with ParseExports()
    */

    wprintf(L"\n\n[2] Parsing Export Section\n\n");
    ParseExports();


    wprintf(L"\n\n[3] Parsing Relocation Section (.reloc)\n\n");
    ParseRelocations();

    return TRUE;
}


int wmain() {
    ReadFileIntoBuffer();
    ParsePEHeaders();
    return 0;
}
