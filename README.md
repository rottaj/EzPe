# EzPe
## Easy PE Parsing Functions

This repository serves as a reference for copy and paste functions for parsing Portable Executables using the Win32 API.
<br>
All functions are in a single file to make your time here as quick as possible.

#### What is the purpose of this?
There are many PE parsers on GitHub, but if you're like me and just want to read the CliffNotes, then this may be for you. These functions are also useful when creating Position Independant Code (PIC).

#### NOTE:
The purpose of this is to provide a small, portable template for your PE functions. There is no extensive printing to standard output.
These functions give you a base to start with, and you build the rest. That being said, each function includes an example for reference.

The functions rely on a singleton struct for the Portable Executable as follows:
```C
typedef struct __PE_HDRS {
    PVOID lpFileBuffer; // Pointer to buffer of entire file - Serves as base
    DWORD ulFileSize; // Size of File buffer

    PIMAGE_DOS_HEADER pDosHeader; // Pointer to the DOS header
    PIMAGE_NT_HEADERS pNtHeader; // Pointer to the NT Header
    PIMAGE_OPTIONAL_HEADER pOptionalHeader; // Pointer to the NT Header

    PIMAGE_DATA_DIRECTORY pImportDataDir; // Pointer to the Import Directory

} PE_HDRS, *PP_HDRS;
```
Initialize the singleton:
```C
PE_HDRS myPe = { 0 };
PP_HDRS pPe = &myPe;
```


### Installation
```bash
git clone https://wwww.github.com/rottaj/EzPe
cd EzPe
make
```



## Individual Parsing Functions
### ParseImports()
ParseImports relies on two helper functions. <br>
* GetEnclosingSectionHeader: Returns PIMAGE_SECTION_HEADER given an RVA.
* GetPtrFromRVA: Returns a pointer given an RVA.
```C
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
        // Example (prints each imported DLL the PE uses)
        wprintf(L"[+] %s\n", GetPtrFromRVA(import->Name));
        import++;
    }
    return TRUE;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pPe->pNtHeader);
    unsigned i;

    for ( i=0; i < pPe->pNtHeader->FileHeader.NumberOfSections; i++, section++ ){
    // Is the RVA within this section?
        if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + section->Misc.VirtualSize))) {
            return section;
        }

    return 0;
}

LPVOID GetPtrFromRVA( DWORD rva) {
    PIMAGE_SECTION_HEADER pSectionHdr;
    INT delta;

    pSectionHdr = GetEnclosingSectionHeader( rva );
    if ( !pSectionHdr )
        return 0;

    delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);

    return (PVOID)(pPe->lpFileBuffer+ rva - delta);
}
```

### ParseRelocations()
ParseRelocations relies on 1 helper function
* MakePtr - Returns a pointer given a pointer and an add value.
```C


LPVOID MakePtr(PVOID ptr, DWORD_PTR addValue) {
    return (LPVOID)((DWORD_PTR)ptr + addValue);
}
// The names of the available base relocations
char *SzRelocTypes[] = {
    "ABSOLUTE","HIGH","LOW","HIGHLOW","HIGHADJ","MIPS_JMPADDR",
    "SECTION","REL32" 
};

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


```

### References
http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm <br>
https://0xrick.github.io/win-internals/pe2/ <br>
http://www.wheaty.net/ <br>
https://www.rotta.rocks/offensive-tool-development/windows-internals/pe-file-format