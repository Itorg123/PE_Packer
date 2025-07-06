
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <winnt.h>

/*
  _____ _______   __     __        _    _          _____ _  ________
 |_   _|__   __|/\\ \   / /       | |  | |   /\   |_   _| |/ /  ____|
   | |    | |  /  \\ \_/ /        | |__| |  /  \    | | | ' /| |__
   | |    | | / /\ \\   /         |  __  | / /\ \   | | |  < |  __|
  _| |_   | |/ ____ \| |          | |  | |/ ____ \ _| |_| . \| |____
 |_____|  |_/_/    \_\_|          |_|  |_/_/    \_\_____|_|\_\______|
*/

char i_key = 'J';
char y_key = 'x';

char help_to_decrypt_2(int i)
{
    switch (i)
    {
    case 0:
        return i_key;   // I
    case 1:
        return 's';     // t
    case 2:
        return 'b';     // a
    case 3:
        return y_key;   // y
    case 4:
        return '`';     // _
    case 5:
        return 'g';     // h
    }
}

void help_to_decrypt(int i, char key_arr[])
{
    // for any i - find the correct char

    if (i % 2 == 0)
    {
        key_arr[i] = help_to_decrypt_2(i) - 1;
    }
    else
    {
        key_arr[i] = help_to_decrypt_2(i) + 1;
    }
}



void decrypt(unsigned char* encrypted_data, int size)
{
    char key[7] = ""; // "Itay_h"

    for (int i = 0; i < 6; i++)
    {
        help_to_decrypt(i, key);
    }

    // decrypt

    for (int i = 0; i < size; i++)
    {
        for (int j = 0; j < 6; j++)
        {
            encrypted_data[i] ^= (unsigned char)key[j];
        }
    }

}

/*
void trampoline()
{

    // need to change the orig function proluge = 3 bytes     to      (pop eax; nop; nop) = 3 bytes
    DWORD loaded_exe_delta;
    DWORD loaded_function_address;
    DWORD loader_function_address;
    DWORD loaded_function_address_rva_from_here = (loaded_function_address + loaded_exe_delta) - loader_function_address;
    __asm
    {


        // move the relative_address to eax
        mov eax, [new_address_rva]

        // jump to the relative_address on eax
        jmp eax
    }
}
*/

void anti_debug()
{
    while (1)
    {
        // is_debuger_present - this is check the PEB - procces enviorment block
        if (IsDebuggerPresent())
        {
            printf("debuger is present!!!!!!!!!");
            ExitProcess(-1);
        }

        // check the procces enviorment block
        BOOL is_debugged;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_debugged) && is_debugged)
        {
            printf("debuger is present!!!!!!!!!");
            ExitProcess(-1);
        }

        // when procces run on debuger - the debuger catch the exception - if it wasnt catch - probably dont have debuger
        is_debugged = true;
        __try
        {
            RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, 0);
            // is_debugged stay true beacuse the exception catched and the try continue because he doesnt see exception 
        }
        __except (GetExceptionCode() == DBG_PRINTEXCEPTION_C)
        {
            // exception wasnt catched -> the __except catched it - so there is no debuger
            is_debugged = false;
        }

        // exit
        if (is_debugged)
        {
            printf("debuger is present!!!!!!!!!");
            ExitProcess(-1);
        }

        // it possible to check times, or check for CC (BreakPoint)in the memory but for now it enough
    }
}


int main()
{
    // Read the exe -> read the .encrypt section -> decrypt -> run 

    // open file

    // open thread of find debuger - run all time

    DWORD thread_id;
    // HANDLE anti_debug_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)anti_debug, NULL, 0, &thread_id);

    FILE* exe;

    fopen_s(&exe, "C:\\Users\\Itay H\\Desktop\\cyber\\packer_project_learn\\PACKER_TRAMP.exe", "rb");
    if (!exe)
    {
        printf("Open file failed");
        return 0;
    }

    // find file size

    fseek(exe, 0, SEEK_END);
    int this_size = ftell(exe);
    fseek(exe, 0, SEEK_SET);

    // read to buffer

    unsigned char* buffer = (unsigned char*)malloc(this_size);
    fread(buffer, 1, this_size, exe); // 1 byte * size    

    // dos_header
    PIMAGE_DOS_HEADER dos_header_first = (PIMAGE_DOS_HEADER)buffer;

    printf("ifanew: %d", dos_header_first->e_lfanew);


    // nt_header
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(buffer + dos_header_first->e_lfanew);

    // file_header
    IMAGE_FILE_HEADER file_header = (IMAGE_FILE_HEADER)(nt_header->FileHeader);

    // number of sections
    int section_number_loader = file_header.NumberOfSections;

    // secion header
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
    

    // declare here - i can use it later
    int table_size, asm_size;

    //init the buffers
    unsigned char* enc = NULL;
    unsigned char* trampoline_asm = NULL;
    DWORD * addresses_table = NULL;

    printf("section number: %d ", section_number_loader);
    for (int i = 0; i < section_number_loader; i++)
    {
        if (!memcmp(section_header->Name, ".encrypt", strlen(".encrypt")))
        {
            // size, offset of header
            int encrypt_offset = section_header->PointerToRawData;
            int encrypt_size = section_header->SizeOfRawData;

            // start from the section offset
            fseek(exe, encrypt_offset, SEEK_SET);

            // read to buffer
            enc = (unsigned char*)malloc(encrypt_size);
            fread(enc, 1, encrypt_size, exe);

            // decrypt
            decrypt(enc, encrypt_size);

            // next section
            section_header++;
        }

        printf("%s", section_header->Name);
        if (!memcmp(section_header->Name, ".trampol", strlen(".trampol")))
        {
            // size, offset of header
            int asm_offset = section_header->PointerToRawData;
            asm_size = section_header->SizeOfRawData;

            // start from the section offset
            fseek(exe, asm_offset, SEEK_SET);

            printf("found .trampol");

            // read to buffer
            trampoline_asm = (unsigned char*)malloc(asm_size);
            fread(trampoline_asm, 1, asm_size, exe);

            // next section
            section_header++;
        }

        printf("%s", section_header->Name);
        if (!memcmp(section_header->Name, ".address", strlen(".address")))
        {
            // size, offset of header
            int table_offset = section_header->PointerToRawData;
            table_size = section_header->SizeOfRawData;

            // start from the section offset
            fseek(exe, table_offset, SEEK_SET);

            printf("found .address");

            // read to buffer
            addresses_table = (DWORD *)malloc(table_size);
            fread(addresses_table, 1, table_size, exe);
        }

        // next section
        section_header++;
    }


    /*
    .....................................................................................................................
                                                     _                    _
                                                    | |    ___   __ _  __| | ___ _ __
                                                    | |   / _ \ / _` |/ _` |/ _ \ '__|
                                                    | |__| (_) | (_| | (_| |  __/ |
                                                    |_____\___/ \__,_|\__,_|\___|_|
    .....................................................................................................................
    */

    // dos_header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)enc;

    // nt_header
    nt_header = (PIMAGE_NT_HEADERS)(enc + dos_header->e_lfanew);

    // file_header
    file_header = (IMAGE_FILE_HEADER)(nt_header->FileHeader);

    // optional header

    IMAGE_OPTIONAL_HEADER optional_header = (IMAGE_OPTIONAL_HEADER)(nt_header->OptionalHeader);
    //printf("image_base: %x", optional_header.ImageBase);

    // image size
    DWORD size_of_image = optional_header.SizeOfImage;

    // allocate size
    DWORD allocate_size = size_of_image + asm_size + table_size;

    // allocate image

    LPVOID virtual_memory = VirtualAlloc(NULL, // windows choose the address
        allocate_size, // size to allocate
        MEM_COMMIT | MEM_RESERVE, // allocate physical memory
        PAGE_EXECUTE_READWRITE); // read, write, execute

    // image base
    DWORD image_base = optional_header.ImageBase;

    // delta between actual address and "wanted"
    DWORD delta = ((DWORD)virtual_memory) - image_base;

    printf("image base: %llx, actual address: %llx, delta: %llx ", image_base, virtual_memory, delta);

    // copy headers to memory
    memcpy(virtual_memory, enc, optional_header.SizeOfHeaders);



    // number of sections
    int section_number = file_header.NumberOfSections;

    // secion header
    section_header = IMAGE_FIRST_SECTION(nt_header);

    // copy sections to memory (image)

    for (int i = 0; i < section_number; i++)
    {
        // size, offset of header
        BYTE* source_address = (BYTE*)enc + section_header->PointerToRawData;
        BYTE* destination_address = (BYTE*)virtual_memory + section_header->VirtualAddress;
        size_t size_of_section = (size_t)section_header->SizeOfRawData;
        memcpy(destination_address, source_address, size_of_section);

        // next section
        section_header++;
    }

    // copy assembly opcode bytes to memory
    int size_of_code = *(int*)trampoline_asm;
    BYTE* destination_address = (BYTE*)virtual_memory + size_of_image;
    BYTE* source_address = (BYTE*)(trampoline_asm + 4); // 4 bytes of meta data (size of code)
    printf("        size of code: %d      ", size_of_code);

    memcpy(destination_address, source_address, size_of_code);


    // copy jumps table


    // add delta to table addresses
    for (int i = 0; i < (table_size / sizeof(DWORD)-1); i++)
    {
        printf("         in index i: %x      ", addresses_table[i]);
        addresses_table[i] += (DWORD)virtual_memory;
    }

    // the copy:
    destination_address = (BYTE*)((BYTE*)virtual_memory + size_of_image + size_of_code); // immediatly after the code
    source_address = (BYTE*)(addresses_table);
    memcpy(destination_address, source_address, table_size);


    // relocation

    if (image_base != (DWORD)virtual_memory)
    {
        // realoc directory
        IMAGE_DATA_DIRECTORY realoc_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        DWORD realoc_dir_size = realoc_dir.Size;
        DWORD realoc_dir_rva = realoc_dir.VirtualAddress;
        printf("realoc_dir_rva: %x", realoc_dir_rva);

        // realoc .......
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)virtual_memory + realoc_dir_rva);

        int passed = 0;

        printf("realoc_dir_size: %x", realoc_dir_size);
        while ((passed < realoc_dir_size) && (reloc->SizeOfBlock > 0))
        {
            DWORD enteries_num = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* realoc_data = (WORD*)(reloc + 1);

            for (int i = 0; i < enteries_num; i++)
            {
                WORD realoc_entery = realoc_data[i];

                // type of relocation
                WORD type = realoc_entery >> 12; // mask of last byte

                // offset to change
                WORD offset = realoc_entery & 0x0fff; // mask of 3 first bytes

                if (type == IMAGE_REL_BASED_HIGHLOW)  // 32 bit
                {
                    //  change the address that need relocation
                    DWORD* address_to_change = (DWORD*)((BYTE*)virtual_memory + reloc->VirtualAddress + offset);
                    *address_to_change += delta;
                }

            }
            printf("     (enteries_num):%x    ", enteries_num);

            // forward

            passed += reloc->SizeOfBlock;
            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);

        }
    }


    // Init the IAT - Import Address Table


    IMAGE_DATA_DIRECTORY iat = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (iat.Size != 0)
    {
        // initialize variables
        PIMAGE_IMPORT_DESCRIPTOR import_desc;
        import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)virtual_memory + iat.VirtualAddress);
        DWORD ilt_rva = import_desc->OriginalFirstThunk;
        DWORD ilt_address = ilt_rva;
        DWORD iat_rva = import_desc->FirstThunk;
        DWORD iat_address = iat_rva;

        printf("iat_rva: %d", iat_rva);

        while (import_desc->Name != 0)
        {

            char* name = (char*)((BYTE*)virtual_memory + import_desc->Name);
            HMODULE dll_handle = LoadLibraryA(name);
            if (!dll_handle)
            {
                printf("import failed");
            }

            PIMAGE_THUNK_DATA orig_thunk = (PIMAGE_THUNK_DATA)((BYTE*)virtual_memory + import_desc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((BYTE*)virtual_memory + import_desc->FirstThunk);

            while (orig_thunk->u1.AddressOfData)
            {

                // find dunction by name or ordinal (like id of the function in the dll)
                FARPROC func_address;

                if (!(orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) // by name
                {
                    PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)virtual_memory + orig_thunk->u1.AddressOfData);
                    char* func_name = (char*)import_by_name->Name;

                    // get function address
                    func_address = GetProcAddress(dll_handle, func_name);

                    // not working
                    if (func_address == NULL)
                    {
                        printf("GetModuleAddress failed");
                    }
                }
                else // not by name - by ordinal
                {
                    // get function addres
                    func_address = GetProcAddress(dll_handle, (LPCSTR)(orig_thunk->u1.Ordinal & 0xffff));  // ordinal value in lower 16 bit of ordinal

                    // not working
                    if (func_address == NULL)
                    {
                        printf("GetModuleAddress failed");
                    }

                }

                // write the address in table
                first_thunk->u1.Function = (ULONGLONG)func_address;

                // forward function
                orig_thunk++;
                first_thunk++;

            }
            // forward dll
            import_desc++;
        }

    }

    // add the assembly of trampolie and jumps table:
    


    // call to entery point

    DWORD entery_point_rva = optional_header.AddressOfEntryPoint;
    /*
    using run_entery_point = void(*)();
    run_entery_point to_run = (run_entery_point)((BYTE*)virtual_memory + entery_point_rva);
    */

    // address of start of code
    BYTE* to_run = (BYTE*)virtual_memory + entery_point_rva;

    // delete all the cache - i dont want that it will run from what he remember, i want to run from what that write in memory
    FlushInstructionCache(GetCurrentProcess(), virtual_memory, allocate_size);

    // open thread for the code
    DWORD THREAD_ID;
    HANDLE image_run_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)to_run, NULL, 0, &THREAD_ID);

    // sont close the procces while the thread run
    WaitForSingleObject(image_run_thread, INFINITE);

    // free

    free(buffer);
    free(enc);
    VirtualFree(virtual_memory, 0, MEM_RELEASE);

    // close threads handles
    CloseHandle(image_run_thread);
    //CloseHandle(anti_debug_thread);


}
