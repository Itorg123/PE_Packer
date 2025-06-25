// PACKER.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
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
int main()
{
    // Read the exe -> read the .encrypt section -> decrypt -> run 


    // open file

    FILE* exe;
    
    if (fopen_s(&exe, "blabla.exe", "rb") == 0 || !exe);
    {
        printf("Open file failed");
        return 0;
    }

    // find file size

    fseek(exe, 0, SEEK_END);
    int this_size = ftell(exe);
    fseek(exe, 0, SEEK_SET);

    // read to buffer

    unsigned char * buffer = (unsigned char *)malloc(this_size);
    fread(buffer, 1, this_size, exe); // 1 byte * size

    // dos_header -> nt_header -> file_header
    //                   ||          
    //                   \/
    //                 optional_header -> 
    

    // dos_header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer;

    // nt_header
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)buffer + dos_header->e_lfanew;

    // file_header
    PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)(nt_header->FileHeader);

    // number of sections
    int section_number = file_header->NumberOfSections;

    int size_of_section_header = sizeof(IMAGE_SECTION_HEADER);
    
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);


    for (int i = 0; i < section_number; i++) 
    {
        if (section_header->Name == ".encrypt")
        {
            // size, offset of header
            int encrypt_offset = section_header->PointerToRawData;
            int encrypt_size = section_header->SizeOfRawData;
            
            fseek(exe, encrypt_offset, SEEK_SET);

            // 
        }
    }
    // section_header.  


}
