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



void decrypt(unsigned char *encrypted_data, int size)
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



int main()
{
    // Read the exe -> read the .encrypt section -> decrypt -> run 

    // open file
    FILE* exe;
    
    fopen_s(&exe, "C:\\Users\\Itay H\\Desktop\\cyber\\packer_project_learn\\PACKER_00.exe", "rb");
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

    unsigned char * buffer = (unsigned char *)malloc(this_size);
    fread(buffer, 1, this_size, exe); // 1 byte * size

    // dos_header -> nt_header -> file_header
    //                   ||          
    //                   \/
    //                 optional_header -> 
    

    // dos_header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer;

    // nt_header
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(buffer + dos_header->e_lfanew);

    // file_header
    IMAGE_FILE_HEADER file_header = (IMAGE_FILE_HEADER)(nt_header->FileHeader);

    // number of sections
    int section_number = file_header.NumberOfSections;


    int size_of_section_header = sizeof(IMAGE_SECTION_HEADER);
    
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);


    for (int i = 0; i < section_number; i++) 
    {
        if (!memcmp(section_header->Name, ".encrypt", strlen(".encrypt")))
        {
            // size, offset of header
            int encrypt_offset = section_header->PointerToRawData;
            int encrypt_size = section_header->SizeOfRawData;
            
            // start from the section offset
            fseek(exe, encrypt_offset, SEEK_SET);

            // read to buffer
            unsigned char* enc = (unsigned char*)malloc(encrypt_size);
            fread(enc, 1, encrypt_size, exe);

            // decrypt
            decrypt(enc, encrypt_size);
            
            break;
        }

        section_header++;
    }

}
