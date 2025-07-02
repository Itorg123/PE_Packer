"""

EXE from client
.
.call ___
.
_______________
trampoline code: 

mov eax, 1
pop edx  // return address
jmp end_of_calls_number

mov eax, 2
pop edx  // return address
jmp end_of_calls_number

mov eax, 3
pop edx  // return address
jmp end_of_calls_number

mov eax, 4
pop edx  // return address
jmp end_of_calls_number

mov eax, 5
pop edx  // return address
jmp end_of_calls_number

_end_of_calls_number:

    
    mov [tls+4*eax], edx
    
    calculate with eax or find in table on memory what is the correct address for the number

    call found_address

    mov edx, [tls] // return address
    
    push edx // put it again in stack
    
    ret

start_of_trampoline_rva_from_call = size_of_image -


"""

from capstone import *
import pefile
import struct

# exe path
# path = "c:\\Users\\Itay H\\Desktop\\cyber\\packer_project_learn\\PACKER_00.exe"
path = "C:\\Users\\Itay H\\Downloads\\GuessPass.exe"

def create_patch_dict(exe_path):
    # init pe file
    pe = pefile.PE(exe_path)

    # find .text between the sections
    for section in pe.sections:
        if '.text' in str(section.Name): # i think that this is not very safe - might be other section with same name
            # find text offset, rva
            text_rva = section.VirtualAddress
            text_offset = section.PointerToRawData
            
            # read the code from .text
            assembly_from_text = section.get_data()
            
            # stop the loop
            break
            

    """
    0:  b8 01 00 00 00          mov    eax,0x1
    5:  5a                      pop    edx
    6:  e9 eb be ad de          jmp    deadbef6 <_main+0xdeadbef6>

    between each entery there are 11 bytes

    """
    # size of entery
    size_of_entery = 11

    # number of calls rel32
    calls_number = 0

    # i write the trampoline function after the exe address - so the rva from image_base is size of image
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    trampoline_start_rva = size_of_image

    # init capstone
    disa = Cs(CS_ARCH_X86, CS_MODE_32)

    # disasm per rva, offset
    opcodes_rva = disa.disasm(assembly_from_text, text_rva)
    opcodes_offset = disa.disasm(assembly_from_text, text_offset)

    # dict for address as (key, value) = (offset, rva)
    change_places = {}

    for inst_rva, isnt_offset in zip(opcodes_rva, opcodes_offset): # run with offset and rva
        
        # find call
        if inst_rva.mnemonic == "call":  
            
            # call rel32
            if inst_rva.bytes[0] == 0xe8: 
                
                # write per offset in file of call rel32 the rva to the trampoline
                
                offset_to_patch = isnt_offset.address + 1  # i need to change the 4 bytes after 0xE8
                
                next_instruction_rva = inst_rva.address + inst_rva.size 
                
                offset_from_trampoline_base = size_of_entery * calls_number

                new_call_address_rva = (trampoline_start_rva + offset_from_trampoline_base) - next_instruction_rva            
                
                change_places[offset_to_patch] = new_call_address_rva 

                calls_number += 1
    
    return calls_number, change_places


"""

  ______                                                           _     _             ______          _       
 / _____)                _               /\                        | |   | |          / _____)        | |      
| /       ____ ____ ____| |_  ____      /  \   ___  ___  ____ ____ | | _ | |_   _    | /      ___   _ | | ____ 
| |      / ___/ _  / _  |  _)/ _  )    / /\ \ /___)/___)/ _  |    \| || \| | | | |   | |     / _ \ / || |/ _  )
| \_____| |  ( (/ ( ( | | |_( (/ /    | |__| |___ |___ ( (/ /| | | | |_) | | |_| |   | \____| |_| ( (_| ( (/ / 
 \______|_|   \____\_||_|\___\____)   |______(___/(___/ \____|_|_|_|____/|_|\__  |    \______\___/ \____|\____)
                                      |      |                              (____/                              
"""
    

def create_assembly_code(calls_number):
    entery = """
    mov eax, {}
    pop edx
    jmp _end_of_calls_number

    """

    # create assembly code
    tramp_code = ""
    for i in range(calls_number):
        tramp_code += entery.format(i)

    # add 

    print(tramp_code)


def patch_file(patches_dict: dict, path: str):
    # open file for patch
    with open(path, "r+b") as file:
        
        # change in all places
        for offset, rel32 in patches_dict.items():
            
            # move to the offset to patch
            file.seek(offset)
            
            # write the change as little endian 4 signed bytes
            file.write(struct.pack("<i", rel32)) 


