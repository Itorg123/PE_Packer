
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from capstone import *
import lief
import pefile
import struct
import os

# exe path
#path = "c:\\Users\\Itay H\\Desktop\\cyber\\packer_project_learn\\PACKER_00.exe"
#path = "C:\\Users\\Itay H\\Downloads\\GuessPass.exe"

def create_patch_dict(exe_path):
    # init pe file
    pe = pefile.PE(exe_path)

    # find .text between the sections
    for section in pe.sections:
        # remove \x00 in the ends
        name = section.Name.decode(errors='ignore').rstrip('\x00')
        print(name)
        if name == '.text': 
            # find text offset, rva
            text_rva = section.VirtualAddress
            text_offset = section.PointerToRawData
            
            # read the code from .text
            assembly_from_text = section.get_data()
            
            # stop the loop
            break
            

    """
    0:  50                      push   eax
    1:  51                      push   ecx
    2:  52                      push   edx
    3:  b8 01 00 00 00          mov    eax,0x1
    8:  e9 fc ff ff ff          jmp    9 <_main+0x9>


    between each entery there are 13 bytes

    """
    # size of entery
    size_of_entery = 13

    # number of calls rel32
    calls_number = 0

    # i write the trampoline function after the exe address - so the rva from image_base is size of image
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    trampoline_start_rva = size_of_image

    # init capstone
    disa = Cs(CS_ARCH_X86, CS_MODE_32)

    print("text rva: ", text_rva)
    # disasm per rva, offset
    opcodes_rva = disa.disasm(assembly_from_text, text_rva)
    opcodes_offset = disa.disasm(assembly_from_text, text_offset)

    # dict for address as (key, value) = (offset, rva)
    change_places = {}

    # istructions list
    inst_lst = []
    
    # the rva of the instructions, i will uses this for calculate the absolute addresses in table
    inst_rva_lst = []
    
    # i think that zip is the best option to move on 2 vars
    for inst_rva, isnt_offset in zip(opcodes_rva, opcodes_offset): # run with offset and rva
        # find call
        if inst_rva.mnemonic == "call":  
            
            # call rel32
            if inst_rva.bytes[0] == 0xe8: 
                
                # add to instructions rva list
                inst_rva_lst.append(inst_rva)
                
                # add to instructions list
                inst_lst.append(bytes(inst_rva.bytes[1:5]))
                
                # write per offset in file of call rel32 the rva to the trampoline
                
                offset_to_patch = isnt_offset.address + 1  # i need to change the 4 bytes after 0xE8
                
                # eip point on the next instruction
                next_instruction_rva = inst_rva.address + inst_rva.size 
                
                # offset of entery for specific call
                offset_from_trampoline_base = size_of_entery * calls_number

                # e8 _ _ _ _, this is what that will replace the _ _ _ _ (rel32 address)
                new_call_address_rva = (trampoline_start_rva + offset_from_trampoline_base) - next_instruction_rva            
                
                # save in the dict where need change to what
                change_places[offset_to_patch] = new_call_address_rva 

                calls_number += 1
    
    return calls_number, change_places, inst_lst, inst_rva_lst


"""
  ______                                                            _     _            ______          _       
 / _____)                _               /\                        | |   | |          / _____)        | |      
| /       ____ ____ ____| |_  ____      /  \   ___  ___  ____ ____ | | _ | |_   _    | /      ___   _ | | ____ 
| |      / ___/ _  / _  |  _)/ _  )    / /\ \ /___)/___)/ _  |    \| || \| | | | |   | |     / _ \ / || |/ _  )
| \_____| |  ( (/ ( ( | | |_( (/ /    | |__| |___ |___ ( (/ /| | | | |_) | | |_| |   | \____| |_| ( (_| ( (/ / 
 \______|_|   \____\_||_|\___\____)   |______(___/(___/ \____|_|_|_|____/|_|\__  |    \______\___/ \____|\____)
                                      |      |                              (____/                              
"""
    

def create_assembly_code(calls_number):
    entery = """
    push eax
    push ecx
    push edx
    mov eax, {}
    jmp _end_of_calls_number"""

    # create assembly code
    tramp_code = ""
    for i in range(calls_number):
        tramp_code += entery.format(i)

    # add the "MAIN" of the trampoline

    # very clever trampoline - taked long time but now im happy
    # the entery pushed the registers eax, ecx, edx
    # then move to eax the entery number and jump to _end_of_calls_number
    # here i calculate the absolute address of the function
    # pop what i saved
    # replace between eax (address to jump), to eax(what i saved)
    # 'jump' by ret 
    tramp_main = """
    _end_of_calls_number:
        call _find_eip_lable 
    _find_eip_lable:
        pop ecx
        mov edx, eax
        mov eax, [ecx + edx*4 + 13]
        pop edx
        pop ecx
        xchg eax, [esp]
        ret
    """
    
    # add the main:
    tramp_code += tramp_main 
    
    print(tramp_code)

    return tramp_code


def assembler(assembly_code):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    
    encode, count = ks.asm(assembly_code, as_bytes = True)
    
    # add the first 4 bytes as meta data - size of opcode bytes
    size_of_code = len(encode)
    
    # pack to bytes
    size_as_bytes = struct.pack("<I", size_of_code)
    
    # add to start
    encode = size_as_bytes + encode
    
    print(size_of_code)
    
    return encode    



def patch_file(patches_dict: dict, path: str):
    # open file for patch
    with open(path, "r+b") as file:
        
        # change in all places
        for offset, rel32 in patches_dict.items():
            
            # move to the offset to patch
            file.seek(offset)
            
            # write the change as little endian 4 signed bytes
            file.write(struct.pack("<i", rel32)) 


def address_to_call_from_table_correct(orig_call_inst_rva: list, inst_rva_lst: list):
    
    # number of enterys
    call_numbers = len(orig_call_inst_rva)
    
    # list: per index - the absolute address for the jmp
    tramp_jmp_absolute_addresses_lst = []

    # loop per any call
    for i in range(call_numbers):
        
        # unpack the struct.pack
        orig_call_rva = struct.unpack("<i", orig_call_inst_rva[i])[0]
        
        # absolute adddress = orig_call_rva + inst_rva (even for + and - value of orig_call_rva ) + 5 (5 byte of instruction)
        absolute_address = orig_call_rva + inst_rva_lst[i].address + 5
        # add to list                
        tramp_jmp_absolute_addresses_lst.append(struct.pack("<I", absolute_address))

    # return the addresses as one bytes 'str'
    return b"".join(tramp_jmp_absolute_addresses_lst)

    

def add_section_2(pe_path, section_data, section_name):
    """Get PE path - return path to new pe with new section"""

    # loader + unpacker
    lief.PE.Binary = lief.PE.parse(pe_path)

    # create section to add
    section = lief.PE.Section(section_name)

    # write data to section
    section.content = list(section_data)

    # init characteristics for premissions - read    
    section.characteristics =  lief.PE.SECTION_CHARACTERISTICS.MEM_READ \
                             | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA

    # add section to loader-packer
    lief.PE.Binary.add_section(section)


    # save the packer
    lief.PE.Binary.write("PACKER_TRAMP.exe")


def encrypt_pe(orig_pe_path):

    # find pe size
    size = os.path.getsize(orig_pe_path)

    # encrypt

    with open(orig_pe_path, 'rb') as orig_file:
        data = orig_file.read()

    encrypted_data = bytes(data)
    key = 'Itay_h'
    for k in key[::-1]:
        encrypted_data = bytes([b^ord(k) for b in encrypted_data])

    # padding to alingment 0x1000 = 4096 bytes

    padding_size = 4096 - size%4096
    if (padding_size == 4096):
        padding_size = 0
    encrypted_data += b'\x00' * padding_size


    # save in file "encrypted_pe.bin"

    with open('encrypted_pe.bin', 'wb') as f:
        f.write(encrypted_data)


    # return path to the file even if it const

    return 'encrypted_pe.bin'


def add_section(pe_path, orig_pe_path):
    """Get PE path - return path to new pe with new section"""

    # loader + unpacker
    lief.PE.Binary = lief.PE.parse(pe_path)

    # create section to add
    section = lief.PE.Section(".encrypt")

    # encrypt the file
    encrypted_pe = encrypt_pe(orig_pe_path)


    # read encrypt data
    with open(encrypted_pe, 'rb') as enc_pe:
        enc = enc_pe.read()


    # write data to section
    section.content = list(enc)

    # init characteristics for premissions - read    
    section.characteristics =  lief.PE.SECTION_CHARACTERISTICS.MEM_READ \
                             | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA

    # add section to loader-packer
    lief.PE.Binary.add_section(section)


    # save the packer
    lief.PE.Binary.write("PACKER_TRAMP.exe")


def main():
    loader_path = "C:\\Users\\Itay H\\source\\repos\\PACKER\\PACKER\\PACKER_TRAMP.exe"
    exe_from_client_path = "C:\\Users\\Itay H\\source\\repos\\PACKER\\PACKER\\check_exe_2.exe"
    loader_path_2 = "C:\\Users\\Itay H\\Desktop\\cyber\\packer_project_learn\\PACKER_TRAMP.exe"

    calls_number, change_places, inst_lst, inst_rva_lst = create_patch_dict(exe_from_client_path)
    
    # change e8 calls
    patch_file(change_places, exe_from_client_path)
    
    # add section - encrypted pe file
    add_section(loader_path, exe_from_client_path)
    
    # create the assembly and make from this bytes of opcodes
    assembly_code = create_assembly_code(calls_number)
    assembly_bytes = assembler(assembly_code)
    
    # jump table: absolute addresses of functions
    address_to_jump_from_trampoline_bytes = address_to_call_from_table_correct(inst_lst, inst_rva_lst)

    # add the assembly bytes
    add_section_2(loader_path_2, assembly_bytes, '.trampol')
    
    # add the table
    add_section_2(loader_path_2, address_to_jump_from_trampoline_bytes, '.address')
    

if __name__ == "__main__":
    main()


"""
part from table as example:
    
    ; entery 1307
    push eax
    push ecx
    push edx
    mov eax, 1307
    jmp _end_of_calls_number
    
    ; entery 1308
    push eax
    push ecx
    push edx
    mov eax, 1308
    jmp _end_of_calls_number

    ; entery 1309
    push eax
    push ecx
    push edx
    mov eax, 1309
    jmp _end_of_calls_number
    
    
    ; 'main' of trampoline
    _end_of_calls_number:
        call _find_eip_lable 
        
    _find_eip_lable:
        pop ecx
        mov edx, eax
        mov eax, [ecx + edx*4 + 13]
        
        pop edx
        pop ecx
        xchg eax, [esp]
        
        ret 
"""

