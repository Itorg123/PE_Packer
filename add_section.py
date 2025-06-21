
import lief
import os


"""
        recv pe
        create loader (assume that the section of the encrypt code is exist)
        encrypt orig 
        add to the loader the section
        send loader        
"""


def encrypt_pe(orig_pe_path):
    
    # find pe size
    size = os.path.getsize(orig_pe_path)
    
    # encrypt
    
    with open(orig_pe_path, 'rb') as orig_file:
        data = orig_file.read()
    
    encrypted_data = bytes(data)
    key = 'itay_h'
    for k in key:
        encrypted_data = bytes([b^ord(k) for b in encrypted_data])
    
    # padding to alingment 0x200 = 512 bytes
    
    padding_size = 512 - size%512
    if (padding_size == 512):
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
    binary = lief.parse(pe_path)
    
    
    # create section to add
    section = lief.PE.Section(".encrypt_pe")
    
    
    # encrypt the file
    encrypted_pe = encrypt_pe(orig_pe_path)
    
    
    # read encrypt data
    with open(encrypted_pe, 'rb') as enc_pe:
        enc = enc_pe.read()
    
    
    # write data to section
    section.content = list(enc)
    
    
    # add section to loader-packer
    binary.add_section(section)
    
    
    # save the packer
    binary.write("PACKER_01")
    

