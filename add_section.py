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
    key = 'Itay_h'
    for k in key[::-1]:
        encrypted_data = bytes([b^ord(k) for b in encrypted_data])

    # TODO: section alingment is not const - check it before
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
    lief.PE.Binary.write("PACKER_00.exe")
    
    
add_section("C:\\Users\\Itay H\\source\\repos\\PACKER\\PACKER\\PACKER.exe", "C:\\Users\\Itay H\\source\\repos\\PACKER\\PACKER\\check_exe.exe")
