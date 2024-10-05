import pefile
from capstone import *

def disas_code(file_path):
    pe = pefile.PE(file_path)

    text_section = None
    """Retrieve the .text section from the PE file."""
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == '.text':
            text_section = section
            break

    if not text_section:
        print("no .text section found")
        return 

    text_va = text_section.VirtualAddress
    text_size = text_section.Misc_VirtualSize

    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entrypoint_address = entrypoint + pe.OPTIONAL_HEADER.ImageBase
    binary_code = pe.get_memory_mapped_image()[text_va:text_va+text_size]



    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

    for insn in disassembler.disasm(binary_code, entrypoint_address):
        print(f"0x{insn.address}\t{insn.mnemonic}\t{insn.op_str}")



disas_code("18a065b740da441c636bce23fd72fc0f68e935956131973f15bf4918e317bf03")