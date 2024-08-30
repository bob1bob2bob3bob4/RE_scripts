from unicorn import *
from unicorn.x86_const import *
import struct
from capstone import *
from capstone.x86 import *



def decrypt_string(code):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # setup the stack
    stack_base = 0x00100000
    stack_size = 0x00100000

    RSP = stack_base + (stack_size // 2)
    uc.mem_map(stack_base, stack_size)
    uc.mem_write(stack_base, b"\x00" * stack_size)

    uc.reg_write(UC_X86_REG_RSP, RSP)


    # setup the code

    target_base = 0x00400000
    target_size = 0x00100000
    target_end = target_base + len(code)

    uc.mem_map(target_base, target_size, UC_PROT_ALL)
    uc.mem_write(target_base, b"\x00" * target_size)
    uc.mem_write(target_base, code)

    data_base = 0x00600000
    data_size = 0x00100000

    uc.mem_map(data_base, data_size, UC_PROT_ALL)
    uc.mem_write(data_base, b"\x00" * data_size)

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True

    def trace(uc, address, size, user_data):
        insn = next(cs.disasm(uc.mem_read(address, size), address))
        # print(f"0x{address:08x} {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic == "call":
            # print("Ending on a call!")
            uc.emu_stop()

    uc.reg_write(UC_X86_REG_R14, data_base)
    uc.hook_add(UC_HOOK_CODE, trace, None)
    uc.emu_start(target_base, target_end, 0, 0)
    ptr_string = uc.reg_read(UC_X86_REG_RBX)
    # print(hex(ptr_string))
    size = uc.reg_read(UC_X86_REG_RCX)
    string_data = uc.mem_read(ptr_string, size)
    string = string_data.decode("utf-8")

    return string


#code_string = bytes.fromhex('49 3B 66 10 0F 86 C8 00 00 00 48 83 EC 38 48 89 6C 24 30 48 8D 6C 24 30 48 BA E5 B1 F0 56 65 EA 73 C9 48 89 54 24 18 66 C7 44 24 20 6F 6E 48 BA 02 00 01 05 01 05 05 07 48 89 54 24 22 48 BA 05 07 05 02 00 07 07 05 48 89 54 24 28 31 C0 EB 1D 44 0F B6 4C 34 18 41 29 D1 41 8D 51 E1 88 54 3C 18 41 8D 50 E1 88 54 34 18 48 83 C0 02 48 83 F8 0E 7D 27 0F B6 54 04 22 0F B6 74 04 23 89 D7 31 F2 01 C2 48 83 FF 0A 73 3C 44 0F B6 44 3C 18 41 29 D0 48 83 FE 0A 72 B8 EB 1B 31 C0 48 8D 5C 24 18 B9 0A 00 00 00 E8 D5 B8 88 FF 48 8B 6C 24 30 48 83 C4 38 C3 89 F0 B9 0A 00 00 00 0F 1F 40 00 E8 3B 02 8A FF 89 F8 B9 0A 00 00 00 E8 2F 02 8A FF 90 E8 A9 DB 89 FF E9 24 FF FF FF')
# code_string = bytes.fromhex('49 3B 66 10 0F 86 EC 00 00 00 48 83 EC 50 48 89 6C 24 48 48 8D 6C 24 48 48 BA 7F C7 83 72 BA 88 65 66 48 89 54 24 1D 48 BA 88 65 66 DB 93 6A AE 20 48 89 54 24 22 48 BA C8 69 35 A3 61 9A 20 9E 48 89 54 24 2A 48 BA 04 0F 10 09 05 09 08 0B 48 89 54 24 32 48 BA 08 0B 0D 14 12 01 02 0B 48 89 54 24 38 48 BA 00 02 0A 14 12 0F 00 08 48 89 54 24 40 31 C0 EB 1D 44 0F B6 4C 34 1D 41 29 D1 41 8D 51 F6 88 54 3C 1D 41 8D 50 F6 88 54 34 1D 48 83 C0 02 48 83 F8 16 7D 29 0F B6 54 04 32 0F B6 74 04 33 89 D7 31 F2 01 C2 48 83 FF 15 73 3A 44 0F B6 44 3C 1D 41 29 D0 48 83 FE 15 72 B8 66 90 EB 1B 31 C0 48 8D 5C 24 1D B9 15 00 00 00 E8 8D 69 FC FF 48 8B 6C 24 48 48 83 C4 50 C3')
# decoded_string = decrypt_string(code_string)
# print(decoded_string)

