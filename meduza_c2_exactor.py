from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
import re
import pefile
import sys


# e2cc35ec3dcbd33d5d75fe7cabe4400dcdf06cf5e7fc3e94a1b3b6f2d8cbd125


def decrypt_string_x64(code):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # setup the stack
    stack_base = 0x00100000
    stack_size = 0x00100000

    RSP = stack_base + (stack_size // 2)
    uc.mem_map(stack_base, stack_size)
    uc.mem_write(stack_base, b'\x00' * stack_size)
    uc.reg_write(UC_X86_REG_RSP, RSP)
    uc.reg_write(UC_X86_REG_RBP, stack_base)

    # setup the code
    target_base = 0x00400000
    target_size = 0x00100000
    target_end = target_base + len(code)

    uc.mem_map(target_base, target_size, UC_PROT_ALL)
    uc.mem_write(target_base, b'\x00' * target_size)
    uc.mem_write(target_base, code)

    data_base = 0x00600000
    data_size = 0x00100000

    uc.mem_map(data_base, data_size, UC_PROT_ALL)
    uc.mem_write(data_base, b'\x00' * data_size)

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True



    def trace(uc, address, size, user_data):
        insn = next(cs.disasm(uc.mem_read(address, size), address))
        # print(f"0x{address:x}:\t{insn.mnemonic}\t{insn.op_str}")
        if insn.mnemonic == "call":
            # print("Ending on a call!!!")
            uc.emu_stop()


    uc.hook_add(UC_HOOK_CODE, trace, None)
    uc.emu_start(target_base, target_end, 0,0) 

    ptr_str = uc.reg_read(UC_X86_REG_RAX)
    # print(hex(ptr_str))
    size = uc.reg_read(UC_X86_REG_R8)
    # print(size)
    string_data = uc.mem_read(ptr_str, size)
    string = string_data.decode('utf-8')
    print(string)

  
def decrypt_string_x32(code):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    # setup the stack
    stack_base = 0x00100000
    stack_size = 0x00100000

    ESP = stack_base + (stack_size // 2)
    uc.mem_map(stack_base, stack_size)
    uc.mem_write(stack_base, b'\x00' * stack_size)
    uc.reg_write(UC_X86_REG_ESP, ESP)
    uc.reg_write(UC_X86_REG_EBP, stack_base)

    # setup the code
    target_base = 0x00400000
    target_size = 0x00100000
    target_end = target_base + len(code)

    uc.mem_map(target_base, target_size, UC_PROT_ALL)
    uc.mem_write(target_base, b'\x00' * target_size)
    uc.mem_write(target_base, code)

    data_base = 0x00600000
    data_size = 0x00100000

    uc.mem_map(data_base, data_size, UC_PROT_ALL)
    uc.mem_write(data_base, b'\x00' * data_size)

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True



    def trace(uc, address, size, user_data):
        insn = next(cs.disasm(uc.mem_read(address, size), address))
        print(f"0x{address:x}:\t{insn.mnemonic}\t{insn.op_str}")
        if insn.mnemonic == "call":
            print("Ending on a call!!!")
            uc.emu_stop()


    uc.hook_add(UC_HOOK_CODE, trace, None)
    uc.emu_start(target_base, target_end, 0,0) 

    ptr_str = uc.reg_read(UC_X86_REG_EAX)
    print(hex(ptr_str))
    size = uc.reg_read(UC_X86_REG_ECX)
    print(size)
    string_data = uc.mem_read(ptr_str, size)
    string = string_data.decode('utf-8')
    print(string)


def extract_x64_C2(section_data):
    pattern = rb'\x48....\x07\x00\x48....\x08\x00'
    functions = []

    for match in re.finditer(pattern, section_data, re.DOTALL):
        end = match.end() + 8
        tmp_data = section_data[:end]
        start = tmp_data.rfind(b'\x48\x89\x5C\x24\x10')
        if start == 1:
            continue
        tmp_data = tmp_data[start:]
        functions.append(tmp_data)
  
    for function in functions:
        try:
            decrypt_string_x64(function)
        except:
            pass  

def extract_x32_C2(section_data):
    pattern = rb'\x0f\x11\x05....\xc7\x05....\x00\x00\x00\x00\xE8'
    functions = []

    for match in re.finditer(pattern, section_data, re.DOTALL):
        end = match.end() + 8
        tmp_data = section_data[:end]
        start = tmp_data.rfind(b'\x53\x8B\xDC\x83\xEC\x08')
        if start == 1:
            continue
        tmp_data = tmp_data[start:]
        functions.append(tmp_data)

    print(functions)
    
    for function in functions:
        try:
            decrypt_string_x32(function)
        except:
            pass  


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <Meduza file>")
        sys.exit(1)
        
    pe = pefile.PE(sys.argv[1])
    file_data = open(sys.argv[1], 'rb').read()
    
    section_data = None
    for section in pe.sections:
        if section.Name[:6] == b'.text\x00':
            section_data = section.get_data()
            break

    assert section_data is not None

    extract_x64_C2(section_data)


