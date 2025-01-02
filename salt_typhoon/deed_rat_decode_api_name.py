#hash: df9904b5d0820ade91a9919512a09bae1ea2c2c8af6ce20594c4f236869043a8
# This IDA script is used to decode the encrypted windows API called by Deed RAT.

import ida_bytes
import idc
import idautils
import idaapi

def rol(value, shift, bit_size=8):
    mask = (1 << bit_size) - 1  
    shift %= bit_size  
    return ((value << shift) & mask) | (value >> (bit_size - shift))

def ror(value, shift, bit_size=8):
    mask = (1 << bit_size) - 1 
    shift %= bit_size  
    return ((value >> shift) | (value << (bit_size - shift))) & mask


def api_decode(address):
    init_key = ida_bytes.get_byte(address)
    start = hex(address)
    print(f'start address is {start}')
    print(f'init key is {hex(init_key)}')
    key = init_key & 0xFF

    result = ""
    for i in range(4096):
        data = ida_bytes.get_byte(address+i+1)
   
        out = data ^ key
        if out == 0:
            break
        else:
            result += chr(out)
            tmp_key = rol(key, 3, 8) &0xFF
      
            key1 = (tmp_key * tmp_key) &0xFF
            key2 = (key * key) & 0xFF
            key3 = ror((key * tmp_key) &0xFF,3,8) &0xFF

            key = ((((key1 + key2) &0xFF) ^ key3) + init_key) &0xFF
      

            init_key = key

    print(result)
    return result


def find_call_address(address):
    caller_adress = []
    for xref in idautils.XrefsTo(address,0):
        caller_adress.append(xref.frm)
    return caller_adress
        

def find_index(caller_address):
        
        current_addr = caller_address
        for _ in range(20):
            current_addr = idc.prev_head(current_addr)
            if current_addr == idaapi.BADADDR:
                return None, None
            mnem = idc.print_insn_mnem(current_addr)
            op1 = idc.print_operand(current_addr, 0)

            if mnem == "mov" and op1 == "edx":
                value = idc.get_operand_value(current_addr, 1)
                print(f"Found mov ecx, {hex(value)} at address {hex(current_addr)}")
                return current_addr, value
        
        return None, None

def find_all_index(target_decrypt_func):
    for caller_addr in find_call_address(target_decrypt_func):
        mov_addr, str_addr = find_index(caller_addr)
        if str_addr is not None:  
            print(f"\nDecoding string from call at {hex(caller_addr)}:")
            result = api_decode(str_addr)   
            set_comment(caller_addr, result)    

def set_comment(address, text):
    idc.set_cmt(address, text, 0)



target_decrypt_func = 0x00BF0B16


# api_decode(0x0BF7BCC)

find_all_index(target_decrypt_func)


