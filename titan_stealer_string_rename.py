import idautils
import idaapi 
import ida_allins
from idc import *

# sample: A7DFB6BB7CA1C8271570DDCF81BB921CF4F222E6E190E5F420D4E1EDA0A0C1F2
# purpose: rename global variables in main_init function

def next_ins(ea, n):
    i = 0
    while i < n:
        ea = next_head(ea)
        i += 1

    return ea
     
def prev_ins(ea, n):
    i = 0
    while i < n:
        ea = prev_head(ea)
        i += 1
        
    return ea     

def process_string_trim(ea):

    curr =  ea
    rename_ea =  next_ins(curr, 3)
    # print("%x" % rename_ea)
    ea = prev_head(ea)
    length =print_operand(ea,1)
    ea = prev_ins(ea, 2)
    trim_data_addr = get_operand_value(ea, 1)
    trim_value = get_wide_byte(trim_data_addr)
    ea = prev_head(ea)
    data_len = get_operand_value(ea, 1)
    ea = prev_ins(ea, 2)
    data_addr = get_operand_value(ea, 1)
    data = get_bytes(data_addr, data_len)
    trimmed_data = data.decode().split(chr(trim_value))

    op = print_operand(rename_ea, 0)
    print(op)
    set_name(op, trimmed_data[0], SN_CHECK)


def rename_strings(addr_func):
    f = ida_funcs.get_func(addr_func)
    addr_start = f.start_ea
    addr_end = f.end_ea

  
    for ea in idautils.Heads(addr_start, addr_end):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        if insn.itype == ida_allins.NN_call:
            print("Call at %x" % ea)
            curr = ea
            func_name = print_operand(ea, 0)
            if func_name == "strings_Trim":
                process_string_trim(curr)
                

def main():
    rename_strings(0x004E19C0)



if __name__ == "__main__":
    main()        