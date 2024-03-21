import idaapi

# get comment by the address
def get_current_comment(address):
    try:
        mnemonic = idaapi.print_insn_mnem(address)
        if mnemonic:
            comment = idaapi.get_cmt(address, 2)
            return comment
        else:
            return None
    except Exception as e:
        print(f"Error occurred while retrieving comment at 0x{address}")
        return None            

