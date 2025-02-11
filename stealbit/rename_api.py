from idautils import *
from idaapi import *
from idc import *
import json

def extract_hash_index(start_addr, end_addr):

    extracted_values = []


    if not is_loaded(start_addr) or not is_loaded(end_addr):
        print("[!] Invalid address range!")
        return []

    print(f"Extracting DWORD values from {hex(start_addr)} to {hex(end_addr)}:\n")

    addr = start_addr
    while addr <= end_addr:
        dword_value = get_wide_dword(addr) 
        extracted_values.append((addr, dword_value))
        
        print(f"{hex(addr)} -> {hex(dword_value)}")  

        addr += 4 

    return extracted_values


       
def rename_api_address(json_file, api_address_list):
    with open(json_file, "r") as json_f:
        data = json.load(json_f)

    for api_hash in api_address_list:
        target_hash = api_hash[1]
        for dll, functions in data.items():
            for function in functions:
                if int(function["hash"], 16) == target_hash:
                    safe_name = function['name']
                    print(f"found {safe_name} in {hex(api_hash[0])}")
                    if set_name(api_hash[0], safe_name, SN_NOWARN):
                        print(f"[+] Renamed {hex(api_hash[0])} -> {safe_name}")
                        



# start_addr = 0x40C8A8
# end_addr = 0x40C8FC

start_addr = 0x0040D150
end_addr = 0x0040D178

hash_list = extract_hash_index(start_addr, end_addr)
rename_api_address("dll_exports.json", hash_list)









