
import pefile
import os
import json

DLL_LIST = [
    'kernel32.dll', 'shell32.dll',  'user32.dll',
    'gdiplus.dll', 'ole32.dll', 'advapi32.dll',
    'gdi32.dll', 'ntdll.dll', 'shlwapi.dll', 'ws2_32.dll'
]

export_list = []

def mw_api_hash(string: str) -> int:

    seed = 0xC4D5A97A  
    hash_value = seed
    
    for char in string:
        char_value = ord(char) 
        temp = (hash_value * 32) + char_value  
        hash_value ^= ((hash_value >> 2) + temp) & 0xFFFFFFFF
    
    return hash_value & 0xFFFFFFFF

dll_exports = {}

for item in os.listdir("C:\\Windows\\System32"):
    if item.lower() in DLL_LIST:
        pe = pefile.PE(f"C:\\Windows\\System32\\{item}")
        exports = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                export_name = exp.name.decode('utf-8')
                export_hash = mw_api_hash(export_name)
                exports.append({"name": export_name, "hash": hex(export_hash)})
            except:
                continue
        dll_exports[item] = exports


with open('dll_exports.json', 'w') as json_file:
    json.dump(dll_exports, json_file, indent=4)

print("Export list saved to dll_exports.json")


