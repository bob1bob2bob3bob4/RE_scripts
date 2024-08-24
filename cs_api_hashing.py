def ROR(data, bits):
    return ((data & 0xFFFFFFFF) >> bits) | ((data << (32 - bits)) & 0xFFFFFFFF)

def hash_api(dll_name, api_name):
    dll_hash = 0
    api_hash = 0
    dll = dll_name.upper().encode('utf-16')[2:] + b'\x00\x00'
    print(dll)
    api = bytes(api_name, 'utf-8') + b'\x00'

    for i in range(len(dll)):
        dll_hash = ROR(dll_hash, 0x0d) + dll[i]

    for i in range(len(api)):
        api_hash = ROR(api_hash, 0x0d) + api[i]

    
    hash = dll_hash + api_hash

    return hash


print(hex(hash_api("wininet.dll", "InternetOpenA"))) #0xa779563a
