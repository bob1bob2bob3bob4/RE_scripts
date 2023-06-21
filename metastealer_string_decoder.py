import idautils
import re
import idc
import idaapi

# hash: 6cf8bfba1b221effcb1eccec0c91fb0906d0b8996932167f654680cb3ac53aac
#.text:100D9A9D 66 0F EF 8D 80 FD FF FF                 pxor    xmm1, xmmword ptr [ebp-280h]
#.text:100CB079 C5 FD EF 45 80                          vpxor   ymm0, ymm0, ymmword ptr [ebp-80h]


# Define the binary pattern


# Define the pattern
pattern_pxor = rb'\x66[\x00-\x0f]\xef'
regex_pxor = re.compile(pattern_pxor)

pattern_vpxor = rb'\xC5[\xf0-\xff]\xEF'
regex_vpxor = re.compile(pattern_vpxor)
print("===================")

pattern1 = b'''\xc7\x85..\xff\xff....'''


# Iterate over all functions in the database
for function_ea in idautils.Functions():
    offset = function_ea
    function = idaapi.get_func(function_ea)
    function_size = function.size()
    if function_size > 500:
        for address in idautils.FuncItems(function_ea):
            opcode = idc.get_bytes(address, idc.get_item_size(address))
            if regex_pxor.search(opcode):
                # print(f"pxor found at address: 0x{address:08X}")
                # print(f"offset address: 0x{offset:08X}")
                # print(f"function_ea address: 0x{function_ea:08X}")
                bytes_values = idaapi.get_bytes(offset+4, address - offset)
                # print(bytes_values)
                vals = re.findall(pattern1, bytes_values)
                if vals != []:
                    if len(vals) > 8:
                        tmp_data = vals[-8:]

                    else:
                        tmp_data = vals

                try:        
                    xor_data1 = tmp_data[0][-4:]
                    xor_data1 += tmp_data[1][-4:]
                    xor_data1 += tmp_data[2][-4:]
                    xor_data1 += tmp_data[3][-4:]

                    xor_data2 = tmp_data[4][-4:]
                    xor_data2 += tmp_data[5][-4:]
                    xor_data2 += tmp_data[6][-4:]
                    xor_data2 += tmp_data[7][-4:]

                    xor_data1 = bytearray(xor_data1)
                    xor_data2 = bytearray(xor_data2)

                    for i in range(len(xor_data1)):
                        xor_data1[i] ^= xor_data2[i]

                    tmp_str = b''.join(xor_data1.split(b'\x00'))
                    if tmp_str.isascii():
                        print(tmp_str)    

                except:
                    # print("data length is not 8 for 0x{function_ea:08X}")
                    pass


                
                offset = address     












