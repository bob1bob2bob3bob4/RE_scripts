import re 
import pefile
import sys
import string_decoder

file_data = open(sys.argv[1], 'rb').read()
pe = pefile.PE(data=file_data)

section_data = None
for section in pe.sections:
    if section.Name[:6] == b'.text\x00':
        section_data = section.get_data()
        break

assert section_data is not None

egg = rb'\x48\x8D\x5C..\xB9....\xE8....\x48\x8B\x6C..\x48\x83..\xC3'
## another egg:
# 48 8D 5C ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B AC ?? ?? ?? ?? ?? 48 81 ?? ?? ?? ?? ?? C3

functions = []

for m in re.finditer(egg, section_data, re.DOTALL):
    end = m.end()
    tmp_data = section_data[:end]
    start = tmp_data.rfind(b'\x49\x3B\x66\x10\x0F\x86')
    if start == 1:
        continue
    tmp_data = tmp_data[start:]
    functions.append(tmp_data)

for func in functions:
    try:
        print(string_decoder.decrypt_string(func))
    except:
        print(func.hex()[:100])    



