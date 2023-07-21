import re

# sample hash: 43cc6ed0dcd1fa220283f7bbfa79aaf6342fdb5e73cdabdde67debb7e2ffc945
try:
    with open("stage1.txt", "r") as file:
        content = file.read()
except FileNotFoundError:
    print("File stage1.txt not found") 
except IOError:
    print("Error reading the file stage1.txt")


def deobfuscate(script):

    def deobfuscate_chars(match):
        char_code = match.group(1)
        if '-' in char_code:
            items = char_code.split('-')
            char_code = str(int(items[0]) - int(items[1]))
        return chr(int(char_code))

    regex =  r"\[char\]\((\d+-\d+)\)\+?"

    deobfuscated_script = re.sub(regex,  deobfuscate_chars, script)

    expression_pattern = r"\[char\](\d+)\+?"
    deobfuscated_script = re.sub(expression_pattern, lambda match: chr(int(match.group(1))),deobfuscated_script)
    arithmetic_pattern = r"\((\d+)-(\d+)\)"
    deobfuscated_script = re.sub(arithmetic_pattern, lambda match: str(int(match.group(1)) - int(match.group(2))), deobfuscated_script)



    return deobfuscated_script


print(deobfuscate(content))      