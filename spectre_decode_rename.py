# thanks OAlab https://github.com/OALabs
import idaapi
import idautils
import ida_bytes
import idc
import ida_kernwin
import json
import string
import ida_loader
import logging
import ida_name

strings = {
0x450A7C: "76E894005c2DE86E40b032a0931D2ABC05C6eB36ACb1C18F5b640aD24Bbc9454",
0x19FEC8: "OzYuOT02LjY1LDUw",
0x19FEE0: "ZWN0bXtjYXJtZ2xjaXxjbWFya28sYW9t",
0x19FEF8: "Y2xnbWRpbmFpaGRmZnpnZHJpYWssYW9t",
0x45098C: "1950BC4F01",
0x4506F8: "17B4C29833",
0x45080C: "EEE592271B",
0x450590: "CullinetProgram",
0x450B90: "680FDC",
0x450578: "ACDB39",
0x450A34: "09-23",
0x450860: "rhnu.dll",
0x450650: "nyxhv",
0x4505D8: "B3C830CA-4433-CC3A-6737",
0x4509A4: "uhapy",
0x4508F0: "http://manjitaugustuswaters.com",
0x450740: "jnml.php",
0x450638: "grfq.php",
0x450698: "tsml.zip",
0x450A4C: "tsml_nonir.zip",
0x450BF0: "wvxk.zip",
0x450B0C: "wvxk_x64.zip",
0x450B78: "wsau.exe",
0x4505C0: "nico=",
0x450B3C: "&yfat=",
0x450A04: "&zbce=",
0x450AAC: "&qiob=",
0x4508A8: "&jwrb=",
0x4507AC: "&nsmb=",
0x4506B0: "&inau=",
0x450608: "&wpof=",
0x45077C: "&chja=",
0x4509BC: "&ehin=",
0x4508C0: "&vmzn=",
0x4509EC: "&ouej=",
0x450944: "&rzya=",
0x450890: "&cdyt=",
0x45092C: "&rich=",
0x450794: "&clsx=",
0x450ADC: "&hwqy=",
0x4505A8: "?selk=",
0x450BD8: "vdle",
0x450BC0: "down/",
0x450560: "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
0x45083C: "nircmdc.exe",
0x450BA8: "zip.exe",
0x450680: "/c ping localhost -n 6 > nul &",
0x450974: "/c ping localhost -n 10 > nul &",
0x4505F0: "cout",
0x4507F4: "http://",
0x450AC4: "true",
0x450908: "false",
0x4509D4: "void",
0x450A94: ".asd",
0x450620: "[@]",
0x4508D8: "[|]",
0x4507DC: "[*]",
0x450710: ".png",
0x450668: ".exe",
0x450B54: ".lnk",
0x450764: ".vbs",
0x450B24: ".txt",
0x450728: ".7z",
0x4506E0: ".bak",
0x450A1C: " --headless=old --disable-gpu --remote-debugging-port=0 ",
0x4507C4: "MyTasks\\"
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def set_hexrays_comment(address, text):
    """
    Set a comment in the decompiled code at the specified address.

    Args:
        address (int): The address in the decompiled code where the comment should be set.
        text (str): The comment text to set.

    """
    try:
        cfunc = idaapi.decompile(address)
        tl = idaapi.treeloc_t()
        tl.ea = address
        tl.itp = idaapi.ITP_SEMI
        if cfunc is not None:
            cfunc.set_user_cmt(tl, text)
            cfunc.save_user_cmts() 
    except Exception as e:
        print(f"Unable to comment pseudocode at {hex(address)}")


def set_comment(address, text):
    """
    Set a comment in both the disassembly and decompiled code at the specified address.

    Args:
        address (int): The address where the comment should be set.
        text (str): The comment text to set.
    """
    ## Set in dissassembly
    idc.set_cmt(address, text,0)
    ## Set in decompiled data
    set_hexrays_comment(address, text)



for k in strings.keys():
    decde_str = strings[k]
    print(f"{hex(k)}: {decde_str}")
    ida_name.set_name(k, decde_str, ida_name.SN_FORCE)
    set_comment(k, decde_str)
    