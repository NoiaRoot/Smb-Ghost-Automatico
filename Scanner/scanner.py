import socket
import struct
import hexdump

def scanner_smb_ghost(ip,port):
    #print ("Hemos recibido",ip,port)
    header = b"\xfeSMB" # magic
    header += struct.pack("H", 64) # header size
    header += struct.pack("H", 0) # credit charge
    header += struct.pack("H", 0) # channel sequence
    header += struct.pack("H", 0) # reserved
    header += struct.pack("H", 0) # negotiate protocol command
    header += struct.pack("H", 31) # credits requested
    header += struct.pack("I", 0) # flags
    header += struct.pack("I", 0) # chain offset
    header += struct.pack("Q", 0) # message id
    header += struct.pack("I", 0) # process id
    header += struct.pack("I", 0) # tree id
    header += struct.pack("Q", 0) # session id
    header += struct.pack("QQ", (0 >> 64) & 0xffffffffffffffff, 0 & 0xffffffffffffffff) # signature

    negotiation = b""
    negotiation += struct.pack("H", 0x24) # struct size
    negotiation += struct.pack("H", 8) # amount of dialects
    negotiation += struct.pack("H", 1) # enable signing
    negotiation += struct.pack("H", 0) # reserved
    negotiation += struct.pack("I", 0x7f) # capabilities
    negotiation += struct.pack("QQ", (0 >> 64) & 0xffffffffffffffff, 0 & 0xffffffffffffffff) # client guid
    negotiation += struct.pack("I", 0x78) # negotiation offset
    negotiation += struct.pack("H", 2) # negotiation context count
    negotiation += struct.pack("H", 0) # reserved
    negotiation += struct.pack("H", 0x0202) # smb 2.0.2 dialect
    negotiation += struct.pack("H", 0x0210) # smb 2.1.0 dialect
    negotiation += struct.pack("H", 0x0222) # smb 2.2.2 dialect
    negotiation += struct.pack("H", 0x0224) # smb 2.2.4 dialect
    negotiation += struct.pack("H", 0x0300) # smb 3.0.0 dialect
    negotiation += struct.pack("H", 0x0302) # smb 3.0.2 dialect
    negotiation += struct.pack("H", 0x0310) # smb 3.1.0 dialect
    negotiation += struct.pack("H", 0x0311) # smb 3.1.1 dialect
    negotiation += struct.pack("I", 0) # padding
    negotiation += struct.pack("H", 1) # negotiation context type
    negotiation += struct.pack("H", 38) # negotiation data length
    negotiation += struct.pack("I", 0) # reserved
    negotiation += struct.pack("H", 1) # negotiation hash algorithm count
    negotiation += struct.pack("H", 32) # negotiation salt length
    negotiation += struct.pack("H", 1) # negotiation hash algorithm SHA512
    negotiation += struct.pack("H", 1) # negotiation hash algorithm SHA512
    negotiation += struct.pack("QQ", (0 >> 64) & 0xffffffffffffffff, 0 & 0xffffffffffffffff) # salt part 1
    negotiation += struct.pack("QQ", (0 >> 64) & 0xffffffffffffffff, 0 & 0xffffffffffffffff) # salt part 2
    negotiation += struct.pack("H", 3) # unknown??
    negotiation += struct.pack("H", 10) # data length unknown??
    negotiation += struct.pack("I", 0) # reserved unknown??
    negotiation += b"\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" # unknown??

    packet = header + negotiation

    netbios = b""
    netbios += struct.pack("H", 0) # NetBIOS sessions message (should be 1 byte but whatever)
    netbios += struct.pack("B", 0) # just a pad to make it 3 bytes
    netbios += struct.pack("B", len(packet)) # NetBIOS length (should be 3 bytes but whatever, as long as the packet isn't 0xff+ bytes)

    packet = netbios + packet

    print(f"NetBIOS ({len(netbios)}): {netbios.hex()}")
    print(f"Cabeçalho ({len(header)}): {header.hex()}")
    print(f"Negociação ({len(negotiation)}): {negotiation.hex()}")
    print(f"Pacote ({len(packet)}): {packet.hex()}")

    hexdump.hexdump(packet)

    io = socket.socket(socket.AF_INET)
    io.connect((str(ip), int(port)))
    io.send(packet)
    size = struct.unpack("I", io.recv(4))[0]
    print(f"Comprimento da resposta: {size}")
    response = io.recv(size)
    print(f"Resposta: {response.hex()}")

    hexdump.hexdump(response)

    version = struct.unpack("H", response[68:70])[0]
    context = struct.unpack("H", response[70:72])[0]

    if version != 0x0311:
        print(f"SMB versão {hex(version)} foi encontrado que não é vulnerável!")
        return False
    elif context != 2:
        print(f"Servidor respondeu com contexto {hex(context)} o que indica que o destino pode não ter a compactação SMB habilitada e, portanto, não é vulnerável!")
        return False
    else:
        print(f"SMB versão {hex(version)} com contexto {hex(context)} foi encontrado o que indica que o SMBv3.1.1 está sendo usado e a compactação SMB está habilitada, sendo portanto vulnerável a CVE-2020-0796!")
        return True
