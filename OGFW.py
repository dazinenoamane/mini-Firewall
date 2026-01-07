import socket
import struct
import binascii
from netfilterqueue import NetfilterQueue

# RULES
RULES = ['allow', 'deny']
#exceptions
def exceptions_rule(protocol,dst_port,rule_action):
    if protocol not in [6,17]:
        raise ValueError("Unsupported protocol. Use 6 for TCP or 17 for UDP.")
    if not (0 <= dst_port <= 65535):
        raise ValueError("Destination port must be between 0 and 65535.")
    if rule_action.lower() not in RULES:
        raise ValueError("Invalid rule action. Use 'allow', 'deny', or 'log'.")
    return (protocol,dst_port,rule_action)

# LOGS
def log(protocol,dst_port,action):
    log_file = open("firewall_log.txt", "a")
    log_file.write("Protocol: {}, Destination Port: {}, Action: {}\n".format(protocol,dst_port,action))
    log_file.close()
#input for rules
prot=int(input("Enter protocol (6 for TCP, 17 for UDP): "))
des_port=int(input("Enter destination port (0-65535): "))
rule_action=input("Enter rule action (allow, deny, log) or 'exit' to quit: ")
exceptions_rule(prot,des_port,rule_action)

def callback(packet):
    raw_data = packet.get_payload()
    #L3
    ip_header = raw_data[:20]
    version_ihl, type_of_service, total_length, identification, flags_fragment, ttl, protocol, header_checksum, src_ip, dest_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version = version_ihl >> 4
    header_length = (version_ihl & 0xF) * 4
    src_ip,dest_ip = socket.inet_ntoa(src_ip),socket.inet_ntoa(dest_ip)
    #L4
    transport_start=header_length
    if protocol == 6:
        tcp_header = raw_data[transport_start:transport_start+20]
        src_port, dest_port = struct.unpack("!HH", tcp_header[:4])
    elif protocol == 17:
        if len(raw_data) >= transport_start+8:
            udp_header = raw_data[transport_start:transport_start+8]
            src_port, dest_port, length, checksum = struct.unpack("!HHHH", udp_header)
        else:
            raise Exception("bruuuuh")
    if (protocol == prot) and (dest_port == des_port):
            if rule_action.lower() == "allow":
                action="packet allowed"
                print("src:{}| | dest:{}| proto:{}| port:{} | Action: --- {}".format(src_ip,dest_ip,protocol,dest_port,action))
                packet.accept()
                log(protocol,dest_port,action)
            elif rule_action.lower() == "deny":
                action="packet denied"
                print("src:{}| | dest:{}| proto:{}| port:{} | Action: --- {}".format(src_ip,dest_ip,protocol,dest_port,action))
                packet.drop()
                log(protocol,dest_port,action)
            
    else:
        action="No matching rule, packet allowed"
        packet.accept()
        log(protocol,dest_port,action)

#QUEUE

queue = NetfilterQueue()
queue.bind(0, callback)
try:
    print("Starting firewall...")
    queue.run()
except KeyboardInterrupt:
    print("Stopping firewall...")
finally:
    queue.unbind()