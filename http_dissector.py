import sys
import os
import re
from scapy.all import *

_GET_BYTESTRING = b"GET"
_HEAD_BYTESTRING = b"HEAD"
_POST_BYTESTRING = b"POST"
_PUT_BYTESTRING = b"PUT"
_DELETE_BYTESTRING = b"DELETE"
_CONNECT_BYTESTRING = b"CONNECT"
_OPTIONS_BYTESTRING = b"OPTIONS"
_TRACE_BYTESTRING = b"TRACE"

_OK_BYTESTRING = b"200 OK"

_REGEX_FILENAME = b'\/([^/]+) HTTP'
_REGEX_RESPONSE_DATA = b'\\r\\n\\r\\n((.|\\n)*)'

_DEBUG = False
_ACCEPT_FILES_WITHOUT_EXTENSION = False


class HTTPFile:
    def __init__(self, name):
        self.name = name
        self.original_name = name.decode()
        self.data = b''
        self.next_seq = 0
        self.response = False
        self.post = False

    def save_file(self):
        try:
            with open(self.name, "wb") as binary_file:
                binary_file.write(self.data)
        except FileExistsError:
            print(f"[!] Write Error: file {self.name} already exists.")
        except PermissionError:
            print(f"[!] Write Error: no permission to write {self.name} to current directory.")

    def update_next_seq(self, rcv_packet):
        self.next_seq = rcv_packet.seq + len(rcv_packet.load)

    def update_name(self, new_name):
        self.name = new_name

    def __repr__(self):
        return f"Name: {self.name}\nData: {self.data}"


def ask_save_file(httpfile):
    suitable_filename(httpfile)
    if httpfile.name != httpfile.original_name:
        inp = input(f"[*] Save {httpfile.name} (original file name: {httpfile.original_name})? [Yes - Y/y, No - N/n]")
    else:
        inp = input(f"[*] Save {httpfile.name} ? [Yes - Y/y, No - N/n]")
    if inp.lower() == "y":
        print(f"\t[*] Writing {httpfile.name}...\n")
        httpfile.save_file()
    else:
        print(f"\t[*] Skipping {httpfile.name}\n")


def suitable_filename(httpfile):
    httpfile.update_name(httpfile.name.decode())
    name = httpfile.name
    i = 2
    extension_index = name.rfind(".")
    temp = name
    if extension_index == -1:
        while os.path.isfile(temp):
            temp = name+"(" + str(i) + ")"
            i += 1
    else:
        while os.path.isfile(temp):
            temp = name[:extension_index]+"("+str(i)+")"+name[extension_index:]
            i += 1

    httpfile.update_name(temp)


def packet_classificator(rcv_packet):
    if rcv_packet.haslayer("TCP"):
        if rcv_packet.haslayer("Raw"):
            load = rcv_packet.load
            if load.find(_GET_BYTESTRING) == 0 or load.find(_HEAD_BYTESTRING) == 0:
                # packet with response
                return 0
            elif load.find(_OK_BYTESTRING) == 9:
                # response to the GET
                return 1
            elif load.find(_POST_BYTESTRING) == 0:
                # other http packet
                return 3
            else:
                # data packet
                return 2
        else:
            return -1
    else:
        return -1


def process_request(rcv_packet):
    filename = re.search(_REGEX_FILENAME, rcv_packet.load)
    if filename is None:
        if _ACCEPT_FILES_WITHOUT_EXTENSION:
            filename = b"no_name.html"
            file = HTTPFile(filename)
            file.original_name = "/"
        else:
            return None
    else:
        filename = filename.group(1)
        if _ACCEPT_FILES_WITHOUT_EXTENSION:
            file = HTTPFile(filename)
        else:
            if filename.find(b".") == -1:
                return None
            else:
                file = HTTPFile(filename)

    file.next_seq = rcv_packet.ack
    return file


def process_response(rcv_packet, file_list):
    for file in file_list:
        if not file.response and file.next_seq == rcv_packet.seq:
            temp = re.search(_REGEX_RESPONSE_DATA, rcv_packet.load)
            if temp is None:
                temp = b""
            else:
                temp = temp.group(1)
            file.data += temp
            file.update_next_seq(rcv_packet)
            file.response = True
            break


def process_data(rcv_packet, file_list):
    index = find_index(file_list, rcv_packet)
    if index != -1:
        file_list[index].update_next_seq(rcv_packet)
        file_list[index].data += rcv_packet.load


def find_index(file_list, rcv_packet):
    i = 0
    for file in file_list:
        if file.post:
            if file.next_seq == rcv_packet.ack:
                return i
        else:
            if file.next_seq == rcv_packet.seq:
                return i
        i += 1
    return -1


def process_post(rcv_packet):
    filename = re.search(_REGEX_FILENAME, rcv_packet.load)
    if filename is None:
        if _ACCEPT_FILES_WITHOUT_EXTENSION:
            filename = b"no_name"
            file = HTTPFile(filename)
            file.original_name = "/"
        else:
            return None
    else:
        filename = filename.group(1)
        if _ACCEPT_FILES_WITHOUT_EXTENSION:
            file = HTTPFile(filename)
        else:
            if filename.find(b".") == -1:
                return None
            else:
                file = HTTPFile(filename)

    file.response = True
    file.post = True

    temp = re.search(_REGEX_RESPONSE_DATA, rcv_packet.load)
    if temp is None:
        temp = b""
    else:
        temp = temp.group(1)

    file.data += temp
    file.next_seq = rcv_packet.ack

    return file


def show_packet(rcv_packet, i, packet_type):
    print(f"[{i}]{rcv_packet}")
    print(f"[*] Packet type: {packet_type}")
    input()


def dissector(pcap_path):
    try:
        packets = rdpcap(pcap_path)
    except:
        print(f"[!] Error opening {pcap_path}")
        print(f"[!] Exiting...")
        return

    file_list = []
    i = 0

    print(f"[*] Dissecting {pcap_path}")

    for rcv_packet in packets:
        packet_type = packet_classificator(rcv_packet)

        if _DEBUG:
            show_packet(rcv_packet, i, packet_type)
            i += 1

        if packet_type == 0:
            file = process_request(rcv_packet)
            if file is not None:
                file_list.append(file)

        elif packet_type == 1:
            process_response(rcv_packet, file_list)

        elif packet_type == 2:
            process_data(rcv_packet, file_list)

        elif packet_type == 3:
            file = process_post(rcv_packet)
            if file is not None:
                file_list.append(file)

    for file in file_list:
        ask_save_file(file)


def main():
    n = len(sys.argv)
    pcap_path = None
    global _DEBUG
    global _ACCEPT_FILES_WITHOUT_EXTENSION

    # Input handling
    for i in range(n):
        if sys.argv[i] == "-D":
            _DEBUG = True
            print(f"[*] Debug mode active ( _DEBUG {_DEBUG} )")

        if sys.argv[i] == "-E":
            _ACCEPT_FILES_WITHOUT_EXTENSION = True
            print(f"[*] Accepting files without extension")

        if sys.argv[i] == "-r":
            try:
                pcap_path = sys.argv[i+1]
            except:
                print("[!] pcap file should be provided after -r flag")
                print("[!] Exiting...")
                return

    if pcap_path is None:
        print("[!] pcap file should be provided after -r flag")
        print("[!] Exiting...")
        return
    else:
        try:
            open(pcap_path, "r")
        except FileNotFoundError:
            print(f"[!] File \"{pcap_path}\" not found")
            print("[!] Exiting...")
            return

        dissector(pcap_path)


if __name__ == "__main__":
    main()
