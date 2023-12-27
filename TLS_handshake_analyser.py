#read wireshark JSON file

import sys
import os
import re
import time
import pandas as pd
import json

orig_filename = "demo.json"
out_filename = "tls_inter.json"

tls_versions={
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303" : "TLS 1.2"
}

arr = []


def replace_name():
    tls_rec_counter=1
    tls_record = '\"tls.record\"'
    f = open(out_filename,"w")
    with open(orig_filename) as temp_f:
        datafile = temp_f.readlines()
    for line in datafile:
        if '\"_index\"' in line:
            tls_rec_counter=1
        if tls_record in line:
            hold = "\"tls.record"+str(tls_rec_counter)+"\""
            tls_rec_counter+=1
            line = line.replace(tls_record,hold)
        f.write(line)
        
    return 


def gettlsrecords(filename):
    #read json file packet by packet
    with open(filename, "r") as f:
        data = json.load(f)
        # print(len(data))
        tls_packets = []
        for i, packet in enumerate(data):
            if 'tls' in packet['_source']['layers']['frame']['frame.protocols']:
                tls_packets.append(packet)
                arr.append(i+1)
        return tls_packets


def analyze_handshakes(tls_packets):

    for packnum,packet in enumerate(tls_packets):
       
        for tls_rec in range(len(packet['_source']['layers']['tls'])):

            tls_record_num = 'tls.record'+ str(tls_rec +1)

            if( packet['_source']['layers']['tls'].get(tls_record_num,-1) == -1 or
                packet['_source']['layers']['tls'][tls_record_num].get('tls.handshake',-1) == -1 or 
                isinstance(packet['_source']['layers']['tls'][tls_record_num]['tls.handshake'], str)) :
                continue

            handshake_type = packet['_source']['layers']['tls'][tls_record_num]['tls.handshake']['tls.handshake.type']
            pack_tls_detail = "Packet "+str(arr[packnum])+" - TLS record "+ str(tls_rec +1)

            if( handshake_type == '1'):
                print( pack_tls_detail + " - Client Hello \n")

            elif(handshake_type == '2'):

                print( pack_tls_detail+ " - Server Hello\n\nTLS Version:  " + 
                       tls_versions[packet['_source']['layers']['tls'][tls_record_num]['tls.handshake']['tls.handshake.version']])

                print("Cipher Suite: ",end ="")
                cipher = packet['_source']['layers']['tls'][tls_record_num]['tls.handshake']['tls.handshake.ciphersuite']     
                df = pd.read_csv('ciphers.csv', header=None)
                print(df[df[0]==cipher][1].to_string(index=False))
                print()

            elif( handshake_type == '4' ):
                print(pack_tls_detail + " - New Session Ticket \n")

            elif( handshake_type == '11' ):
                print(pack_tls_detail + " - Certificate \n")
            
            elif( handshake_type == '12' ):
                print(pack_tls_detail + " - Server Key Exchange \n")

            elif( handshake_type == '14' ):
                print(pack_tls_detail + " - Server Hello Done \n")

            elif( handshake_type == '16' ):
                print(pack_tls_detail + " - Client Key Exchange \n")
        
    return


def main():
    print("         TLS HANDSHAKE ANALYZER")
    print("*----------------------------------------*")
    replace_name()
    tls_packets = gettlsrecords(out_filename)
    analyze_handshakes(tls_packets)
  
  
if __name__ == "__main__":
    main()
