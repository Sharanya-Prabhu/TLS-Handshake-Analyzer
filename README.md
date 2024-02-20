
# TLS Handshake Analyzer

The TLS Handshake Analyzer is a tool designed to provide insights into the TLS (Transport Layer Security) handshaking process. This project aims to reveal the details of TLS handshaking, display exchanged messages between clients and servers, and identify the cipher suites used for data encryption in each TLS session.


## Objectives

The objectives of this project are as follows:
1) To understand the working of TLS handshaking.
2) To show the messages exchanged between the client and the server during TLS handshaking.
3) To identify the cipher suite used for data encryption in all the sessions.

## Methodology

1) The central concept was to receive a packet capture file in JSON format and output TLS handshaking information along with the cipher suites in use in all TLS sessions in the capture.
2) We have captured packets on Wireshark while browsing the internet and exported the captured file as JSON. This generates a sample input file for the program.
3) The program scans the JSON file and creates a new JSON file with numbered TLS records for each TLS packet. This is done to impart uniqueness to the TLS records which would otherwise be overwritten with one another when read into a Python dictionary.
4) The new JSON file is parsed. We identify a packet as a TLS packet if TLS is listed amongst the protocols in frame for the packet. A list named tls_packets consisting of all identified TLS packets is constructed. Each packet’s information is stored in a nested dictionary format. 
5) We iterate through each TLS packet in the tls_packets list to analyze it further. For each packet, we iterate through each of its TLS records. We skip the TLS record if it does not contain any handshaking information.
6) We identify the handshaking message in the TLS record using the tls.handshake.type key located in the dictionary of tls.handshake which is present inside the TLS record.
7) If the handshaking type has a value 1, the TLS record carries the ‘Client Hello’ message. If the value is 2, it carries a ‘Server Hello’ message. Similarly, it carries a message ‘New Session Ticket’ for value 4, ‘Certificate’ for value 11, ‘Server Key Exchange’ for value 12, ‘Server Hello Done’ for value 14 and ‘Client Key Exchange’ for value 16. The message is outputted by the program along with the packet number and TLS record number.
8) If the TLS record carries a ‘Server Hello’ message, we extract the cipher suite used in the current TLS session using tls.handshake.ciphersuite key located in the dictionary of tls.handshake which is present inside the TLS record. This key is a hexadecimal code representing a particular cipher. We have created a csv file with cipher names and their corresponding hexadecimal codes. This csv file is read as a pandas dataframe in our code. We use this dataframe to output the corresponding cipher name from the extracted hexadecimal code. 
9) This way the algorithm outputs the messages exchanged between the server and the client during TLS handshaking and identifies the ciphers used in each TLS session.
