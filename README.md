SENG2250 - Network and Systems Security 
Assignment 3 - Part 2 - Individual

Implemented on 30 Oct, 2022
    
The folder include: 
- AESCBC.java 
- Client.java
- CryptoFunc.java
- DataExchange_Packet.java
- DHE_Key_Confirmation_Packet.java
- DHE_Packet_To_Client.java
- DHE_Packet_To_Server.java
- DiffieHellman.java
- RSA_PublicKeyPacket.java
- Server.java
- ServerSessionID_Packet.java


1. Open a new terminal window, compile all the files above with the following cmd
cmd: javac AESCBC.java Client.java CryptoFunc.java DataExchange_Packet.java DataExchange_Packet.java DHE_Key_Confirmation_Packet.java DHE_Packet_To_Client.java DHE_Packet_To_Server.java DiffieHellman.java RSA_PublicKeyPacket.java Server.java ServerSessionID_Packet.java

2. Run Server with the following cmd
cmd: java Server


3. Open a new terminal window, run Client with the following cmd
cmd: java Client

Example of Server execution
####
Server started

Waiting for a client ...

Client Accepted

Client: Hello

Client: Client's ID is Client564207ff5c22-6

== Proceed to Diffie Hellman Key Exchange ==

-- Proceed to calculate Share Key

== Proceed to Data Exchange ==

-- HMAC verification successfully

Client: Message 1: 67a16dfb0cbd57e16148c141fccaaf651ef8037671f157efe4bf7b4aea513f6e5e1c27bd9e368edf78bf24c2e87c3d47c451cf1a93216545c193c9ce64f9da0d

-- HMAC verification successfully

Client: Message 3: 08eb5625127625ab0cf821040a013a7aaf24f04bb423f381205e9a0f1d7f45fcbb2a0fd20650e52773108b182e1cbf9508b93c4dc59ae307d0f1fc5dd5cfd72c

Data Exchange Completed. Session End.
####

Example of Client execution
####
Connecting ...

Server: Send Server's RSA Public Key

Server's digital signature verified

Server: Server's ID is Server564221e83439-d SessionID is 1497645055771580363611738528470791840063593514723611226011408173674882313812 

== Proceed to Diffie Hellman Key Exchange ==

-- Server's digital signature verified


-- Proceed to calculate Share Key

-- Shared Key Confirmed

== Proceed to Data Exchange ==

-- HMAC verification successfully

Server: Message 2: b4737d63a0fd30027fa38ee9dc1c4d5636a816abbbbdfd42d53f9c23bc0b9eede34ad2e77548c17114ec0a925d1f5e45268e5729fc02164d0d0e7278e12cbafc

-- HMAC verification successfully

Server: Message 4: 5a562c9b2277ea3b143a081394ce196434d1c9a2ed7d332dba1a315fdb1166ce02c3e0bef2ac9131d7248ba2d130aff9668428f3f1db38666e6177c909eb6db8

Data Exchange Completed. Session End.
####

Implemented by Gia Thu Tran
