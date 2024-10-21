
# Botnet Saves the World - Assignment 5

## Overview

This project implements a store-and-forward botnet message server with a Command and Control (C&C) client. The goal is to create a decentralized messaging network that can continue functioning during network failures.

## Files
- `client.cpp`: Client-side implementation.
- `server.cpp`: Server-side implementation.
- `server_log.txt`: Log file with all server activities.
- `server_log_old.txt`: Extra log file for when the main one is larger then 5MB.

## How to Compile

You can use the provided `Makefile` to compile both the client and server. To compile the project, run:

```bash
make
```

If you need to clean the previous build files, use:

```bash
make clean
```

This will generate two executable files:  
- `client`: The client executable  
- `tsamgroup1`: The server executable

## How to Run

### Running the Server

To start the server, use the following command:

```bash
./tsamgroup1 <groupnumber> <port> <servers_to_connect_to> <begining_port_for_connected_servers> <ending_port_for_connected_servers>
```
Copy/paste cmd to talk to instruction servers
```bash
./tsamgroup1 1 60000 130.208.246.249 5001 5005
```

### Running the Client

To run the client and connect to the server:

```bash
./client <server_ip> <server_port>
```

Example:

```bash
./client 89.160.229.150 60000
```

## Telnet for Manual Testing

You can also use `telnet` to manually test the server. Here’s how you can do it:

1. **Connect to the server using `telnet`:**

```bash
telnet <server_ip> <server_port>
```

Example:

```bash
telnet 127.0.0.1 60000
```

2. **Send commands** like `HELO` or `LISTSERVERS` directly after connecting. For example:

```bash
HELO,A5_1
```

3. **Close the connection** manually by typing `Ctrl + ]` to return to the telnet prompt, then `quit`.

## Commands

### Client Commands:

*   `HELO`: Register the client.
*   `SENDMSG`: Send a message to another server.
*   `GETMSGS`: Retrieve messages for your group.
*   `LISTSERVERS`: List connected servers.
*   `QUIT`: Disconnect from the server.

### Server Commands:

*   `HELO,<GROUP_ID>`
*   `KEEPALIVE,<No. of Messages>`
*   `SENDMSG,<TO_GROUP_ID>,<FROM_GROUP_ID>,<Message>`
*   `GETMSGS,<GROUP_ID>`
*   `STATUSREQ`: Request server status.

## Logging

The server logs all commands and activities in `server_log.txt`.
The server is able to write upto 5MB into one log file then it uses another log file.

## Extra

We run the server behind a Fortigate with a Geo Blocker, we only allow Iceland
Server is on a Rasp Pi: 89.160.229.150 60000

## Points we are going for

### Section 1
- **1.a [x]** - 4 Points: Code matches all requirements.
- **1.b [x]** - 1 Point: Wireshark was apart of the submission, also submitted in 2.a
- **1.c [x]** - 1 Point: Server connects to a Instructor server
  - Target timestamp: Oct 21, 11:22:58
- **1.d [x]** - 1 Point: Messages received from 2 other groups
  - Target timestamp: Oct 21, 11:24:30
  - Target timestamp: Oct 21, 16:30:12
- **1.e [x]** - 1 Point: Messages sent to 2 other groups
  - Target timestamp: Oct 21, 11:26:58
  - Target timestamp: Oct 21, 13:17:09
- **1.f [x]** - 1 Point: Correct submission type
  - zip file
  - README file
  - Makefile
  - No hidden files
- **1.g [x]** - 1 Point: Logs are readable and show information on the servers behavior

### Section 2 (Max 5 points)
- **2.a [x]** - 1 Point: Wireshark trace of server to client communucations
- **2.b [ ]** - 3 Points: Akureyri groups - Failed
- **2.c [ ]** - 2 Points: Find the emeny, failed. We have a geo blocker to ignore those messages.
- **2.d [x]** - 2 Points: Server runs on a Rasp Pi on 89.160.229.150 60000 remotly, not the TSAM server

TODO:
Wirehsark af client to server með all commands - Skiluðum samt í 2.a
