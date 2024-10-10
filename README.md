
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
./tsamgroup1 <port> <servers_to_connect_to> <begining_port_for_connected_servers> <ending_port_for_connected_servers>
```
Copy/paste cmd to talk to instruction servers
```bash
./tsamgroup1 60000 130.208.246.249 5001 5005
```

Example:

```bash
./tsamgroup1 60000
```

### Running the Client

To run the client and connect to the server:

```bash
./client <server_ip> <server_port>
```

Example:

```bash
./client 127.0.0.1 60000
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
