# Botnet Saves the World - Assignment 5

## Overview

This project implements a store-and-forward botnet message server with a Command and Control (C&C) client. The goal is to create a decentralized messaging network that can continue functioning during network failures.

## Features:
- Peer-to-peer server communication
- Client-server messaging
- Logging of all sent, received commands and client information
- Blocks repeated unknown attempts

## Requirements
- **OS**: Linux or Unix-based environment
- **Language**: C++
- **Compiler**: g++ (C++11 or later)

## Files
- `client.cpp`: Client-side implementation.
- `server.cpp`: Server-side implementation.
- `server_log.txt`: Log file with all server activities.
- `server_log_old.txt`: Extra log file for when the main one is larger then 5MB.

## Compilation

```bash
g++ client.cpp -o client
g++ server.cpp -o tsamgroup1 -pthread
```

## Running the Server

```bash
./tsamgroup1 <port> <servers_to_connect_to> <begining_port_for_connected_servers> <ending_port_for_connected_servers>
```
Copy/paste cmd to talk to instruction servers
```bash
./tsamgroup1 60000 130.208.246.249 5001 5005
```

## Running the Client

```bash
./client <server_ip> <server_port>
```

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
