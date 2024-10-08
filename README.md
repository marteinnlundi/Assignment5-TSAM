# Botnet Saves the World - Assignment 5

## Overview

This project implements a store-and-forward botnet message server with a Command and Control (C&C) client. The goal is to create a decentralized messaging network that can continue functioning during network failures.

## Features:
- Peer-to-peer server communication
- Client-server messaging
- Logging of all sent and received commands

## Requirements
- **OS**: Linux or Unix-based environment
- **Language**: C++
- **Compiler**: g++ (C++11 or later)

## Files
- `client.cpp`: Client-side implementation.
- `server.cpp`: Server-side implementation.
- `server_log.txt`: Log file with all server activities.

## Compilation

```bash
g++ client.cpp -o client
g++ server.cpp -o tsamgroup1 -pthread
```

## Running the Server

```bash
./tsamgroup1 <port>
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

