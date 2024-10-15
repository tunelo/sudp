# SUDP (Secure User Datagram Protocol)

## Overview

SUDP is a protocol based on UDP that ensures secure communication through encryption and session control between client and server. It includes authentication mechanisms, session management, and encrypted data transmission.

## Header Structure

The header contains key information for managing message transmission between the client and server:

| Field | Type   | Description                            |
|-------|--------|----------------------------------------|
| ver   | uint8  | Protocol version                       |
| kind  | uint8  | Message type                           |
| len   | uint16 | Length of the message                  |
| src   | uint16 | Source identifier                      |
| dst   | uint16 | Destination identifier                 |
| epoch | uint32 | Epoch identifier for DH key exchange   |
| time  | uint64 | Timestamp                              |
| crc32 | uint32 | CRC32 (calculated, not transmitted)     |

> **Note:** The `crc32` field is calculated but not transmitted in the header. It is used in the signed portion of the message body.

## Handshake Structure

The handshake structure is used during the initial negotiation phase to exchange public keys and digital signatures.

| Field     | Type      | Description                          |
|-----------|-----------|--------------------------------------|
| crc32     | uint32    | CRC32 of the handshake message       |
| pubkey    | [65]byte  | DH public key                        |
| signature | [64]byte  | Digital signature of the message     |

- **pubkey:** The Diffie-Hellman public key used for secure key exchange.
- **signature:** A digital signature that authenticates the message.

## Control Message Structure

Control messages are used to manage connection state, including `KeepAlive`, `RTT`, and epoch acknowledgments.

| Field     | Type      | Description                          |
|-----------|-----------|--------------------------------------|
| crc32     | uint32    | CRC32 of the control message         |
| ctrl      | uint32    | Control flags (see below)            |
| data      | uint64    | Additional data                      |
| signature | [64]byte  | Digital signature of the message     |

### Control Flags

The following control flags manage different connection states:

| Flag         | Bit Position | Description                        |
|--------------|--------------|------------------------------------|
| KeepAlive    | 0            | KeepAlive message                  |
| RTT          | 1            | Round Trip Time request            |
| KeepAliveAck | 2            | Acknowledgment for KeepAlive       |
| EpochAck     | 3            | Acknowledgment for epoch change    |

## Message Types

The protocol supports the following message types, defined by the `kind` field in the header:

| Type                | Value | Description                        |
|---------------------|-------|------------------------------------|
| protocolVersion      | 0x2   | Current version of the protocol    |
| typeData             | 0x04  | Encrypted data                     |
| typeCtrlMessage      | 0x03  | Control message                    |
| typeServerHandshake  | 0x02  | Server handshake                   |
| typeClientHandshake  | 0x01  | Client handshake                   |

## Data Structure

Data transmitted through SUDP is encrypted using the **AES-GCM** algorithm to ensure confidentiality and integrity.

| Field | Type   | Description              |
|-------|--------|--------------------------|
| crc32 | uint32 | CRC32 of the data         |
| buff  | []byte | Encrypted data buffer     |

- **buff:** The body of the message, encrypted using **AES-GCM** for secure transmission.

---

## Summary

SUDP is designed for secure and efficient communication in environments where security is critical. It offers authentication through digital signatures, secure key exchange via DH, and encrypted data transmission using AES-GCM. The protocol is aimed at maintaining message integrity and confidentiality over untrusted networks.

### Key Features:
- **Encryption:** Data is encrypted using AES-GCM.
- **Authentication:** Digital signatures and DH public keys ensure message authenticity.
- **Session Control:** Control messages manage the state and synchronization between client and server.
