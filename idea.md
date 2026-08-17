peer to peer file transfer
Session Rendevouz Utilities for NAT (SRUN) server to exchange IPs and PORTs
maybe a STUN server along side, because corporate networks may have simetric NAT/Firewall


client:
- check STUN for its IP:PORT
- if sending
-   create Rendevouz ID and publish its IP:PORT
- if receiving
-   uses Rendevouz ID and publish its IP:PORT
- get the others IP:PORT and start connecting througth NAT Traversal
- FILESYSTEM THREAD:
-   reads/writes the sending/receiving file
- NETWORK THREAD:
-   receive/send packets, healthcheck, acks, mantain throughput, etc
-   maybe two threads, one for recv and one for sending.
- communicate through ring buffer

STUN/SRUN server:
- two udp server
- two threads
-   A. STUN
-   B. SRUN
