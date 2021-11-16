# SM2_Synergism_Algorithm

Create in 2021 / 11 / 16

## 1、Instruction

SM2协同计算算法

关键点：

- 协同签名的过程
- 协同解密的过程

设计难点：

- 如何实现参与签名或解密的双方进行安全的数据传输

目前设计的方案：

- 用一个自定义的结构体存放socket, socketAddr, ip_server, port_server,以及privateKey等数据
