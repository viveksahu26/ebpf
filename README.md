# What is an eBPF ??

- It is technology which allows users to extend the functionality of the Linux kernel without having modify the kernel code itself.
- An eBPF program is a set of eBPF bytecode instructions.

## eBPF History

- eBPF” today has its roots in the **BSD Packet Filter**.
- **Filter** which are **programs** written to determine whether to accept or reject a network
packet.
- Importantly, the author of the filter can write their own custom programs to be executed within the kernel, and this is the heart of what eBPF enables.
- **BPF** came to stand for “Berkeley Packet Filter, it was used in the tcpdump utility as an efficient way **to capture the packets** to be traced out.
- when **seccomp-bpf** was introduced in 2012, this enabled the use of BPF programs to make decisions about whether **to allow or deny user space** applications from making system calls.
- And finally, eBPF provides an environment to run own custom program on any events.

## What is eBPF maps ??

- A map is a data structure that can be accessed from an eBPF program and from user
space.
- Use of Maps:
    Maps can be used to **share data** among multiple eBPF programs or to communicate between a user space application and eBPF code running in the kernel.
    They are all key–value stores

## Write an eBPF program to drop the TCP packets running on port 4040.

- Any packet have 3 componenets: ethernet header, ip headers and tcp headers.
- Get the ethernet headers and it's size must be less than packet size.
- check it's protocol is IP.
  - Else drop the packet.
- Now get the IP headers, and it's size must be less than packet size.
- check it's protocol is TCP.
  - else drop the packet.
- Now get the TCP header and it's size must be less than packet size.
  - extract the destination port. 
  - If the destination port is 4040, then drop the packet.
  - Else pass the packet.

## To run the program

- Clone the repository.
- Run command:
  - `$ go build`
  - `$ sudo ./ebpf`
- Open a terminal(Terminal 1) and run a netcat server:
  - `$ nc -l 4040`
- Open a second terminal(Terminal 2) and send a request to that server as a client.
  - `$ echo hello | nc localhost 4040`
- If "hello" is printed on Terminal1, that means packet is allowed. And if "hello" is not printed, that means packet is dropped.

- To see the tracelog:
  - `$ sudo bpftool prog tracelog`

## To run the program manually.

- First compile the program
  - `sudo clang -O2 -g -Wall -target bpf -c tcppackets.bpf.c -o tcppackets.bpf.o`
- Now load this program in the kernel. We will use `bpftool` for this.
  - `$ sudo bpftool prog load tcppackets.bpf.o /sys/fs/bpf/ping`
- Check whether the program is loaded or not.
  - `$ sudo bpftool prog show name xdp_tcp`
- Now attach the program to xdp hook:
  - `$ sudo bpftool net attach xdp id 1970 dev wlo1`
- Check whether program is attached to wlo1 interface.
  - `$ sudo bpftool net list`
- Open a terminal(Terminal 1) and run a netcat server:
  - `$ nc -l 4040`
- Open a second terminal(Terminal 2) and send a request to that server as a client.
  - `$ echo hello | nc localhost 4040`
- If "hello" is printed on Terminal1, that means packet is allowed. And if "hello" is not printed, that means packet is dropped.
- To see the tracelog:
  - `$ sudo bpftool prog tracelog`
- To detach the program from xdp hook
  - `$ sudo bpftool net detach xdp dev wlo1`
- To remove program or unload program from kernel.
  - `$ sudo rm  /sys/fs/bpf/ping`
