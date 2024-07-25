<h1>Packet Sniffer and parser using raw sockets</h1>

![](https://github.com/user-attachments/assets/16effe3f-264e-42d2-9460-7b5d6af64b90)


A simple network packet sniffer written in C that captures and analyzes packets. This tool uses raw sockets to intercept and display detailed information about Ethernet, IP, TCP, and UDP headers along with the packet payload in hexadecimal and ASCII formats.


## Features

- Captures packets on a specified network interface.
- Displays Ethernet, IP, TCP, and UDP header information.
- Prints packet payload in hexadecimal and ASCII formats.
- Provides timestamps for captured packets.
- It uses the Berkeley Packet Filter (BPF) to filter and capture specific types of packets.
    - For more information refer to this: https://www.kernel.org/doc/html/v5.12/networking/filter.html

![](https://github.com/user-attachments/assets/befa6b55-12c8-4a9c-a0ef-5be785ee5b8a)

## Note

- Ensure you have the necessary permissions to run the program (typically requires sudo access).
- Modify the network interface (default is wlan0) in the code to match your setup.
    - ![](https://github.com/user-attachments/assets/5e9cf504-82a5-4668-bb84-bc80abfdce5d)

- This tool currently supports only IPv4 packets without options.

## Getting Started

1. Clone the repository

```bash

git clone https://github.com/ImonChakraborty/pack-sniffer.git
```
```bash

cd pack-sniffer
```

2. Compile the code

```bash

gcc -o pack_sniffer pack_sniffer.c

```

3. Run the packet sniffer (requires root privileges):

```bash

sudo ./pack_sniffer

```

## License

- This project is licensed under the GPL-3.0 License - see the LICENSE file for details.
<br>
<p align=center> Thank you </p>
