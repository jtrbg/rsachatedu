# rsachatedu

`rsachatedu` is an educational toolkit designed to demonstrate the importance and application of RSA encryption in secure communications. This repository includes a server, client, and network sniffer to illustrate secure data transmission and interception in networked environments.

## Setup

To test the project effectively, if you don't have access to three separate computers, you can set up three virtual machines with minimal system requirements. Configure each VM's network to use your standard WiFi adapter. For environments where network sniffing is restricted, use an internal network setup.

### Installation Steps

1. Install necessary libraries on each VM:
   ```
   sudo apt update
   sudo apt install python3-openssl python3-cryptography
   ```

3. Clone the repository to each machine:
   ```
   git clone https://github.com/jtrbg/rsachatedu
   ```

5. Configure the network on the VM designated for sniffing to promiscuous mode:
   ```
   ip link set [interface] promisc on
   ```
   Replace `[interface]` with your desired network interface. To list all interfaces, use:
   ```
   ip link show
   ```

7. Obtain the IP addresses of each VM for network configuration.

## Usage

Run the server, client, and sniffer scripts on their respective VMs:

- **Server (`longbow.py`):**
  ```
  python3 longbow.py
  ```

- **Client (`crecy.py`):**
  You will need to specify the server's IP address when prompted. This is the IP of the VM running `longbow.py`.
  ```
  python3 crecy.py
  ```

- **Sniffer (`mantlet.py`):**
  ```
  python3 mantlet.py
  ```

Follow the on-screen instructions to initiate and observe encrypted communications between the server and client, while the sniffer monitors the network traffic for educational analysis.
