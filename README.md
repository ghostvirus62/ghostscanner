# GhostVirus™ Port Scanner V1.0

GhostVirus™ Port Scanner is a simple Python script that allows you to scan for open ports on a target IP address using Nmap. It provides a command-line interface for specifying the target IP, port range, and the number of threads to use for parallel scanning.

## Features

- Scan for open ports on a target IP address.
- Specify a range of ports or a single port to scan.
- Configure the number of threads for parallel scanning.
- Displays results in a tabular format.

## Usage

To use the GhostVirus™ Port Scanner, follow these steps:

1. Clone this repository:

```bash
git clone https://github.com/ghostvirus62/ghostscanner.git
```
2. Navigate to the cloned directory:
   
```bash
cd ghostscanner
```

3. Run the script with the following command-line arguments:

```bash
python ghostscan.py <target_ip> <port_range> [<num_threads>]
```

- `<target_ip>`: The IP address of the target system you want to scan.
- `<port_range>`: Specify either a range of ports (e.g., `1-1000`) or a single port number (e.g., `80`).
- `[<num_threads>]` (optional): The number of threads to use for parallel scanning. Default is `1`.

## Example

Scan the target IP address `192.168.1.100` for ports `1-100` using 4 threads:
```bash
python ghostscan.py 192.168.1.100 1-100 4
```


## Dependencies

- Python 3
- nmap module (`pip install python-nmap`)
- tabulate module (`pip install tabulate`)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


