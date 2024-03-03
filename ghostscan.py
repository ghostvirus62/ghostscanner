import sys
import threading
import nmap
from tabulate import tabulate

def scan_single_port(target_ip, port):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, ports=str(port), arguments='-sV')
        port_info = nm[target_ip]['tcp'][port]
        if port_info['state'] == 'open':
            service = port_info['name']
            version = port_info['product'] + ' ' + port_info['version']
            return port, service, version
    except nmap.PortScannerError as e:
        print(f"Nmap error scanning port {port}: {e}")
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
    return None, None, None 


def port_scan(target_ip, port_range, num_threads):
    try:
        open_ports = []

        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
            if start_port < 0 or end_port < 0 or start_port > end_port or end_port > 65535:
                raise ValueError("Invalid port range")
            open_ports = divide_and_scan(target_ip, num_threads, start_port, end_port)
        else:
            port = int(port_range)
            if port < 0 or port > 65535:
                raise ValueError("Invalid port number")
            result = scan_single_port(target_ip, port)
            if result:
                open_ports.append(result)

        open_ports = [(port, service, version) for port, service, version in open_ports if service and version is not None]

        return open_ports
    except ValueError as e:
        print(f"Error: {e}. Please provide a valid range in the format 'start_port-end_port' or a single port number.")
        return []


def divide_and_scan(target_ip, num_threads, start_port, end_port):
    ports_per_thread = (end_port - start_port + 1) // num_threads
    threads = []
    results = []

    for i in range(num_threads):
        thread_start_port = start_port + (i * ports_per_thread)
        thread_end_port = thread_start_port + ports_per_thread - 1
        if i == num_threads - 1:
            thread_end_port = end_port
        thread = threading.Thread(target=port_scan_thread, args=(target_ip, thread_start_port, thread_end_port, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return results

def port_scan_thread(target_ip, start_port, end_port, results):
    for port in range(start_port, end_port + 1):
        result = scan_single_port(target_ip, port)
        if result: 
            results.append(result)


def main():
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python ghostscan.py <target_ip> <port_range> [<num_threads>]")
        return

    target_ip = sys.argv[1]
    port_range_arg = sys.argv[2]

    try:
        if '-' in port_range_arg:
            start_port, end_port = map(int, port_range_arg.split('-'))
            port_range = f"{start_port}-{end_port}"
            if start_port < 0 or end_port < 0 or start_port > end_port or end_port > 65535:
                raise ValueError("Invalid port range")
        else:
            port_range = port_range_arg
            port = int(port_range)
            if port < 0 or port > 65535:
                raise ValueError("Invalid port number")
    except ValueError as e:
        print(f"Error: {e}. Please provide a valid port range in the format 'start_port-end_port' or a single port number.")
        return

    num_threads = 1 
    if len(sys.argv) == 4:
        try:
            num_threads = int(sys.argv[3])
        except ValueError:
            print("Error: num_threads must be an integer.")
            return
        if num_threads <= 0:
            print("Error: num_threads must be a positive integer.")
            return


    print("\tGhostVirus™ Port Scanner V1.0")

    try:
        open_ports = port_scan(target_ip, port_range, num_threads)
        if not open_ports:
            print("No open ports found.")
        else:
            headers = ["Open Ports", "Service", "Version"]
            data = [(port, service, version) for port, service, version in open_ports]
            print(tabulate(data, headers=headers, tablefmt="grid"))
    except KeyboardInterrupt:
        print("Scan aborted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
