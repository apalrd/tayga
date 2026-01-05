import socket
import threading
import os
import time


class LoadTester:
    def __init__(self, port=0, chunk_size=65536):
        self.port = port
        self.chunk_size = chunk_size
        self.server_socket = None
        self.client_socket = None
        self.server_addr = "::"
        self.client_addr = None
        self.bytes_exchanged = 0
        self.running = False
    
    def start_server(self):
        """Start the listening socket."""
        self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.server_addr, self.port))
        self.server_socket.listen(1)
        print(f"Server listening on {self.server_addr}:{self.port}")
    
    def _handle_connection(self):
        """Handle incoming connection and exchange data."""
        try:
            conn, addr = self.server_socket.accept()
            print(f"Connection accepted from {addr}")
            
            while self.running:
                data = os.urandom(self.chunk_size)
                try:
                    conn.sendall(data)
                    self.bytes_exchanged += len(data)
                except (BrokenPipeError, ConnectionResetError):
                    break
            
            conn.close()
        except Exception as e:
            print(f"Server handler error: {e}")
    
    def _dial_and_exchange(self):
        """Connect to server and exchange data."""
        try:
            time.sleep(0.1)  # Give server time to start
            self.client_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            self.client_socket.connect((self.client_addr,self.port,0,0))
            print(f"Connected to server at {self.client_addr}:{self.port}")
            
            while self.running:
                try:
                    data = self.client_socket.recv(self.chunk_size)
                    if not data:
                        break
                    if self.running: self.bytes_exchanged += len(data)
                except (ConnectionResetError, ConnectionAbortedError):
                    break
            
            self.client_socket.close()
        except Exception as e:
            print(f"Client error: {e}")
    
    def run(self):
        self.running = True
        self.start_server()
        
        # Start server handler thread
        self.server_thread = threading.Thread(target=self._handle_connection, daemon=True)
        self.server_thread.start()
        
        # Start client thread
        self.client_thread = threading.Thread(target=self._dial_and_exchange, daemon=True)
        self.client_thread.start()
        self.start_time = time.time()

    def stop(self):
        self.running = False
        self.server_thread.join(timeout=1)
        self.client_thread.join(timeout=1)
        
        elapsed = time.time() - self.start_time
        throughput_mbps = (self.bytes_exchanged * 8) / (elapsed * 1e6)
        print(f"Exchanged {self.bytes_exchanged} bytes in {elapsed:.2f}s ({throughput_mbps:.2f} Mbps)")


if __name__ == "__main__":
    tester = LoadTester(port=5555)
    tester.server_addr = "::ffff:198.18.0.1"
    tester.client_addr = "64:ff9b::198.18.0.1"
    tester.run()
    time.sleep(10)
    tester.stop()
