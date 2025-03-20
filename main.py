import time
from datetime import datetime
from typing import Dict, List
import logging
from pathlib import Path
from scapy.all import sniff, wrpcap, IP, TCP
from scapy.layers.inet import TCP
import threading
import os
import signal
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class EmailTrafficMonitor:
    def __init__(self):
        self.protocols = {
            'SMTP': [25, 587, 465],
            'IMAP': [143, 993],
            'POP3': [110, 995]
        }
        
        # Flatten port list for packet filtering
        self.monitored_ports = [port for ports in self.protocols.values() for port in ports]
        
        # Create captures directory if it doesn't exist
        self.capture_dir = Path('email_captures')
        self.capture_dir.mkdir(exist_ok=True)
        
        # Initialize protocol-specific loggers
        self.loggers = self._setup_loggers()
        
        # Packet buffers for each protocol
        self.packet_buffers = {protocol: [] for protocol in self.protocols.keys()}
        
        # Control flag for the monitoring loop
        self.running = False
        
        # Lock for thread-safe packet handling
        self.buffer_lock = threading.Lock()
        
    def _setup_loggers(self) -> Dict[str, logging.Logger]:
        loggers = {}
        for protocol in self.protocols.keys():
            logger = logging.getLogger(protocol)
            handler = logging.FileHandler(f'email_captures/{protocol.lower()}.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            loggers[protocol] = logger
        return loggers
    
    def _get_protocol_for_port(self, port: int) -> str:
        """Determine the protocol based on the port number."""
        for protocol, ports in self.protocols.items():
            if port in ports:
                return protocol
        return None
    
    def packet_callback(self, packet):
        """Process captured packets."""
        if not packet.haslayer(TCP):
            return
        
        # Check if packet is using email ports
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # Determine if this packet is email related
        email_port = None
        if src_port in self.monitored_ports:
            email_port = src_port
        elif dst_port in self.monitored_ports:
            email_port = dst_port
            
        if email_port:
            protocol = self._get_protocol_for_port(email_port)
            if protocol:
                with self.buffer_lock:
                    self.packet_buffers[protocol].append(packet)
                    self.loggers[protocol].info(
                        f'Captured {protocol} packet: '
                        f'{packet[IP].src}:{packet[TCP].sport} -> '
                        f'{packet[IP].dst}:{packet[TCP].dport}'
                    )
    
    def _save_capture(self, protocol: str, packets: List):
        """Save captured packets to a PCAP file."""
        if not packets:
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'email_captures/email_capture_{protocol.lower()}_{timestamp}.pcap'
        
        try:
            wrpcap(filename, packets)
            self.loggers[protocol].info(f'Saved capture file: {filename}')
            # Clear the buffer after saving
            packets.clear()
        except Exception as e:
            self.loggers[protocol].error(f'Failed to save capture: {str(e)}')
    
    def _save_periodic_captures(self):
        """Periodically save captured packets to files."""
        while self.running:
            with self.buffer_lock:
                for protocol in self.protocols:
                    self._save_capture(protocol, self.packet_buffers[protocol])
            time.sleep(3600)  # Save every hour
    
    def start_monitoring(self):
        """Start the packet capture process."""
        try:
            self.running = True
            
            # Start the periodic save thread
            save_thread = threading.Thread(target=self._save_periodic_captures)
            save_thread.daemon = True
            save_thread.start()
            
            # Create BPF filter for email ports
            port_filter = ' or '.join(f'port {port}' for port in self.monitored_ports)
            
            logging.info(f'Starting packet capture for email protocols...')
            logging.info(f'Monitoring ports: {", ".join(map(str, self.monitored_ports))}')
            
            # Start packet capture
            sniff(
                filter=port_filter,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: not self.running
            )
            
        except Exception as e:
            logging.error(f'Error during monitoring: {str(e)}')
        finally:
            self.running = False
            logging.info('Monitoring stopped')
    
    def stop_monitoring(self):
        """Stop the packet capture process."""
        self.running = False
        # Save any remaining packets
        with self.buffer_lock:
            for protocol in self.protocols:
                self._save_capture(protocol, self.packet_buffers[protocol])

def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown."""
    logging.info('Received shutdown signal')
    if monitor:
        monitor.stop_monitoring()
    sys.exit(0)

if __name__ == '__main__':
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root to capture network packets")
        sys.exit(1)
        
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    print("Starting Email Traffic Monitor...")
    monitor = EmailTrafficMonitor()
    
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("\nMonitoring stopped by user")