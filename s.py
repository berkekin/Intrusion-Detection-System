import tkinter as tk
from tkinter import messagebox, ttk
import socket
from datetime import datetime
import threading
import ctypes
import subprocess
import sys

class IntrusionDetectionSystem:
    def __init__(self, master):
        self.master = master
        master.title("Intrusion Detection System")

        # GUI components
        self.create_widgets()

    def create_widgets(self):
        # Target IP Address Label and Entry
        self.label_ip = tk.Label(self.master, text="Target IP Address:")
        self.label_ip.pack()

        self.entry_ip = tk.Entry(self.master)
        self.entry_ip.pack()

        # Port Range Label and Entry
        self.label_port_range = tk.Label(self.master, text="Port Range (e.g., 1-1000):")
        self.label_port_range.pack()

        self.entry_port_range = tk.Entry(self.master)
        self.entry_port_range.pack()

        # Scan Time Label and Entry
        self.label_scan_time = tk.Label(self.master, text="Scan Time (seconds):")
        self.label_scan_time.pack()

        self.entry_scan_time = tk.Entry(self.master)
        self.entry_scan_time.pack()

        # Scan Type Selection (New Feature)
        self.scan_type = tk.StringVar(value="TCP")  # Default to TCP scan
        self.label_scan_type = tk.Label(self.master, text="Scan Type:")
        self.label_scan_type.pack()

        self.scan_types = ["TCP", "UDP", "SYN", "ICMP"]
        for scan_type in self.scan_types:
            scan_radio = tk.Radiobutton(self.master, text=scan_type, variable=self.scan_type, value=scan_type)
            scan_radio.pack(anchor=tk.W)

        # Scan Button
        self.scan_button = tk.Button(self.master, text="Scan Ports", command=self.start_scanning)
        self.scan_button.pack()

        # Log Area
        self.log_area = tk.Text(self.master, height=15, width=50)
        self.log_area.pack()

        # Security Status Label
        self.security_status_label = tk.Label(self.master, text="Security Status:")
        self.security_status_label.pack()

        # Progress Bar
        self.progress_bar = ttk.Progressbar(self.master, orient="horizontal", mode="determinate", length=200)
        self.progress_bar.pack()

    def log_message(self, msg):
        """Log messages to the log area."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_area.insert(tk.END, f"{timestamp} - {msg}\n")
        self.log_area.see(tk.END)  # Scroll to the end of text

    def scan_ports(self, host, port_range, scan_time, scan_type):
        """Scan ports on the target IP address."""
        open_ports = []
        try:
            if not port_range:
                port_range = "1-65535"  # If no port range is specified, scan all ports
            start_port, end_port = map(int, port_range.split('-'))
            total_ports = end_port - start_port + 1

            for port in range(start_port, end_port + 1):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)  # Connection timeout
                    if scan_type == "TCP":
                        s.connect((host, port))
                        open_ports.append(port)
                    elif scan_type == "UDP":
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect((host, port))
                        open_ports.append(port)
                    elif scan_type == "SYN":
                        # Use connect_ex() for SYN scan
                        result = s.connect_ex((host, port))
                        if result == 0:
                            open_ports.append(port)
                    elif scan_type == "ICMP":
                        # Perform ICMP scanning here
                        pass

                progress = ((port - start_port + 1) / total_ports) * 100
                self.progress_bar['value'] = progress
                self.progress_bar.update_idletasks()  # Update progress bar
                self.master.update()  # Update window

                if scan_time and progress >= 100:
                    break  # Stop scanning if scan time is specified and reached

            return open_ports

        except ValueError:
            self.log_message("Invalid port range. Please enter a valid range.")

    def start_scanning(self):
        """Start scanning ports on the target IP address."""
        host = self.entry_ip.get()
        port_range = self.entry_port_range.get()
        scan_time = int(self.entry_scan_time.get()) if self.entry_scan_time.get() else None
        scan_type = self.scan_type.get()

        if not host:
            messagebox.showwarning("Warning", "Please enter the target IP address.")
            return

        self.log_area.delete('1.0', tk.END)  # Clear previous logs
        self.log_message(f"Port scanning started for: {host}")

        open_ports = self.scan_ports(host, port_range, scan_time, scan_type)

        if open_ports:
            self.log_message("Open ports:")
            for port in open_ports:
                self.log_message(f"Port {port} is open.")
        else:
            self.log_message("No open ports found for the specified IP address.")

        # Security Status
        num_open_ports = len(open_ports)
        if num_open_ports > 0:
            self.security_status_label.config(text="Security Status: ATTACK DETECTED", fg="red")
        else:
            self.security_status_label.config(text="Security Status: No attack detected", fg="green")

root = tk.Tk()
ids = IntrusionDetectionSystem(root)
root.mainloop()
