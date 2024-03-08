import tkinter as tk
from tkinter import messagebox, ttk
import socket
from datetime import datetime
import threading

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

        # Scan Type Selection
        self.scan_type = tk.StringVar(value="TCP")  # Default to TCP scan
        self.label_scan_type = tk.Label(self.master, text="Scan Type:")
        self.label_scan_type.pack()

        self.scan_types = ["TCP", "UDP", "SYN", "ICMP"]
        for scan_type in self.scan_types:
            scan_radio = tk.Radiobutton(self.master, text=scan_type, variable=self.scan_type, value=scan_type)
            scan_radio.pack(anchor=tk.W)

        # Scan Button
        self.scan_button = tk.Button(self.master, text="Scan Ports", command=self.start_scanning_thread)
        self.scan_button.pack()

        # Log Area
        self.log_area = tk.Text(self.master, height=15, width=50, state='disabled')
        self.log_area.pack()

        # Security Status Label
        self.security_status_label = tk.Label(self.master, text="Security Status: Unknown", fg="black")
        self.security_status_label.pack()

        # Progress Bar
        self.progress_bar = ttk.Progressbar(self.master, orient="horizontal", mode="determinate", length=200)
        self.progress_bar.pack()

    def log_message(self, msg):
        """Log messages to the log area."""
        self.log_area.config(state='normal')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_area.insert(tk.END, f"{timestamp} - {msg}\n")
        self.log_area.see(tk.END)  # Scroll to the end of text
        self.log_area.config(state='disabled')

    def scan_ports(self, host, port_range, scan_time, scan_type):
        """Scan ports on the target IP address."""
        open_ports = []
        start_port, end_port = map(int, port_range.split('-'))
        total_ports = end_port - start_port + 1

        for port in range(start_port, end_port + 1):
            self.scan_port(host, port, scan_type, open_ports)

            progress = ((port - start_port + 1) / total_ports) * 100
            self.progress_bar['value'] = progress
            self.master.update_idletasks()

            if scan_time and progress >= 100:
                break  # Stop scanning if scan time is specified and reached

        return open_ports

    def scan_port(self, host, port, scan_type, open_ports):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)  # Connection timeout
                if scan_type == "TCP":
                    if s.connect_ex((host, port)) == 0:
                        open_ports.append(port)
                # Add other scan types here
        except socket.error as e:
            self.log_message(f"Error scanning port {port}: {e}")

    def start_scanning_thread(self):
        """Start a new thread for scanning to keep the UI responsive."""
        threading.Thread(target=self.start_scanning, daemon=True).start()

    def start_scanning(self):
        host = self.entry_ip.get().strip()
        port_range = self.entry_port_range.get().strip()
        scan_time = self.entry_scan_time.get().strip()
        scan_type = self.scan_type.get()

        if not host or not port_range or not scan_time.isdigit():
            messagebox.showwarning("Warning", "Please enter valid input for all fields.")
            return

        scan_time = int(scan_time)
        self.log_area.delete('1.0', tk.END)  # Clear previous logs
        self.log_message(f"Port scanning started for: {host}")

        open_ports = self.scan_ports(host, port_range, scan_time, scan_type)

        if open_ports:
            self.log_message("Open ports:")
            for port in open_ports:
                self.log_message(f"Port {port} is open.")
        else:
            self.log_message("No open ports found.")

        # Update Security Status
        self.update_security_status(open_ports)

    def update_security_status(self, open_ports):
        if open_ports:
            self.security_status_label.config(text="Security Status: ATTACK DETECTED", fg="red")
        else:
            self.security_status_label.config(text="Security Status: Safe", fg="green")

root = tk.Tk()
ids = IntrusionDetectionSystem(root)
root.mainloop()
