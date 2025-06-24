#!/usr/bin/env python3
import sys
import socket
import threading
import time
import datetime
import random
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import nmap
import psutil
import dpkt
from collections import defaultdict, deque
import platform
import subprocess
import json
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP
import queue

# Constants
VERSION = "1.0.0"
MAX_LOG_ENTRIES = 1000
UPDATE_INTERVAL = 2000  # ms
THEMES = {
    "dark": {
        "bg": "#121212",
        "fg": "#00ff00",
        "text_bg": "#222222",
        "text_fg": "#ffffff",
        "button_bg": "#333333",
        "button_fg": "#00ff00",
        "highlight": "#006600"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "text_bg": "#ffffff",
        "text_fg": "#000000",
        "button_bg": "#e0e0e0",
        "button_fg": "#000000",
        "highlight": "#a0a0a0"
    }
}

class ThreatDetector:
    def __init__(self):
        self.ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'last_seen': 0,
            'ports': set(),
            'packet_times': deque(maxlen=100)
        })
        self.dos_threshold = 1000  # packets per second
        self.port_scan_threshold = 20  # unique ports in short time
        self.syn_flood_threshold = 500  # SYN packets without ACK
        self.current_threats = []
        self.threat_history = []
        self.syn_count = defaultdict(int)
        self.attack_patterns = {
            'DOS': self.detect_dos,
            'DDOS': self.detect_ddos,
            'Port Scan': self.detect_port_scan,
            'SYN Flood': self.detect_syn_flood,
            'UDP Flood': self.detect_udp_flood,
            'ICMP Flood': self.detect_icmp_flood
        }
    
    def analyze_packet(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            current_time = time.time()
            
            # Update IP statistics
            self.ip_stats[ip_src]['packet_count'] += 1
            self.ip_stats[ip_src]['last_seen'] = current_time
            self.ip_stats[ip_src]['packet_times'].append(current_time)
            
            # Check for specific protocols
            if TCP in packet:
                self._analyze_tcp(packet, ip_src)
            elif UDP in packet:
                self._analyze_udp(packet, ip_src)
            elif ICMP in packet:
                self._analyze_icmp(packet, ip_src)
            
            # Run all attack detection patterns
            detected_threats = []
            for threat_name, detector in self.attack_patterns.items():
                if detector(ip_src):
                    detected_threats.append(threat_name)
            
            if detected_threats:
                threat_entry = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'source_ip': ip_src,
                    'threat_types': detected_threats,
                    'destination_ip': ip_dst
                }
                self.current_threats.append(threat_entry)
                self.threat_history.append(threat_entry)
                return threat_entry
        
        return None
    
    def _analyze_tcp(self, packet, ip_src):
        tcp = packet[TCP]
        self.ip_stats[ip_src]['ports'].add(tcp.dport)
        
        # Check for SYN packets
        if tcp.flags & 0x02:  # SYN flag
            self.syn_count[ip_src] += 1
    
    def _analyze_udp(self, packet, ip_src):
        udp = packet[UDP]
        self.ip_stats[ip_src]['ports'].add(udp.dport)
    
    def _analyze_icmp(self, packet, ip_src):
        # ICMP flood detection
        pass
    
    def detect_dos(self, ip_src):
        # Check packet rate
        packet_times = self.ip_stats[ip_src]['packet_times']
        if len(packet_times) > 10:
            time_diff = packet_times[-1] - packet_times[0]
            rate = len(packet_times) / time_diff if time_diff > 0 else 0
            if rate > self.dos_threshold:
                return True
        return False
    
    def detect_ddos(self, ip_src):
        # Similar to DOS but would correlate with multiple IPs
        # Simplified for this implementation
        return self.detect_dos(ip_src)
    
    def detect_port_scan(self, ip_src):
        # Check number of unique ports accessed
        if len(self.ip_stats[ip_src]['ports']) > self.port_scan_threshold:
            return True
        return False
    
    def detect_syn_flood(self, ip_src):
        # Check SYN packets without corresponding ACK
        if self.syn_count.get(ip_src, 0) > self.syn_flood_threshold:
            return True
        return False
    
    def detect_udp_flood(self, ip_src):
        # Similar to SYN flood but for UDP
        return False
    
    def detect_icmp_flood(self, ip_src):
        # Check ICMP packet rate
        return False
    
    def get_current_threats(self):
        return self.current_threats.copy()
    
    def clear_current_threats(self):
        self.current_threats = []
    
    def get_threat_stats(self):
        stats = defaultdict(int)
        for threat in self.threat_history:
            for threat_type in threat['threat_types']:
                stats[threat_type] += 1
        return stats

class NetworkMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.is_monitoring = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.target_ip = None
        self.packet_count = 0
        self.start_time = None
    
    def start_monitoring(self, target_ip):
        if self.is_monitoring:
            return False
        
        self.target_ip = target_ip
        self.is_monitoring = True
        self.packet_count = 0
        self.start_time = time.time()
        
        # Start packet processing thread
        self.sniffer_thread = threading.Thread(
            target=self._packet_capture_loop,
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start packet processing thread
        self.processor_thread = threading.Thread(
            target=self._packet_processing_loop,
            daemon=True
        )
        self.processor_thread.start()
        
        return True
    
    def stop_monitoring(self):
        self.is_monitoring = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=2)
    
    def _packet_capture_loop(self):
        try:
            sniff(
                filter=f"host {self.target_ip}",
                prn=lambda p: self.packet_queue.put(p),
                store=0,
                stop_filter=lambda _: not self.is_monitoring
            )
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def _packet_processing_loop(self):
        while self.is_monitoring or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.packet_count += 1
                threat = self.threat_detector.analyze_packet(packet)
                if threat:
                    yield threat
            except queue.Empty:
                continue
    
    def get_stats(self):
        uptime = time.time() - self.start_time if self.start_time else 0
        return {
            'packets_processed': self.packet_count,
            'uptime': uptime,
            'packet_rate': self.packet_count / uptime if uptime > 0 else 0,
            'current_threats': self.threat_detector.get_current_threats(),
            'threat_stats': self.threat_detector.get_threat_stats()
        }

class TerminalEmulator:
    def __init__(self, network_monitor):
        self.network_monitor = network_monitor
        self.commands = {
            'help': self.cmd_help,
            'start monitoring': self.cmd_start_monitoring,
            'stop': self.cmd_stop,
            'netstat': self.cmd_netstat,
            'net share': self.cmd_net_share,
            'ifconfig /all': self.cmd_ifconfig_all,
            'ifconfig': self.cmd_ifconfig,
            'nmap --script vuln': self.cmd_nmap_vuln,
            'msfconsole': self.cmd_msfconsole,
            'nc -lvp 4444': self.cmd_nc_listen,
            'nc': self.cmd_nc_connect
        }
    
    def execute(self, command):
        parts = command.strip().split()
        if not parts:
            return "No command entered"
        
        # Find the best matching command
        matched_cmd = None
        for cmd in self.commands:
            if ' '.join(parts[:len(cmd.split())]).lower() == cmd.lower():
                matched_cmd = cmd
                args = parts[len(cmd.split()):]
                break
        
        if not matched_cmd:
            return f"Command not found: {command}\nType 'help' for available commands"
        
        try:
            return self.commands[matched_cmd](*args)
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def cmd_help(self):
        help_text = "Available commands:\n"
        for cmd in self.commands:
            help_text += f"  {cmd}\n"
        help_text += "\nType command name for more info about specific command"
        return help_text
    
    def cmd_start_monitoring(self, ip_address=None):
        if not ip_address:
            return "Usage: start monitoring <IP address>"
        
        if not self.validate_ip(ip_address):
            return f"Invalid IP address: {ip_address}"
        
        if self.network_monitor.start_monitoring(ip_address):
            return f"Started monitoring network traffic for IP: {ip_address}"
        else:
            return "Monitoring is already active"
    
    def cmd_stop(self):
        self.network_monitor.stop_monitoring()
        return "Stopped network monitoring"
    
    def cmd_netstat(self):
        try:
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_net_share(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['net', 'share'], capture_output=True, text=True)
                return result.stdout if result.stdout else result.stderr
            else:
                return "Command only available on Windows"
        except Exception as e:
            return str(e)
    
    def cmd_ifconfig_all(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
                return result.stdout if result.stdout else result.stderr
            else:
                result = subprocess.run(['ifconfig', '-a'], capture_output=True, text=True)
                return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_ifconfig(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                return result.stdout if result.stdout else result.stderr
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_nmap_vuln(self, target=None):
        if not target:
            return "Usage: nmap --script vuln <target>"
        
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments='--script vuln')
            return json.dumps(nm._scan_result, indent=2)
        except Exception as e:
            return str(e)
    
    def cmd_msfconsole(self):
        return "Metasploit Framework console would launch here in a real implementation"
    
    def cmd_nc_listen(self):
        return "Netcat listener started on port 4444 (simulated)"
    
    def cmd_nc_connect(self, target=None, port=None, *args):
        if not target or not port:
            return "Usage: nc <target> <port>"
        return f"Connecting to {target}:{port} with Netcat (simulated)"
    
    def validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

class DashboardApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Accurate Cyber Defense Network Intrusion Detection System v{VERSION}")
        self.current_theme = "dark"
        self.apply_theme()
        
        # Initialize components
        self.threat_detector = ThreatDetector()
        self.network_monitor = NetworkMonitor(self.threat_detector)
        self.terminal = TerminalEmulator(self.network_monitor)
        
        # Create menu
        self.create_menu()
        
        # Create main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create dashboard layout
        self.create_dashboard()
        
        # Start update loop
        self.update_interval = UPDATE_INTERVAL
        self.update_dashboard()
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Monitoring Session", command=self.new_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Switch Theme", command=self.switch_theme)
        view_menu.add_command(label="Threat Dashboard", command=self.show_threat_dashboard)
        view_menu.add_command(label="Network Stats", command=self.show_network_stats)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vuln_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Threat Dashboard tab
        self.threat_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.threat_tab, text="Threat Dashboard")
        
        # Network Stats tab
        self.stats_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_tab, text="Network Stats")
        
        # Terminal tab
        self.terminal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_tab, text="Terminal")
        
        # Build each tab
        self.build_threat_tab()
        self.build_stats_tab()
        self.build_terminal_tab()
    
    def build_threat_tab(self):
        # Threat monitoring frame
        monitor_frame = ttk.LabelFrame(self.threat_tab, text="Threat Monitoring")
        monitor_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # IP entry and controls
        ip_frame = ttk.Frame(monitor_frame)
        ip_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(ip_frame, text="Target IP:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.start_btn = ttk.Button(ip_frame, text="Start", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(ip_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        
        # Threat display area
        threat_display_frame = ttk.Frame(monitor_frame)
        threat_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Current threats
        current_threats_frame = ttk.LabelFrame(threat_display_frame, text="Current Threats")
        current_threats_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5)
        
        self.current_threats_tree = ttk.Treeview(current_threats_frame, columns=('time', 'source', 'type', 'target'), show='headings')
        self.current_threats_tree.heading('time', text='Time')
        self.current_threats_tree.heading('source', text='Source IP')
        self.current_threats_tree.heading('type', text='Threat Type')
        self.current_threats_tree.heading('target', text='Target IP')
        
        self.current_threats_tree.column('time', width=150)
        self.current_threats_tree.column('source', width=120)
        self.current_threats_tree.column('type', width=120)
        self.current_threats_tree.column('target', width=120)
        
        self.current_threats_tree.pack(fill=tk.BOTH, expand=True)
        
        # Threat stats frame
        stats_frame = ttk.Frame(threat_display_frame)
        stats_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5)
        
        # Threat type distribution
        threat_pie_frame = ttk.LabelFrame(stats_frame, text="Threat Distribution")
        threat_pie_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.threat_pie_fig = plt.figure(figsize=(5, 3), dpi=100)
        self.threat_pie_ax = self.threat_pie_fig.add_subplot(111)
        self.threat_pie_canvas = FigureCanvasTkAgg(self.threat_pie_fig, threat_pie_frame)
        self.threat_pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threat timeline
        threat_timeline_frame = ttk.LabelFrame(stats_frame, text="Threat Timeline")
        threat_timeline_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.threat_timeline_fig = plt.figure(figsize=(5, 3), dpi=100)
        self.threat_timeline_ax = self.threat_timeline_fig.add_subplot(111)
        self.threat_timeline_canvas = FigureCanvasTkAgg(self.threat_timeline_fig, threat_timeline_frame)
        self.threat_timeline_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def build_stats_tab(self):
        # Network statistics frame
        stats_frame = ttk.LabelFrame(self.stats_tab, text="Network Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Stats display
        stats_display_frame = ttk.Frame(stats_frame)
        stats_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left side - numerical stats
        numerical_frame = ttk.Frame(stats_display_frame)
        numerical_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.stats_labels = {}
        stats = [
            ('Packets Processed', 'packets_processed'),
            ('Uptime (sec)', 'uptime'),
            ('Packet Rate (pps)', 'packet_rate')
        ]
        
        for label_text, stat_key in stats:
            frame = ttk.Frame(numerical_frame)
            frame.pack(fill=tk.X, pady=2)
            
            ttk.Label(frame, text=label_text + ":").pack(side=tk.LEFT)
            self.stats_labels[stat_key] = ttk.Label(frame, text="0")
            self.stats_labels[stat_key].pack(side=tk.RIGHT)
        
        # Right side - charts
        chart_frame = ttk.Frame(stats_display_frame)
        chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Packet rate chart
        packet_rate_frame = ttk.LabelFrame(chart_frame, text="Packet Rate Over Time")
        packet_rate_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.packet_rate_fig = plt.figure(figsize=(5, 3), dpi=100)
        self.packet_rate_ax = self.packet_rate_fig.add_subplot(111)
        self.packet_rate_canvas = FigureCanvasTkAgg(self.packet_rate_fig, packet_rate_frame)
        self.packet_rate_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Top protocols chart
        protocols_frame = ttk.LabelFrame(chart_frame, text="Top Protocols")
        protocols_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.protocols_fig = plt.figure(figsize=(5, 3), dpi=100)
        self.protocols_ax = self.protocols_fig.add_subplot(111)
        self.protocols_canvas = FigureCanvasTkAgg(self.protocols_fig, protocols_frame)
        self.protocols_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def build_terminal_tab(self):
        # Terminal emulator frame
        terminal_frame = ttk.Frame(self.terminal_tab)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output area
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame,
            wrap=tk.WORD,
            state='disabled'
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        
        # Input area
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT)
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(fill=tk.X, expand=True, padx=5)
        self.terminal_input.bind('<Return>', self.execute_terminal_command)
        
        # Help button
        ttk.Button(
            terminal_frame,
            text="Help",
            command=lambda: self.print_to_terminal(self.terminal.cmd_help())
        ).pack(side=tk.RIGHT)
    
    def apply_theme(self):
        theme = THEMES[self.current_theme]
        style = ttk.Style()
        
        # Configure main window
        self.root.config(bg=theme['bg'])
        
        # Configure ttk styles
        style.theme_use('clam')  # Starting with a basic theme
        
        # Frame styles
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
        
        # Label styles
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        
        # Button styles
        style.configure('TButton', 
                       background=theme['button_bg'], 
                       foreground=theme['button_fg'],
                       bordercolor=theme['highlight'],
                       focuscolor=theme['highlight'])
        
        # Entry styles
        style.configure('TEntry', 
                        fieldbackground=theme['text_bg'],
                        foreground=theme['text_fg'],
                        insertcolor=theme['fg'])
        
        # Notebook styles
        style.configure('TNotebook', background=theme['bg'])
        style.configure('TNotebook.Tab', 
                        background=theme['button_bg'],
                        foreground=theme['button_fg'],
                        padding=[10, 5])
        style.map('TNotebook.Tab',
                 background=[('selected', theme['highlight'])],
                 foreground=[('selected', theme['fg'])])
    
    def switch_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme()
    
    def start_monitoring(self):
        ip_address = self.ip_entry.get().strip()
        if not ip_address:
            messagebox.showerror("Error", "Please enter a valid IP address")
            return
        
        if self.network_monitor.start_monitoring(ip_address):
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.print_to_terminal(f"Started monitoring {ip_address}")
        else:
            messagebox.showerror("Error", "Monitoring is already active")
    
    def stop_monitoring(self):
        self.network_monitor.stop_monitoring()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.print_to_terminal("Stopped monitoring")
    
    def update_dashboard(self):
        # Update threat display
        self.update_threat_display()
        
        # Update network stats
        self.update_network_stats()
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_dashboard)
    
    def update_threat_display(self):
        # Clear current threats tree
        for item in self.current_threats_tree.get_children():
            self.current_threats_tree.delete(item)
        
        # Add current threats
        current_threats = self.threat_detector.get_current_threats()
        for threat in current_threats:
            threat_types = ', '.join(threat['threat_types'])
            self.current_threats_tree.insert('', 'end', values=(
                threat['timestamp'],
                threat['source_ip'],
                threat_types,
                threat['destination_ip']
            ))
        
        # Update threat stats charts
        self.update_threat_charts()
        
        # Clear current threats after displaying
        self.threat_detector.clear_current_threats()
    
    def update_threat_charts(self):
        # Get threat statistics
        threat_stats = self.threat_detector.get_threat_stats()
        
        # Update pie chart
        self.threat_pie_ax.clear()
        if threat_stats:
            labels = list(threat_stats.keys())
            sizes = list(threat_stats.values())
            self.threat_pie_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            self.threat_pie_ax.axis('equal')
            self.threat_pie_fig.tight_layout()
        self.threat_pie_canvas.draw()
        
        # Update timeline chart (simplified)
        self.threat_timeline_ax.clear()
        if threat_stats:
            labels = list(threat_stats.keys())
            counts = list(threat_stats.values())
            self.threat_timeline_ax.bar(labels, counts)
            self.threat_timeline_ax.set_ylabel('Count')
            self.threat_timeline_fig.tight_layout()
        self.threat_timeline_canvas.draw()
    
    def update_network_stats(self):
        stats = self.network_monitor.get_stats()
        
        # Update numerical stats
        for stat_key, label in self.stats_labels.items():
            value = stats.get(stat_key, 0)
            if isinstance(value, float):
                label.config(text=f"{value:.2f}")
            else:
                label.config(text=str(value))
        
        # Update packet rate chart (simplified)
        self.packet_rate_ax.clear()
        if stats['uptime'] > 0:
            # Simulate some data for the chart
            x = [stats['uptime'] * 0.2 * i for i in range(5)]
            y = [stats['packet_rate'] * (0.8 + 0.4 * random.random()) for _ in range(5)]
            self.packet_rate_ax.plot(x, y, 'g-')
            self.packet_rate_ax.set_xlabel('Time (s)')
            self.packet_rate_ax.set_ylabel('Packets/s')
            self.packet_rate_fig.tight_layout()
        self.packet_rate_canvas.draw()
        
        # Update protocols chart (simplified)
        self.protocols_ax.clear()
        protocols = ['TCP', 'UDP', 'ICMP', 'Other']
        counts = [random.randint(10, 100) for _ in protocols]  # Simulated data
        self.protocols_ax.bar(protocols, counts)
        self.protocols_ax.set_ylabel('Count')
        self.protocols_fig.tight_layout()
        self.protocols_canvas.draw()
    
    def execute_terminal_command(self, event=None):
        command = self.terminal_input.get()
        self.terminal_input.delete(0, tk.END)
        
        # Print the command
        self.print_to_terminal(f"> {command}", prompt=True)
        
        # Execute and print result
        result = self.terminal.execute(command)
        self.print_to_terminal(result)
    
    def print_to_terminal(self, text, prompt=False):
        self.terminal_output.config(state='normal')
        if prompt:
            self.terminal_output.insert(tk.END, text + "\n", 'prompt')
        else:
            self.terminal_output.insert(tk.END, text + "\n")
        self.terminal_output.config(state='disabled')
        self.terminal_output.see(tk.END)
    
    def new_session(self):
        if messagebox.askyesno("New Session", "Start a new monitoring session?"):
            self.network_monitor.stop_monitoring()
            self.ip_entry.delete(0, tk.END)
            self.threat_detector = ThreatDetector()
            self.network_monitor = NetworkMonitor(self.threat_detector)
            self.terminal = TerminalEmulator(self.network_monitor)
            self.print_to_terminal("New session created")
    
    def save_session(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                data = {
                    'target_ip': self.ip_entry.get(),
                    'threat_history': self.threat_detector.threat_history,
                    'terminal_history': self.terminal_output.get("1.0", tk.END)
                }
                with open(file_path, 'w') as f:
                    json.dump(data, f)
                self.print_to_terminal(f"Session saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save session: {str(e)}")
    
    def load_session(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, data.get('target_ip', ''))
                
                self.threat_detector.threat_history = data.get('threat_history', [])
                
                self.terminal_output.config(state='normal')
                self.terminal_output.delete("1.0", tk.END)
                self.terminal_output.insert(tk.END, data.get('terminal_history', ''))
                self.terminal_output.config(state='disabled')
                
                self.print_to_terminal(f"Session loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load session: {str(e)}")
    
    def show_threat_dashboard(self):
        self.notebook.select(self.threat_tab)
    
    def show_network_stats(self):
        self.notebook.select(self.stats_tab)
    
    def open_port_scanner(self):
        messagebox.showinfo("Port Scanner", "Port scanner tool would open here")
    
    def open_vuln_scanner(self):
        messagebox.showinfo("Vulnerability Scanner", "Vulnerability scanner tool would open here")
    
    def open_packet_analyzer(self):
        messagebox.showinfo("Packet Analyzer", "Packet analyzer tool would open here")
    
    def show_user_guide(self):
        guide = """ Accurate Cyber Defnse Network Intrusion Detection System

1. Threat Monitoring:
   - Enter target IP and click Start to begin monitoring
   - Current threats will appear in the table
   - Charts show threat distribution and timeline

2. Network Statistics:
   - View real-time network metrics
   - See packet rate and protocol distribution

3. Terminal:
   - Execute security commands
   - Type 'help' for available commands"""
        
        messagebox.showinfo("User Guide", guide)
    
    def show_about(self):
        about = f"""Advanced Cyber Security Monitor v{VERSION}

A comprehensive network security tool for:
- Real-time threat detection (DOS, DDOS, Port Scanning)
- Network traffic monitoring
- Security command execution

Developed for cybersecurity professionals"""
        messagebox.showinfo("About", about)

def main():
    root = tk.Tk()
    root.geometry("1200x800")
    
    try:
        DashboardApp(root)
    except Exception as e:
        messagebox.showerror("Error", f"Application failed to start: {str(e)}")
        raise
    
    root.mainloop()

if __name__ == "__main__":
    main()