#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════╗
║  HACKERS_TCHAD IGMP PRO - Analyseur & Injecteur IGMP Temps Réel      ║
║  Créé par HACKERS_TCHAD                                               ║
║  Interface Hacker Green/Red - Tkinter                                 ║
║                                                                       ║
║  Gère le VRAI trafic IGMP sur le réseau :                            ║
║  - Capture/sniffing de paquets IGMP en temps réel                    ║
║  - Injection de paquets IGMP (Join, Leave, Query, Report)            ║
║  - Envoi et réception de trafic multicast UDP réel                   ║
║  - Table de routage multicast dynamique                              ║
║  - IGMP Snooping avec apprentissage des ports                        ║
║  - Statistiques, logs, export CSV                                    ║
╚═══════════════════════════════════════════════════════════════════════╝
"""

import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import json
import time
import os
import random
import platform
import subprocess
import csv
from datetime import datetime
from collections import defaultdict, deque

# ============ CONSTANTES ============
IGMP_ALL_ROUTERS = "224.0.0.2"
IGMP_ALL_SYSTEMS = "224.0.0.1"
DEFAULT_MCAST_GROUP = "239.255.1.1"
DEFAULT_MCAST_PORT = 50001
BUFFER_SIZE = 65535
MAX_LOG_LINES = 1000

THEME = {
    "bg": "#000000",
    "bg_secondary": "#0a0a0a",
    "bg_tertiary": "#111111",
    "panel": "#0d0d0d",
    "green": "#00ff00",
    "green_dim": "#00aa00",
    "green_dark": "#003300",
    "green_glow": "#39ff14",
    "red": "#ff0000",
    "red_dim": "#aa0000",
    "red_dark": "#330000",
    "accent": "#00ff41",
    "text": "#e0ffe0",
    "text_muted": "#88aa88",
    "warning": "#ffff00",
    "cyan": "#00ffff",
    "magenta": "#ff00ff",
    "orange": "#ff8800",
    "blue": "#0088ff",
    "border": "#00ff00",
    "border_red": "#ff0000",
}

IGMP_TYPES = {
    0x11: "MEMBERSHIP QUERY",
    0x12: "V1 MEMBERSHIP REPORT",
    0x16: "V2 MEMBERSHIP REPORT",
    0x17: "V2 LEAVE GROUP",
    0x22: "V3 MEMBERSHIP REPORT",
}


def get_local_ips():
    ips = ["0.0.0.0"]
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for addr in addrs:
            ip = addr[4][0]
            if not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    return sorted(set(ips))


def ip_to_int(ip):
    return struct.unpack(">I", socket.inet_aton(ip))[0]


def int_to_ip(n):
    return socket.inet_ntoa(struct.pack(">I", n))


def checksum_igmp(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_igmp_packet(igmp_type, group_address, max_resp=100, version=2):
    group_bytes = socket.inet_aton(group_address)
    if version == 3 and igmp_type == 0x11:
        data = struct.pack("!BBH", igmp_type, max_resp, 0) + group_bytes + struct.pack("!BBH", 0, 0, 0)
    else:
        data = struct.pack("!BBH", igmp_type, max_resp, 0) + group_bytes
    cs = checksum_igmp(data)
    if version == 3 and igmp_type == 0x11:
        data = struct.pack("!BBH", igmp_type, max_resp, cs) + group_bytes + struct.pack("!BBH", 0, 0, 0)
    else:
        data = struct.pack("!BBH", igmp_type, max_resp, cs) + group_bytes
    return data


def parse_igmp_packet(data):
    if len(data) < 8:
        return None
    igmp_type, max_resp, checksum, group = struct.unpack("!BBH4s", data[:8])
    group_ip = socket.inet_ntoa(group)
    return {
        "type": igmp_type,
        "type_name": IGMP_TYPES.get(igmp_type, f"UNKNOWN(0x{igmp_type:02X})"),
        "max_resp": max_resp,
        "checksum": checksum,
        "group": group_ip,
    }


def build_ip_header(src_ip, dst_ip, protocol, payload_len, ttl=1):
    ihl = 5
    version = 4
    tos = 0
    total_len = (ihl * 4) + payload_len
    identification = random.randint(0, 65535)
    flags_frag = 0
    ttl = ttl
    checksum_ip = 0
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) + ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        checksum_ip,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    checksum_ip = checksum_igmp(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) + ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        checksum_ip,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    return header


# ============ CLASSES RÉSEAU ============
class IGMPPacketSniffer:
    """Capture les paquets IGMP réels sur l'interface réseau."""

    def __init__(self, app, interface="0.0.0.0"):
        self.app = app
        self.interface = interface
        self.sock = None
        self.running = False

    def start(self):
        try:
            if platform.system() == "Windows":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            else:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
            self.running = True
            threading.Thread(target=self.capture_loop, daemon=True).start()
            self.app.log("[SNIFFER] Capture IGMP démarrée", "green_glow")
            return True
        except PermissionError as e:
            self.app.log(f"[SNIFFER] Privilèges root/admin requis: {e}", "red")
            return False
        except Exception as e:
            self.app.log(f"[SNIFFER] Erreur: {e}", "red")
            return False

    def capture_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                if platform.system() == "Windows":
                    igmp_data = data
                    src_ip = "0.0.0.0"
                else:
                    if len(data) < 34:
                        continue
                    src_ip = socket.inet_ntoa(data[26:30])
                    dst_ip = socket.inet_ntoa(data[30:34])
                    ip_header_len = (data[14] & 0x0F) * 4
                    igmp_data = data[14 + ip_header_len:]

                parsed = parse_igmp_packet(igmp_data)
                if parsed:
                    self.app.handle_real_igmp(src_ip, parsed)
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


class IGMPSource:
    """Source/Serveur multicast : envoie du vrai trafic UDP multicast."""

    def __init__(self, app, group, port, ttl=64):
        self.app = app
        self.group = group
        self.port = port
        self.ttl = ttl
        self.sock = None
        self.running = False
        self.sequence = 0

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
            self.running = True
            self.app.log(f"[SOURCE] Démarrée vers {self.group}:{self.port} (TTL={self.ttl})", "green")
            return True
        except Exception as e:
            self.app.log(f"[SOURCE] Erreur: {e}", "red")
            return False

    def send_packet(self, payload):
        if not self.running or not self.sock:
            return False
        try:
            full = f"[{self.sequence}] {payload}".encode("utf-8")
            self.sock.sendto(full, (self.group, self.port))
            self.sequence += 1
            self.app.log(f"[SOURCE] UDP #{self.sequence} → {self.group}:{self.port} ({len(full)} B)", "green_dim")
            self.app.stats["sent"] += 1
            self.app.update_stats()
            return True
        except Exception as e:
            self.app.log(f"[SOURCE] Erreur envoi: {e}", "red")
            return False

    def send_burst(self, count, interval_ms, payload):
        def burst():
            for _ in range(count):
                if not self.running:
                    break
                self.send_packet(payload)
                time.sleep(interval_ms / 1000.0)
        threading.Thread(target=burst, daemon=True).start()

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.app.log("[SOURCE] Arrêtée", "red_dim")


class IGMPClient:
    """Client/Hôte : rejoint/quitte des groupes multicast, reçoit le trafic UDP."""

    def __init__(self, app, interface, port=DEFAULT_MCAST_PORT):
        self.app = app
        self.interface = interface
        self.port = port
        self.sock = None
        self.joined_groups = set()
        self.running = False

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.interface, self.port))
            self.running = True
            threading.Thread(target=self.receive_loop, daemon=True).start()
            self.app.log(f"[CLIENT] Écoute UDP démarrée sur {self.interface}:{self.port}", "green")
            return True
        except Exception as e:
            self.app.log(f"[CLIENT] Erreur: {e}", "red")
            return False

    def join_group(self, group):
        if group in self.joined_groups:
            self.app.log(f"[CLIENT] Déjà membre de {group}", "warning")
            return
        try:
            mreq = socket.inet_aton(group) + socket.inet_aton(self.interface)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.joined_groups.add(group)
            self.app.log(f"[CLIENT] JOIN {group}", "cyan")
            self.send_igmp_report(group)
            self.app.update_client_groups(self.joined_groups)
        except Exception as e:
            self.app.log(f"[CLIENT] Erreur JOIN {group}: {e}", "red")

    def leave_group(self, group):
        if group not in self.joined_groups:
            return
        try:
            mreq = socket.inet_aton(group) + socket.inet_aton(self.interface)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            self.joined_groups.discard(group)
            self.app.log(f"[CLIENT] LEAVE {group}", "red_dim")
            self.send_igmp_leave(group)
            self.app.update_client_groups(self.joined_groups)
        except Exception as e:
            self.app.log(f"[CLIENT] Erreur LEAVE {group}: {e}", "red")

    def send_igmp_report(self, group, version=2):
        pkt = build_igmp_packet(0x16, group, version=version)
        self._send_raw_igmp(pkt, group)

    def send_igmp_leave(self, group, version=2):
        pkt = build_igmp_packet(0x17, group, version=version)
        self._send_raw_igmp(pkt, IGMP_ALL_ROUTERS)

    def _send_raw_igmp(self, pkt, dst):
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            src_ip = self.interface if self.interface != "0.0.0.0" else get_local_ips()[-1]
            ip_header = build_ip_header(src_ip, dst, 2, len(pkt), ttl=1)
            raw_sock.sendto(ip_header + pkt, (dst, 0))
            raw_sock.close()
            self.app.log(f"[CLIENT] Paquet IGMP envoyé vers {dst}", "green_dim")
            self.app.stats["igmp_sent"] += 1
            self.app.update_stats()
        except PermissionError as e:
            self.app.log(f"[CLIENT] Privilèges root/admin requis pour IGMP RAW: {e}", "warning")
        except Exception as e:
            self.app.log(f"[CLIENT] Impossible d'envoyer IGMP: {e}", "warning")

    def receive_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                msg = data.decode("utf-8", errors="replace")
                self.app.log(f"[CLIENT] Reçu de {addr[0]}:{addr[1]} → {msg[:120]}", "cyan")
                self.app.update_received_stats(addr[0], len(data))
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        for g in list(self.joined_groups):
            try:
                mreq = socket.inet_aton(g) + socket.inet_aton(self.interface)
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except Exception:
                pass
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.app.log("[CLIENT] Arrêté", "red")


class IGMPRouter:
    """Routeur multicast : reçoit les IGMP Reports/Leave, gère la table IGMP."""

    def __init__(self, app, interface, query_interval=30):
        self.app = app
        self.interface = interface
        self.query_interval = query_interval
        self.sock = None
        self.running = False
        self.igmp_table = defaultdict(set)

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            self.sock.bind((self.interface, 0))
            self.running = True
            threading.Thread(target=self.listen_igmp, daemon=True).start()
            threading.Thread(target=self.send_queries_loop, daemon=True).start()
            self.app.log("[ROUTEUR] Démarré - écoute IGMP", "green")
            return True
        except PermissionError as e:
            self.app.log(f"[ROUTEUR] Privilèges root/admin requis: {e}", "red")
            return False
        except Exception as e:
            self.app.log(f"[ROUTEUR] Erreur: {e}", "red")
            return False

    def send_general_query(self):
        pkt = build_igmp_packet(0x11, "0.0.0.0")
        self._send_raw(pkt, IGMP_ALL_SYSTEMS)
        self.app.log("[ROUTEUR] General Query envoyé", "orange")

    def send_group_specific_query(self, group):
        pkt = build_igmp_packet(0x11, group)
        self._send_raw(pkt, group)
        self.app.log(f"[ROUTEUR] Group-Specific Query pour {group}", "orange")

    def _send_raw(self, pkt, dst):
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            src_ip = self.interface if self.interface != "0.0.0.0" else get_local_ips()[-1]
            ip_header = build_ip_header(src_ip, dst, 2, len(pkt), ttl=1)
            raw_sock.sendto(ip_header + pkt, (dst, 0))
            raw_sock.close()
            self.app.stats["igmp_sent"] += 1
            self.app.update_stats()
        except Exception as e:
            self.app.log(f"[ROUTEUR] Erreur envoi IGMP: {e}", "red")

    def listen_igmp(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                parsed = parse_igmp_packet(data)
                if parsed:
                    self.process_igmp(parsed, addr[0])
            except Exception:
                if not self.running:
                    break

    def process_igmp(self, parsed, src_ip):
        igmp_type = parsed["type"]
        group = parsed["group"]

        if igmp_type in (0x12, 0x16, 0x22):
            self.igmp_table[group].add(src_ip)
            self.app.log(f"[ROUTEUR] Report reçu de {src_ip} pour {group}", "green")
        elif igmp_type == 0x17:
            if src_ip in self.igmp_table.get(group, set()):
                self.igmp_table[group].discard(src_ip)
                if not self.igmp_table[group]:
                    del self.igmp_table[group]
            self.app.log(f"[ROUTEUR] Leave reçu de {src_ip} pour {group}", "red_dim")
        elif igmp_type == 0x11:
            self.app.log(f"[ROUTEUR] Query reçue de {src_ip} (group={group})", "orange")

        self.app.update_router_table(self.igmp_table)
        self.app.stats["igmp_received"] += 1
        self.app.update_stats()

    def send_queries_loop(self):
        while self.running:
            time.sleep(self.query_interval)
            if self.running:
                self.send_general_query()

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.app.log("[ROUTEUR] Arrêté", "red")


class IGMPSwitch:
    """Switch avec IGMP Snooping : apprend les ports/groupes depuis le trafic IGMP."""

    def __init__(self, app, interface):
        self.app = app
        self.interface = interface
        self.sock = None
        self.running = False
        self.snooping_table = defaultdict(set)

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            self.sock.bind((self.interface, 0))
            self.running = True
            threading.Thread(target=self.snoop_loop, daemon=True).start()
            self.app.log("[SWITCH] IGMP Snooping démarré", "green")
            return True
        except PermissionError as e:
            self.app.log(f"[SWITCH] Privilèges root/admin requis: {e}", "red")
            return False
        except Exception as e:
            self.app.log(f"[SWITCH] Erreur: {e}", "red")
            return False

    def snoop_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                parsed = parse_igmp_packet(data)
                if parsed:
                    group = parsed["group"]
                    port = addr[0]
                    if parsed["type"] in (0x12, 0x16, 0x22):
                        self.snooping_table[group].add(port)
                        self.app.log(f"[SWITCH] Snooping: ajout {port} au groupe {group}", "magenta")
                    elif parsed["type"] == 0x17:
                        self.snooping_table[group].discard(port)
                        if not self.snooping_table[group]:
                            del self.snooping_table[group]
                        self.app.log(f"[SWITCH] Snooping: retrait {port} du groupe {group}", "red_dim")
                    self.app.update_switch_table(self.snooping_table)
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.app.log("[SWITCH] Arrêté", "red")


# ============ APPLICATION PRINCIPALE ============
class IGMPProApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔴 HACKERS_TCHAD IGMP PRO - Analyseur Réseau 🔴")
        self.root.geometry("1400x900")
        self.root.configure(bg=THEME["bg"])
        self.root.minsize(1200, 750)

        self.source = None
        self.client = None
        self.router = None
        self.switch = None
        self.sniffer = None

        self.stats = {"sent": 0, "received": 0, "igmp_sent": 0, "igmp_received": 0}
        self.received_sources = defaultdict(int)
        self.pcap_buffer = deque(maxlen=5000)

        self.style_widgets()
        self.build_ui()

    def style_widgets(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=THEME["bg"])
        style.configure("TButton",
                        background=THEME["green_dim"],
                        foreground=THEME["bg"],
                        font=("Consolas", 9, "bold"),
                        borderwidth=0,
                        relief="flat")
        style.map("TButton", background=[("active", THEME["green"])])
        style.configure("TEntry", fieldbackground=THEME["bg_tertiary"], foreground=THEME["green"],
                        insertcolor=THEME["green"], borderwidth=0)
        style.configure("TProgressbar", background=THEME["green"], troughcolor=THEME["bg_tertiary"])

    def build_ui(self):
        main_frame = tk.Frame(self.root, bg=THEME["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Header
        header = tk.Frame(main_frame, bg=THEME["bg_secondary"], highlightbackground=THEME["green"],
                          highlightthickness=2, height=70)
        header.pack(fill=tk.X, pady=(0, 10))
        header.pack_propagate(False)

        tk.Label(header, text="🔴 HACKERS_TCHAD (IGMP) PRO", bg=THEME["bg_secondary"], fg=THEME["green"],
                 font=("Consolas", 20, "bold")).pack(side=tk.LEFT, padx=20, pady=10)
        tk.Label(header, text="Analyseur & Injecteur IGMP Temps Réel", bg=THEME["bg_secondary"],
                 fg=THEME["text_muted"], font=("Consolas", 11)).pack(side=tk.LEFT, padx=10, pady=10)

        self.status_label = tk.Label(header, text="PRÊT", bg=THEME["bg_secondary"], fg=THEME["green"],
                                     font=("Consolas", 10, "bold"))
        self.status_label.pack(side=tk.RIGHT, padx=20, pady=10)

        # Panneau gauche : contrôles
        left_panel = tk.Frame(main_frame, bg=THEME["bg_secondary"], width=360,
                              highlightbackground=THEME["green"], highlightthickness=1)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        self.build_role_panel(left_panel)
        self.build_source_panel(left_panel)
        self.build_client_panel(left_panel)
        self.build_router_panel(left_panel)
        self.build_switch_panel(left_panel)
        self.build_injector_panel(left_panel)
        self.build_scenario_panel(left_panel)

        # Panneau droit : logs, tables, stats
        right_panel = tk.Frame(main_frame, bg=THEME["bg"])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.build_log_area(right_panel)
        self.build_tables_area(right_panel)
        self.build_stats_area(right_panel)

    def build_role_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" RÔLES RÉSEAU ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        self.role_vars = {}
        roles = ["Source/Serveur", "Client/Hôte", "Routeur Multicast", "Switch Snooping", "Sniffer IGMP"]
        for role in roles:
            var = tk.BooleanVar(value=False)
            self.role_vars[role] = var
            cb = tk.Checkbutton(frame, text=role, variable=var,
                                bg=THEME["bg_secondary"], fg=THEME["text"],
                                selectcolor=THEME["green_dark"], activebackground=THEME["bg_secondary"],
                                activeforeground=THEME["green"], font=("Consolas", 10),
                                command=lambda r=role: self.toggle_role(r))
            cb.pack(anchor="w", padx=10, pady=2)

    def build_source_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" SOURCE MULTICAST ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Groupe:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=10, pady=3)
        self.src_group = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.src_group.insert(0, DEFAULT_MCAST_GROUP)
        self.src_group.grid(row=0, column=1, padx=5, pady=3)

        tk.Label(frame, text="Port:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=1, column=0, sticky="w", padx=10, pady=3)
        self.src_port = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.src_port.insert(0, str(DEFAULT_MCAST_PORT))
        self.src_port.grid(row=1, column=1, padx=5, pady=3)

        tk.Label(frame, text="Payload:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=2, column=0, sticky="w", padx=10, pady=3)
        self.src_payload = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.src_payload.insert(0, "HACKERS_TCHAD_IGMP_PRO")
        self.src_payload.grid(row=2, column=1, padx=5, pady=3)

        btn_frame = tk.Frame(frame, bg=THEME["bg_secondary"])
        btn_frame.grid(row=3, column=0, columnspan=2, pady=5)
        tk.Button(btn_frame, text="Envoyer", bg=THEME["green_dim"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.send_one_packet).pack(side=tk.LEFT, padx=3)
        tk.Button(btn_frame, text="Rafale 10x", bg=THEME["green"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.send_burst_packet).pack(side=tk.LEFT, padx=3)

    def build_client_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" CLIENT / HÔTE ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Groupe:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=10, pady=3)
        self.client_group = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.client_group.insert(0, DEFAULT_MCAST_GROUP)
        self.client_group.grid(row=0, column=1, padx=5, pady=3)

        btn_frame = tk.Frame(frame, bg=THEME["bg_secondary"])
        btn_frame.grid(row=1, column=0, columnspan=2, pady=5)
        tk.Button(btn_frame, text="JOIN", bg=THEME["green_dim"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.client_join).pack(side=tk.LEFT, padx=3)
        tk.Button(btn_frame, text="LEAVE", bg=THEME["red_dim"], fg=THEME["text"],
                  font=("Consolas", 9, "bold"), command=self.client_leave).pack(side=tk.LEFT, padx=3)

        self.client_groups_label = tk.Label(frame, text="Groupes: aucun", bg=THEME["bg_secondary"],
                                            fg=THEME["text_muted"], font=("Consolas", 9))
        self.client_groups_label.grid(row=2, column=0, columnspan=2, sticky="w", padx=10, pady=3)

    def build_router_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" ROUTEUR MULTICAST ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Query interval (s):", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=10, pady=3)
        self.router_interval = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.router_interval.insert(0, "30")
        self.router_interval.grid(row=0, column=1, padx=5, pady=3)

        btn_frame = tk.Frame(frame, bg=THEME["bg_secondary"])
        btn_frame.grid(row=1, column=0, columnspan=2, pady=5)
        tk.Button(btn_frame, text="General Query", bg=THEME["green_dim"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.send_manual_query).pack(side=tk.LEFT, padx=3)
        tk.Button(btn_frame, text="Group Query", bg=THEME["orange"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.send_group_query).pack(side=tk.LEFT, padx=3)
        tk.Button(btn_frame, text="Vider", bg=THEME["red_dim"], fg=THEME["text"],
                  font=("Consolas", 9, "bold"), command=self.clear_router_table).pack(side=tk.LEFT, padx=3)

    def build_switch_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" SWITCH SNOOPING ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(frame, text="Vider Table Snooping", bg=THEME["red_dim"], fg=THEME["text"],
                  font=("Consolas", 9, "bold"), command=self.clear_switch_table).pack(pady=8)

    def build_injector_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" INJECTEUR IGMP ", bg=THEME["bg_secondary"],
                              fg=THEME["red"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Type:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=10, pady=3)
        self.inj_type = ttk.Combobox(frame, values=["Report v2", "Leave v2", "Query v2", "Report v1"],
                                     state="readonly", font=("Consolas", 10))
        self.inj_type.set("Report v2")
        self.inj_type.grid(row=0, column=1, padx=5, pady=3)

        tk.Label(frame, text="Groupe:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=1, column=0, sticky="w", padx=10, pady=3)
        self.inj_group = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.inj_group.insert(0, DEFAULT_MCAST_GROUP)
        self.inj_group.grid(row=1, column=1, padx=5, pady=3)

        tk.Button(frame, text="INJECTER PAQUET", bg=THEME["red"], fg=THEME["bg"],
                  font=("Consolas", 10, "bold"), command=self.inject_igmp).grid(row=2, column=0, columnspan=2, pady=8)

    def build_scenario_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" SCÉNARIOS ", bg=THEME["bg_secondary"],
                              fg=THEME["cyan"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Button(frame, text="Demo Join+Leave", bg=THEME["cyan"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.scenario_join_leave).pack(fill=tk.X, padx=10, pady=3)
        tk.Button(frame, text="Demo Source Rafale", bg=THEME["cyan"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.scenario_source_burst).pack(fill=tk.X, padx=10, pady=3)
        tk.Button(frame, text="Export PCAP", bg=THEME["magenta"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.export_pcap).pack(fill=tk.X, padx=10, pady=3)

    def build_log_area(self, parent):
        frame = tk.LabelFrame(parent, text=" LOGS TEMPS RÉEL ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_area = scrolledtext.ScrolledText(frame, state=tk.DISABLED, wrap=tk.WORD,
                                                  bg=THEME["bg"], fg=THEME["green"],
                                                  font=("Consolas", 10), borderwidth=0,
                                                  highlightthickness=1, highlightbackground=THEME["green"],
                                                  padx=8, pady=8)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        for tag, color in {
            "green": THEME["green"], "green_dim": THEME["green_dim"], "green_glow": THEME["green_glow"],
            "red": THEME["red"], "red_dim": THEME["red_dim"], "cyan": THEME["cyan"],
            "magenta": THEME["magenta"], "orange": THEME["orange"], "warning": THEME["warning"],
            "blue": THEME["blue"], "system": THEME["text_muted"]
        }.items():
            self.log_area.tag_config(tag, foreground=color)

    def build_tables_area(self, parent):
        frame = tk.Frame(parent, bg=THEME["bg"])
        frame.pack(fill=tk.X, padx=5, pady=5)

        rt_frame = tk.LabelFrame(frame, text=" TABLE ROUTEUR MULTICAST ", bg=THEME["bg_secondary"],
                                 fg=THEME["green"], font=("Consolas", 10, "bold"))
        rt_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.router_table = tk.Listbox(rt_frame, bg=THEME["bg"], fg=THEME["green"],
                                       selectbackground=THEME["green_dark"], selectforeground=THEME["green"],
                                       font=("Consolas", 10), borderwidth=0, highlightthickness=0)
        self.router_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        sw_frame = tk.LabelFrame(frame, text=" TABLE IGMP SNOOPING ", bg=THEME["bg_secondary"],
                                 fg=THEME["green"], font=("Consolas", 10, "bold"))
        sw_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.switch_table = tk.Listbox(sw_frame, bg=THEME["bg"], fg=THEME["green"],
                                       selectbackground=THEME["green_dark"], selectforeground=THEME["green"],
                                       font=("Consolas", 10), borderwidth=0, highlightthickness=0)
        self.switch_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def build_stats_area(self, parent):
        frame = tk.LabelFrame(parent, text=" STATISTIQUES ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 10, "bold"))
        frame.pack(fill=tk.X, padx=5, pady=5)

        self.stats_label = tk.Label(frame,
                                    text="UDP Sent: 0 | UDP Rcvd: 0 | IGMP Sent: 0 | IGMP Rcvd: 0",
                                    bg=THEME["bg_secondary"], fg=THEME["green"],
                                    font=("Consolas", 11, "bold"))
        self.stats_label.pack(padx=10, pady=10)

    # ============ ACTIONS ============
    def toggle_role(self, role):
        enabled = self.role_vars[role].get()
        if role == "Source/Serveur":
            if enabled:
                group = self.src_group.get().strip()
                port = int(self.src_port.get().strip())
                self.source = IGMPSource(self, group, port)
                self.source.start()
            else:
                if self.source:
                    self.source.stop()
                    self.source = None
        elif role == "Client/Hôte":
            if enabled:
                self.client = IGMPClient(self, "0.0.0.0")
                self.client.start()
            else:
                if self.client:
                    self.client.stop()
                    self.client = None
        elif role == "Routeur Multicast":
            if enabled:
                interval = int(self.router_interval.get().strip() or "30")
                self.router = IGMPRouter(self, "0.0.0.0", interval)
                self.router.start()
            else:
                if self.router:
                    self.router.stop()
                    self.router = None
        elif role == "Switch Snooping":
            if enabled:
                self.switch = IGMPSwitch(self, "0.0.0.0")
                self.switch.start()
            else:
                if self.switch:
                    self.switch.stop()
                    self.switch = None
        elif role == "Sniffer IGMP":
            if enabled:
                self.sniffer = IGMPPacketSniffer(self, "0.0.0.0")
                self.sniffer.start()
            else:
                if self.sniffer:
                    self.sniffer.stop()
                    self.sniffer = None

    def send_one_packet(self):
        if not self.source:
            messagebox.showwarning("Source inactive", "Activez le rôle Source/Serveur d'abord.")
            return
        payload = self.src_payload.get().strip()
        self.source.send_packet(payload)

    def send_burst_packet(self):
        if not self.source:
            messagebox.showwarning("Source inactive", "Activez le rôle Source/Serveur d'abord.")
            return
        payload = self.src_payload.get().strip()
        self.source.send_burst(10, 200, payload)

    def client_join(self):
        if not self.client:
            messagebox.showwarning("Client inactif", "Activez le rôle Client/Hôte d'abord.")
            return
        group = self.client_group.get().strip()
        self.client.join_group(group)

    def client_leave(self):
        if not self.client:
            messagebox.showwarning("Client inactif", "Activez le rôle Client/Hôte d'abord.")
            return
        group = self.client_group.get().strip()
        self.client.leave_group(group)

    def send_manual_query(self):
        if not self.router:
            messagebox.showwarning("Routeur inactif", "Activez le rôle Routeur Multicast d'abord.")
            return
        self.router.send_general_query()

    def send_group_query(self):
        if not self.router:
            messagebox.showwarning("Routeur inactif", "Activez le rôle Routeur Multicast d'abord.")
            return
        group = simpledialog.askstring("Group Query", "Adresse du groupe multicast:", initialvalue=DEFAULT_MCAST_GROUP)
        if group:
            self.router.send_group_specific_query(group)

    def clear_router_table(self):
        if self.router:
            self.router.igmp_table.clear()
        self.update_router_table(defaultdict(set))
        self.log("[ROUTEUR] Table vidée", "red_dim")

    def clear_switch_table(self):
        if self.switch:
            self.switch.snooping_table.clear()
        self.update_switch_table(defaultdict(set))
        self.log("[SWITCH] Table snooping vidée", "red_dim")

    def inject_igmp(self):
        igmp_type_map = {
            "Report v2": 0x16,
            "Leave v2": 0x17,
            "Query v2": 0x11,
            "Report v1": 0x12,
        }
        igmp_type = igmp_type_map.get(self.inj_type.get(), 0x16)
        group = self.inj_group.get().strip()
        pkt = build_igmp_packet(igmp_type, group)
        dst = IGMP_ALL_ROUTERS if igmp_type == 0x17 else (group if igmp_type == 0x11 else group)
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            src_ip = get_local_ips()[-1]
            ip_header = build_ip_header(src_ip, dst, 2, len(pkt), ttl=1)
            raw_sock.sendto(ip_header + pkt, (dst, 0))
            raw_sock.close()
            self.log(f"[INJECTEUR] Paquet {self.inj_type.get()} injecté vers {dst}", "red")
            self.stats["igmp_sent"] += 1
            self.update_stats()
        except PermissionError as e:
            self.log(f"[INJECTEUR] Privilèges root/admin requis: {e}", "warning")
        except Exception as e:
            self.log(f"[INJECTEUR] Erreur: {e}", "red")

    def scenario_join_leave(self):
        def run():
            self.client_join()
            time.sleep(3)
            self.client_leave()
        threading.Thread(target=run, daemon=True).start()

    def scenario_source_burst(self):
        def run():
            if not self.source:
                self.log("[SCÉNARIO] Activez la source d'abord", "warning")
                return
            self.source.send_burst(20, 100, "SCENARIO_BURST_HACKERS_TCHAD")
        threading.Thread(target=run, daemon=True).start()

    def export_pcap(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "source", "type", "group", "details"])
                for entry in self.pcap_buffer:
                    writer.writerow([
                        entry.get("time"), entry.get("src"), entry.get("type"),
                        entry.get("group"), entry.get("details")
                    ])
            self.log(f"[EXPORT] Logs exportés vers {path}", "blue")
        except Exception as e:
            self.log(f"[EXPORT] Erreur: {e}", "red")

    # ============ MISES À JOUR UI ============
    def log(self, message, tag="green"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        full = f"[{timestamp}] {message}\n"

        def _append():
            self.log_area.config(state=tk.NORMAL)
            self.log_area.insert(tk.END, full, tag)
            # Limiter le nombre de lignes
            lines = int(self.log_area.index(tk.END).split(".")[0])
            if lines > MAX_LOG_LINES:
                self.log_area.delete(1.0, f"{lines - MAX_LOG_LINES}.0")
            self.log_area.config(state=tk.DISABLED)
            self.log_area.see(tk.END)
            self.status_label.config(text=message[:80])

        try:
            self.root.after(0, _append)
        except Exception:
            pass

    def handle_real_igmp(self, src_ip, parsed):
        self.pcap_buffer.append({
            "time": datetime.now().isoformat(),
            "src": src_ip,
            "type": parsed["type_name"],
            "group": parsed["group"],
            "details": json.dumps(parsed)
        })
        self.log(f"[SNIFFER] {parsed['type_name']} de {src_ip} pour {parsed['group']}", "green_glow")
        self.stats["igmp_received"] += 1
        self.update_stats()

    def update_client_groups(self, groups):
        def _update():
            text = ", ".join(groups) if groups else "aucun"
            self.client_groups_label.config(text=f"Groupes: {text}")
        try:
            self.root.after(0, _update)
        except Exception:
            pass

    def update_router_table(self, table):
        def _update():
            self.router_table.delete(0, tk.END)
            if not table:
                self.router_table.insert(tk.END, "(Aucun groupe multicast)")
                return
            for group, ips in sorted(table.items()):
                self.router_table.insert(tk.END, f"[GROUPE {group}]")
                for ip in sorted(ips):
                    self.router_table.insert(tk.END, f"   └── Client: {ip}")

        try:
            self.root.after(0, _update)
        except Exception:
            pass

    def update_switch_table(self, table):
        def _update():
            self.switch_table.delete(0, tk.END)
            if not table:
                self.switch_table.insert(tk.END, "(Aucun port appris)")
                return
            for group, ips in sorted(table.items()):
                self.switch_table.insert(tk.END, f"[VLAN/MCAST {group}]")
                for ip in sorted(ips):
                    self.switch_table.insert(tk.END, f"   └── Port/IP: {ip}")

        try:
            self.root.after(0, _update)
        except Exception:
            pass

    def update_received_stats(self, source_ip, size):
        self.stats["received"] += 1
        self.received_sources[source_ip] += size
        self.update_stats()

    def update_stats(self):
        def _update():
            self.stats_label.config(
                text=(f"UDP Sent: {self.stats['sent']} | UDP Rcvd: {self.stats['received']} | "
                      f"IGMP Sent: {self.stats['igmp_sent']} | IGMP Rcvd: {self.stats['igmp_received']}")
            )

        try:
            self.root.after(0, _update)
        except Exception:
            pass

    def on_close(self):
        for obj in [self.source, self.client, self.router, self.switch, self.sniffer]:
            if obj:
                try:
                    obj.stop()
                except Exception:
                    pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = IGMPProApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
