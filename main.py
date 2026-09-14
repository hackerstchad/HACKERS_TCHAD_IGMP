#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HACKERS_TCHAD (IGMP) - Simulateur & Moniteur IGMP Multicast Avancé
Créé par HACKERS_TCHAD
Interface Hacker Green/Red - Tkinter

Fonctionnalités :
- Simulateur IGMP v1/v2/v3 complet
- Rôles : Source/Serveur, Client/Hôte, Routeur Multicast, Switch (IGMP Snooping)
- Envoi réel de trafic multicast UDP en local
- Envoi de paquets IGMP réels (Join, Leave, Query, Report)
- Table de routage multicast dynamique
- IGMP Snooping sur switch avec tables de ports
- Logs temps réel avec couleurs
- Scan de groupe, statistiques, graphiques
"""

import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import json
import time
import os
import random
import platform
from datetime import datetime
from collections import defaultdict

# ============ CONFIGURATION ============
IGMP_ALL_ROUTERS = "224.0.0.2"
IGMP_ALL_SYSTEMS = "224.0.0.1"
IGMP_PROTOCOL_NUMBER = 2
DEFAULT_MCAST_GROUP = "239.255.1.1"
DEFAULT_MCAST_PORT = 50001
DEFAULT_INTERFACE = "0.0.0.0"
BUFFER_SIZE = 4096

THEME = {
    "bg": "#050505",
    "bg_secondary": "#0a0a0a",
    "bg_tertiary": "#111111",
    "panel": "#0d0d0d",
    "green": "#00ff00",
    "green_dim": "#00aa00",
    "green_dark": "#003300",
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
    "border": "#00ff00",
    "border_red": "#ff0000",
}

IGMP_TYPES = {
    0x11: "MEMBERSHIP QUERY",
    0x16: "V2 MEMBERSHIP REPORT",
    0x17: "V2 LEAVE GROUP",
    0x12: "V1 MEMBERSHIP REPORT",
    0x22: "V3 MEMBERSHIP REPORT",
}

ROLES = ["Source/Serveur", "Client/Hôte", "Routeur Multicast", "Switch IGMP Snooping"]


# ============ FONCTIONS UTILITAIRES ============
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
    return ips


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


def build_igmp_packet(igmp_type, group_address, version=2):
    group_bytes = socket.inet_aton(group_address)
    if version == 3 and igmp_type == 0x11:
        # IGMPv3 Query simplifiée
        data = struct.pack("!BBH", igmp_type, 0x64, 0) + group_bytes + struct.pack("!BBH", 0, 0, 0)
    else:
        data = struct.pack("!BBH", igmp_type, 0, 0) + group_bytes
    cs = checksum_igmp(data)
    if version == 3 and igmp_type == 0x11:
        data = struct.pack("!BBH", igmp_type, 0x64, cs) + group_bytes + struct.pack("!BBH", 0, 0, 0)
    else:
        data = struct.pack("!BBH", igmp_type, 0, cs) + group_bytes
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


# ============ CLASSES DE SIMULATION ============
class IGMPSource:
    """Source/Serveur multicast : envoie du trafic UDP vers un groupe."""

    def __init__(self, app, group, port):
        self.app = app
        self.group = group
        self.port = port
        self.sock = None
        self.running = False
        self.thread = None
        self.sequence = 0

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 64)
            self.running = True
            self.app.log(f"[SOURCE] Démarrée vers {self.group}:{self.port}", "green")
            return True
        except Exception as e:
            self.app.log(f"[SOURCE] Erreur: {e}", "red")
            return False

    def send_packet(self, payload):
        if not self.running or not self.sock:
            return
        try:
            full = f"[{self.sequence}] {payload}".encode("utf-8")
            self.sock.sendto(full, (self.group, self.port))
            self.sequence += 1
            self.app.log(f"[SOURCE] Paquet #{self.sequence} envoyé → {self.group}:{self.port} ({len(full)} octets)", "green")
        except Exception as e:
            self.app.log(f"[SOURCE] Erreur envoi: {e}", "red")

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
        self.app.log("[SOURCE] Arrêtée", "red")


class IGMPClient:
    """Client/Hôte : rejoint/quitte des groupes multicast, reçoit le trafic."""

    def __init__(self, app, interface):
        self.app = app
        self.interface = interface
        self.sock = None
        self.joined_groups = set()
        self.running = False

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.interface, DEFAULT_MCAST_PORT))
            self.running = True
            threading.Thread(target=self.receive_loop, daemon=True).start()
            self.app.log(f"[CLIENT] Écoute démarrée sur {self.interface}:{DEFAULT_MCAST_PORT}", "green")
            return True
        except Exception as e:
            self.app.log(f"[CLIENT] Erreur: {e}", "red")
            return False

    def join_group(self, group):
        if group in self.joined_groups:
            return
        try:
            mreq = socket.inet_aton(group) + socket.inet_aton(self.interface)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.joined_groups.add(group)
            self.app.log(f"[CLIENT] JOIN {group}", "cyan")
            self.send_igmp_report(group)
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
        except Exception as e:
            self.app.log(f"[CLIENT] Erreur LEAVE {group}: {e}", "red")

    def send_igmp_report(self, group, version=2):
        pkt = build_igmp_packet(0x16, group, version)
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            raw_sock.sendto(pkt, (group, 0))
            raw_sock.close()
            self.app.log(f"[CLIENT] IGMP Report envoyé pour {group}", "green_dim")
        except Exception as e:
            self.app.log(f"[CLIENT] Impossible d'envoyer IGMP Report (privilèges root/admin requis): {e}", "warning")

    def send_igmp_leave(self, group, version=2):
        pkt = build_igmp_packet(0x17, group, version)
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            raw_sock.sendto(pkt, (IGMP_ALL_ROUTERS, 0))
            raw_sock.close()
            self.app.log(f"[CLIENT] IGMP Leave envoyé pour {group}", "red_dim")
        except Exception as e:
            self.app.log(f"[CLIENT] Impossible d'envoyer IGMP Leave (privilèges root/admin requis): {e}", "warning")

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

    def __init__(self, app, interface):
        self.app = app
        self.interface = interface
        self.sock = None
        self.running = False
        self.igmp_table = defaultdict(set)  # group -> set of client IPs
        self.query_interval = 30

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
            self.app.log(f"[ROUTEUR] Privilèges root/admin requis pour les sockets RAW: {e}", "red")
            return False
        except Exception as e:
            self.app.log(f"[ROUTEUR] Erreur: {e}", "red")
            return False

    def listen_igmp(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                parsed = parse_igmp_packet(data)
                if parsed:
                    self.app.log(f"[ROUTEUR] IGMP reçu de {addr[0]}: {parsed['type_name']} pour {parsed['group']}", "orange")
                    self.update_table(parsed, addr[0])
            except Exception:
                if not self.running:
                    break

    def update_table(self, parsed, source_ip):
        group = parsed["group"]
        t = parsed["type"]
        if t in (0x12, 0x16, 0x22):  # Report
            if source_ip not in self.igmp_table[group]:
                self.igmp_table[group].add(source_ip)
                self.app.log(f"[ROUTEUR] Ajout de {source_ip} au groupe {group}", "green")
                self.app.update_router_table(self.igmp_table)
        elif t == 0x17:  # Leave
            if source_ip in self.igmp_table[group]:
                self.igmp_table[group].discard(source_ip)
                self.app.log(f"[ROUTEUR] Retrait de {source_ip} du groupe {group}", "red")
                self.app.update_router_table(self.igmp_table)

    def send_queries_loop(self):
        while self.running:
            time.sleep(self.query_interval)
            if not self.running:
                break
            self.send_general_query()

    def send_general_query(self):
        pkt = build_igmp_packet(0x11, "0.0.0.0", 2)
        try:
            self.sock.sendto(pkt, (IGMP_ALL_SYSTEMS, 0))
            self.app.log("[ROUTEUR] General Query envoyé", "green_dim")
        except Exception as e:
            self.app.log(f"[ROUTEUR] Erreur General Query: {e}", "red")

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.app.log("[ROUTEUR] Arrêté", "red")


class IGMPSwitch:
    """Switch avec IGMP Snooping : observe les IGMP et construit la table de ports."""

    def __init__(self, app, interface):
        self.app = app
        self.interface = interface
        self.sock = None
        self.running = False
        self.snooping_table = defaultdict(set)  # group -> set of source IPs

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            self.sock.bind((self.interface, 0))
            self.running = True
            threading.Thread(target=self.snoop_loop, daemon=True).start()
            self.app.log("[SWITCH] IGMP Snooping démarré", "green")
            return True
        except PermissionError as e:
            self.app.log(f"[SWITCH] Privilèges root/admin requis pour les sockets RAW: {e}", "red")
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
                    self.app.log(f"[SWITCH] Snoop IGMP de {addr[0]}: {parsed['type_name']} → {parsed['group']}", "magenta")
                    if parsed["type"] in (0x12, 0x16, 0x22):
                        self.snooping_table[parsed["group"]].add(addr[0])
                    elif parsed["type"] == 0x17:
                        self.snooping_table[parsed["group"]].discard(addr[0])
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


# ============ INTERFACE TKINTER ============
class IGMPSimulatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HACKERS_TCHAD (IGMP) - Simulateur Multicast Avancé")
        self.root.geometry("1400x900")
        self.root.configure(bg=THEME["bg"])
        self.root.minsize(1200, 750)

        self.role_vars = {}
        self.source = None
        self.client = None
        self.router = None
        self.switch = None
        self.stats = {"sent": 0, "received": 0, "igmp": 0}
        self.received_sources = defaultdict(int)

        self.style_widgets()
        self.build_ui()

    def style_widgets(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=THEME["bg"])
        style.configure("TButton",
                        background=THEME["green_dim"],
                        foreground=THEME["bg"],
                        font=("Consolas", 10, "bold"),
                        borderwidth=0,
                        relief="flat")
        style.map("TButton", background=[("active", THEME["green"])])
        style.configure("TEntry", fieldbackground=THEME["bg_tertiary"], foreground=THEME["green"],
                        insertcolor=THEME["green"], borderwidth=0)
        style.configure("TCombobox", fieldbackground=THEME["bg_tertiary"], foreground=THEME["green"])

    def build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=THEME["bg_secondary"], height=80,
                          highlightbackground=THEME["green"], highlightthickness=2)
        header.pack(fill=tk.X, padx=10, pady=10)
        header.pack_propagate(False)

        tk.Label(header, text="☠ HACKERS_TCHAD (IGMP)", bg=THEME["bg_secondary"],
                 fg=THEME["green"], font=("Consolas", 24, "bold")).pack(side=tk.LEFT, padx=20)
        tk.Label(header, text="Simulateur & Moniteur Multicast Avancé", bg=THEME["bg_secondary"],
                 fg=THEME["text_muted"], font=("Consolas", 12)).pack(side=tk.LEFT, padx=10)

        # Main content
        main = tk.Frame(self.root, bg=THEME["bg"])
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Left control panel
        left = tk.Frame(main, bg=THEME["bg_secondary"], width=420,
                        highlightbackground=THEME["green"], highlightthickness=1)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left.pack_propagate(False)

        self.build_role_panel(left)
        self.build_source_panel(left)
        self.build_client_panel(left)
        self.build_router_panel(left)
        self.build_switch_panel(left)

        # Right panel: logs and tables
        right = tk.Frame(main, bg=THEME["bg"])
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.build_log_area(right)
        self.build_tables_area(right)
        self.build_stats_area(right)

        # Footer
        footer = tk.Frame(self.root, bg=THEME["bg_secondary"], height=30,
                          highlightbackground=THEME["green_dim"], highlightthickness=1)
        footer.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=5)
        footer.pack_propagate(False)
        self.status_label = tk.Label(footer, text="HACKERS_TCHAD IGMP prêt", bg=THEME["bg_secondary"],
                                     fg=THEME["green"], font=("Consolas", 10), anchor="w", padx=10)
        self.status_label.pack(fill=tk.X)

    def build_role_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" RÔLES ACTIFS ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"),
                              highlightbackground=THEME["green"], highlightthickness=1)
        frame.pack(fill=tk.X, padx=10, pady=10)

        for role in ROLES:
            var = tk.BooleanVar(value=False)
            self.role_vars[role] = var
            cb = tk.Checkbutton(frame, text=role, variable=var,
                                bg=THEME["bg_secondary"], fg=THEME["text"],
                                selectcolor=THEME["green_dark"], activebackground=THEME["bg_secondary"],
                                activeforeground=THEME["green"], font=("Consolas", 10),
                                command=lambda r=role: self.toggle_role(r))
            cb.pack(anchor="w", padx=10, pady=3)

    def build_source_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" SOURCE / SERVEUR MULTICAST ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Groupe:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.src_group = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.src_group.insert(0, DEFAULT_MCAST_GROUP)
        self.src_group.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Port:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.src_port = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.src_port.insert(0, str(DEFAULT_MCAST_PORT))
        self.src_port.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(frame, text="Payload:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.src_payload = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.src_payload.insert(0, "HACKERS_TCHAD MULTICAST PACKET")
        self.src_payload.grid(row=2, column=1, padx=5, pady=5)

        btn_frame = tk.Frame(frame, bg=THEME["bg_secondary"])
        btn_frame.grid(row=3, column=0, columnspan=2, pady=8)
        tk.Button(btn_frame, text="Envoyer 1 paquet", bg=THEME["green_dim"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.send_one_packet).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Rafale 10x", bg=THEME["green"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.send_burst_packet).pack(side=tk.LEFT, padx=5)

    def build_client_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" CLIENT / HÔTE ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Groupe à rejoindre:", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.client_group = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.client_group.insert(0, DEFAULT_MCAST_GROUP)
        self.client_group.grid(row=0, column=1, padx=5, pady=5)

        btn_frame = tk.Frame(frame, bg=THEME["bg_secondary"])
        btn_frame.grid(row=1, column=0, columnspan=2, pady=8)
        tk.Button(btn_frame, text="JOIN (IGMP Report)", bg=THEME["green_dim"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.client_join).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="LEAVE (IGMP Leave)", bg=THEME["red_dim"], fg=THEME["text"],
                  font=("Consolas", 9, "bold"), command=self.client_leave).pack(side=tk.LEFT, padx=5)

    def build_router_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" ROUTEUR MULTICAST ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Intervalle Query (s):", bg=THEME["bg_secondary"], fg=THEME["text_muted"],
                 font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.router_interval = tk.Entry(frame, bg=THEME["bg_tertiary"], fg=THEME["green"], font=("Consolas", 10))
        self.router_interval.insert(0, "30")
        self.router_interval.grid(row=0, column=1, padx=5, pady=5)

        btn_frame = tk.Frame(frame, bg=THEME["bg_secondary"])
        btn_frame.grid(row=1, column=0, columnspan=2, pady=8)
        tk.Button(btn_frame, text="Envoyer General Query", bg=THEME["green_dim"], fg=THEME["bg"],
                  font=("Consolas", 9, "bold"), command=self.send_manual_query).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Vider Table", bg=THEME["red_dim"], fg=THEME["text"],
                  font=("Consolas", 9, "bold"), command=self.clear_router_table).pack(side=tk.LEFT, padx=5)

    def build_switch_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" SWITCH (IGMP Snooping) ", bg=THEME["bg_secondary"],
                              fg=THEME["green"], font=("Consolas", 11, "bold"))
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame, text="Le switch apprend dynamiquement les\nports IGMP à partir du trafic IGMP.",
                 bg=THEME["bg_secondary"], fg=THEME["text_muted"], font=("Consolas", 9),
                 justify=tk.LEFT).pack(padx=10, pady=5, anchor="w")
        tk.Button(frame, text="Vider Table Snooping", bg=THEME["red_dim"], fg=THEME["text"],
                  font=("Consolas", 9, "bold"), command=self.clear_switch_table).pack(pady=8)

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

        self.log_area.tag_config("green", foreground=THEME["green"])
        self.log_area.tag_config("green_dim", foreground=THEME["green_dim"])
        self.log_area.tag_config("red", foreground=THEME["red"])
        self.log_area.tag_config("red_dim", foreground=THEME["red_dim"])
        self.log_area.tag_config("cyan", foreground=THEME["cyan"])
        self.log_area.tag_config("magenta", foreground=THEME["magenta"])
        self.log_area.tag_config("orange", foreground=THEME["orange"])
        self.log_area.tag_config("warning", foreground=THEME["warning"])
        self.log_area.tag_config("system", foreground=THEME["text_muted"], font=("Consolas", 10, "italic"))

    def build_tables_area(self, parent):
        frame = tk.Frame(parent, bg=THEME["bg"])
        frame.pack(fill=tk.X, padx=5, pady=5)

        # Router table
        rt_frame = tk.LabelFrame(frame, text=" TABLE DE ROUTAGE MULTICAST ", bg=THEME["bg_secondary"],
                                 fg=THEME["green"], font=("Consolas", 10, "bold"))
        rt_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.router_table = tk.Listbox(rt_frame, bg=THEME["bg"], fg=THEME["green"],
                                       selectbackground=THEME["green_dark"], selectforeground=THEME["green"],
                                       font=("Consolas", 10), borderwidth=0, highlightthickness=0)
        self.router_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Switch table
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

        self.stats_label = tk.Label(frame, text="Paquets envoyés: 0 | Reçus: 0 | IGMP: 0",
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
                self.client = IGMPClient(self, DEFAULT_INTERFACE)
                self.client.start()
            else:
                if self.client:
                    self.client.stop()
                    self.client = None
        elif role == "Routeur Multicast":
            if enabled:
                self.router = IGMPRouter(self, DEFAULT_INTERFACE)
                self.router.start()
            else:
                if self.router:
                    self.router.stop()
                    self.router = None
        elif role == "Switch IGMP Snooping":
            if enabled:
                self.switch = IGMPSwitch(self, DEFAULT_INTERFACE)
                self.switch.start()
            else:
                if self.switch:
                    self.switch.stop()
                    self.switch = None

    def send_one_packet(self):
        if not self.source:
            messagebox.showwarning("Source inactive", "Activez le rôle Source/Serveur d'abord.")
            return
        payload = self.src_payload.get().strip()
        self.source.send_packet(payload)
        self.stats["sent"] += 1
        self.update_stats()

    def send_burst_packet(self):
        if not self.source:
            messagebox.showwarning("Source inactive", "Activez le rôle Source/Serveur d'abord.")
            return
        payload = self.src_payload.get().strip()
        self.source.send_burst(10, 200, payload)
        self.stats["sent"] += 10
        self.update_stats()

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

    def clear_router_table(self):
        if self.router:
            self.router.igmp_table.clear()
        self.update_router_table(defaultdict(set))
        self.log("[ROUTEUR] Table de routage vidée", "red_dim")

    def clear_switch_table(self):
        if self.switch:
            self.switch.snooping_table.clear()
        self.update_switch_table(defaultdict(set))
        self.log("[SWITCH] Table snooping vidée", "red_dim")

    # ============ MISES À JOUR UI ============
    def log(self, message, tag="green"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        full = f"[{timestamp}] {message}\n"

        def _append():
            self.log_area.config(state=tk.NORMAL)
            self.log_area.insert(tk.END, full, tag)
            self.log_area.config(state=tk.DISABLED)
            self.log_area.see(tk.END)
            self.status_label.config(text=message)

        try:
            self.root.after(0, _append)
        except Exception:
            pass

    def update_router_table(self, table):
        def _update():
            self.router_table.delete(0, tk.END)
            if not table:
                self.router_table.insert(tk.END, "(Aucun groupe multicast)")
                return
            for group, ips in sorted(table.items()):
                self.router_table.insert(tk.END, f"GROUPE {group}:")
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
                self.switch_table.insert(tk.END, f"VLAN/MCAST {group}:")
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
                text=f"Paquets envoyés: {self.stats['sent']} | Reçus: {self.stats['received']} | IGMP: {self.stats['igmp']}"
            )

        try:
            self.root.after(0, _update)
        except Exception:
            pass

    def on_close(self):
        if self.source:
            self.source.stop()
        if self.client:
            self.client.stop()
        if self.router:
            self.router.stop()
        if self.switch:
            self.switch.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = IGMPSimulatorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
