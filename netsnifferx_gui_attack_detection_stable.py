#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetSnifferX - Monitoramento e análise de conexões de rede em tempo real com interface gráfica, relatórios, alertas e DETECÇÃO DE ATAQUES
Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt
Versão: GUI com Detecção de Ataques (Base Estável: Usability)

Baseado em: netsnifferx_gui_alerts_usability.py (fornecido pelo usuário)

NOTA IMPORTANTE: Este script requer privilégios de administrador para capturar pacotes.
Execute com: python netsnifferx_gui_attack_detection_stable.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import datetime
import argparse
import queue
import os
import platform
import json
from collections import defaultdict, deque
# Importar camadas IP, TCP, UDP, ICMP e conf
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf 
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Importar winsound para alertas sonoros no Windows
if platform.system() == "Windows":
    try:
        import winsound
    except ImportError:
        print("Aviso: Módulo winsound não encontrado. Alertas sonoros podem não funcionar.")
        winsound = None
else:
    winsound = None

CONFIG_FILE = "netsnifferx_config.json"

# --- Configuração Padrão Atualizada ---
DEFAULT_CONFIG = {
    # Configs TCP existentes
    "timeout_threshold": 10, 
    "interface": "",
    "filter": "tcp or udp or icmp", # Atualizado para incluir UDP/ICMP
    "duration": 0,
    "enable_visual_alerts": True, # Alertas TCP
    "enable_sound_alerts": True, # Alertas TCP
    "severity_thresholds": { 
        "Baixo": 2,  
        "Médio": 5,  
        "Alto": 10  
    },
    "alert_sounds": { 
        "Baixo": "SystemAsterisk",
        "Médio": "SystemExclamation",
        "Alto": "SystemHand"
    },
    # Novas Configs de Detecção de Ataques
    "attack_detection_enabled": True,
    "port_scan_detection": {
        "enabled": True,
        "threshold_ports": 15, # Número de portas diferentes em X segundos
        "time_window_seconds": 10
    },
    "brute_force_detection": {
        "enabled": True,
        "ports_to_monitor": [21, 22, 23, 3389], # FTP, SSH, Telnet, RDP
        "threshold_failed_attempts": 5, # Tentativas falhas (SYN) em X segundos
        "time_window_seconds": 60
    },
    "flood_detection": {
        "enabled": True,
        "syn_flood_threshold_pps": 100, # Pacotes SYN por segundo para um destino
        "udp_flood_threshold_pps": 150, # Pacotes UDP por segundo para um destino
        "icmp_flood_threshold_pps": 100, # Pacotes ICMP por segundo para um destino
        "time_window_seconds": 5
    },
    "attack_alert_sound": "SystemHand", # Som padrão para alertas de ataque
    "attack_visual_alerts_enabled": True # Controle separado para pop-ups de ataque
}

# Mapeamento de tipos ICMP (igual à versão anterior)
ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench", 5: "Redirect",
    8: "Echo Request", 9: "Router Advertisement", 10: "Router Solicitation", 11: "Time Exceeded",
    12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply", 15: "Information Request",
    16: "Information Reply", 17: "Address Mask Request", 18: "Address Mask Reply"
}
ICMP_CODES_TYPE_3 = {
    0: "Net Unreachable", 1: "Host Unreachable", 2: "Protocol Unreachable", 3: "Port Unreachable",
    4: "Fragmentation Needed", 5: "Source Route Failed", 6: "Dest Network Unknown",
    7: "Dest Host Unknown", 8: "Source Host Isolated", 9: "Network Prohibited",
    10: "Host Prohibited", 11: "Network Unreachable for TOS", 12: "Host Unreachable for TOS",
    13: "Communication Prohibited", 14: "Host Precedence Violation", 15: "Precedence Cutoff"
}

def get_icmp_description(type_code):
    icmp_type, icmp_code = type_code
    type_desc = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
    code_desc = ""
    if icmp_type == 3:
        code_desc = f" (Code {icmp_code}: {ICMP_CODES_TYPE_3.get(icmp_code, 'Unknown')})"
    elif icmp_code != 0:
        code_desc = f" (Code {icmp_code})"
    return f"{type_desc}{code_desc}"

def load_config():
    """Carrega as configurações do arquivo JSON, mesclando com o padrão."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                # Mesclar com padrão para garantir novas chaves e subchaves
                updated_config = DEFAULT_CONFIG.copy()
                for key, value in config.items():
                    if key in updated_config and isinstance(updated_config[key], dict) and isinstance(value, dict):
                        # Mescla dicionários internos recursivamente (nível 1)
                        merged_dict = updated_config[key].copy()
                        merged_dict.update(value)
                        updated_config[key] = merged_dict
                    else:
                        updated_config[key] = value
                # Garantir que todas as chaves padrão existam
                for key, value in DEFAULT_CONFIG.items():
                    if key not in updated_config:
                        updated_config[key] = value
                    elif isinstance(value, dict):
                         if key not in updated_config or not isinstance(updated_config[key], dict):
                             updated_config[key] = value.copy()
                         else:
                             for sub_key, sub_value in value.items():
                                 if sub_key not in updated_config[key]:
                                     updated_config[key][sub_key] = sub_value
                return updated_config
        except Exception as e:
            print(f"Erro ao carregar config: {e}. Usando padrão.")
            return DEFAULT_CONFIG.copy()
    else:
        return DEFAULT_CONFIG.copy()

def save_config(config):
    """Salva as configurações no arquivo JSON."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Erro ao salvar config: {e}")

# --- Classe de Detecção de Ataques (Nova) --- 
class AttackDetector:
    def __init__(self, config, alert_callback):
        self.config = config
        self.alert_callback = alert_callback # Função para chamar quando um ataque é detectado
        self.lock = threading.Lock() # Lock para proteger acesso às estruturas
        
        # Estruturas para Port Scan
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set)) # src_ip -> {timestamp: {dst_port}} 
        self.port_scan_alerts = defaultdict(float) # src_ip -> last_alert_time
        
        # Estruturas para Brute Force (tentativas falhas TCP)
        self.brute_force_tracker = defaultdict(lambda: defaultdict(list)) # src_ip -> dst_port -> [timestamp_falha]
        self.brute_force_alerts = defaultdict(lambda: defaultdict(float)) # src_ip -> dst_port -> last_alert_time
        
        # Estruturas para Flood
        self.flood_tracker = defaultdict(lambda: defaultdict(list)) # dst_ip -> protocol -> [timestamp]
        self.flood_alerts = defaultdict(lambda: defaultdict(float)) # dst_ip -> protocol -> last_alert_time
        
        self.alert_cooldown_seconds = 60 # Evitar alertas repetidos muito rápido
        self.cleanup_interval_seconds = 30 # Intervalo para limpeza dos trackers
        self.last_cleanup_time = time.time()

    def update_config(self, new_config):
        with self.lock:
            self.config = new_config

    def process_packet(self, packet):
        # Roda em thread separada ou na fila, precisa de lock
        if not self.config.get("attack_detection_enabled", False) or IP not in packet:
            return
            
        current_time = time.time()
        
        # Limpeza periódica (menos frequente)
        if current_time - self.last_cleanup_time > self.cleanup_interval_seconds:
            self.cleanup_trackers(current_time)
            self.last_cleanup_time = current_time
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        with self.lock:
            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                self.check_port_scan(current_time, src_ip, dst_ip, dst_port, flags)
                self.check_brute_force(current_time, src_ip, dst_ip, dst_port, flags)
                self.check_flood(current_time, dst_ip, "SYN" if flags & 0x02 else None)
                
            elif UDP in packet:
                self.check_flood(current_time, dst_ip, "UDP")
                
            elif ICMP in packet:
                self.check_flood(current_time, dst_ip, "ICMP")

    def check_port_scan(self, current_time, src_ip, dst_ip, dst_port, flags):
        ps_config = self.config.get("port_scan_detection", {})
        if not ps_config.get("enabled", False):
            return
            
        is_scan_relevant = (flags & 0x02) # SYN flag
        
        if is_scan_relevant:
            window = ps_config.get("time_window_seconds", 10)
            threshold = ps_config.get("threshold_ports", 15)
            
            self.port_scan_tracker[src_ip][current_time].add(dst_port)
            
            ports_scanned = set()
            relevant_times = [t for t in self.port_scan_tracker[src_ip] if current_time - t <= window]
            for t in relevant_times:
                ports_scanned.update(self.port_scan_tracker[src_ip][t])
                
            if len(ports_scanned) >= threshold:
                last_alert = self.port_scan_alerts.get(src_ip, 0)
                if current_time - last_alert > self.alert_cooldown_seconds:
                    # Chamar callback fora do lock se possível, ou garantir que seja rápido
                    self.alert_callback("Port Scan", src_ip, f"Detectado escaneamento de {len(ports_scanned)} portas em {window}s", dst_ip)
                    self.port_scan_alerts[src_ip] = current_time

    def check_brute_force(self, current_time, src_ip, dst_ip, dst_port, flags):
        bf_config = self.config.get("brute_force_detection", {})
        if not bf_config.get("enabled", False):
            return
            
        monitored_ports = bf_config.get("ports_to_monitor", [])
        if dst_port not in monitored_ports:
            return
            
        is_failed_attempt = (flags & 0x02) # Contando SYNs como tentativas (básico)
        
        if is_failed_attempt:
            window = bf_config.get("time_window_seconds", 60)
            threshold = bf_config.get("threshold_failed_attempts", 5)
            
            self.brute_force_tracker[src_ip][dst_port].append(current_time)
            
            attempts_in_window = [t for t in self.brute_force_tracker[src_ip][dst_port] if current_time - t <= window]
            # Não precisa remover aqui, a limpeza periódica cuidará disso
            
            if len(attempts_in_window) >= threshold:
                last_alert = self.brute_force_alerts[src_ip].get(dst_port, 0)
                if current_time - last_alert > self.alert_cooldown_seconds:
                    self.alert_callback("Brute Force (Tentativa)", src_ip, f"Detectadas {len(attempts_in_window)} tentativas de conexão à porta {dst_port} em {window}s", dst_ip)
                    self.brute_force_alerts[src_ip][dst_port] = current_time

    def check_flood(self, current_time, dst_ip, packet_type):
        flood_config = self.config.get("flood_detection", {})
        if not flood_config.get("enabled", False) or packet_type is None:
            return
            
        window = flood_config.get("time_window_seconds", 5)
        threshold_pps = 0
        protocol_key = None
        
        if packet_type == "SYN":
            threshold_pps = flood_config.get("syn_flood_threshold_pps", 100)
            protocol_key = "SYN"
        elif packet_type == "UDP":
            threshold_pps = flood_config.get("udp_flood_threshold_pps", 150)
            protocol_key = "UDP"
        elif packet_type == "ICMP":
            threshold_pps = flood_config.get("icmp_flood_threshold_pps", 100)
            protocol_key = "ICMP"
            
        if not protocol_key or threshold_pps <= 0:
            return
            
        self.flood_tracker[dst_ip][protocol_key].append(current_time)
        
        packets_in_window = [t for t in self.flood_tracker[dst_ip][protocol_key] if current_time - t <= window]
        # Não precisa remover aqui, a limpeza periódica cuidará disso
        
        packet_rate = len(packets_in_window) / window if window > 0 else 0
        
        if packet_rate >= threshold_pps:
            last_alert = self.flood_alerts[dst_ip].get(protocol_key, 0)
            if current_time - last_alert > self.alert_cooldown_seconds:
                self.alert_callback(f"{protocol_key} Flood", f"Múltiplas Fontes (Taxa: {packet_rate:.1f} pps)", f"Detectado alto volume de pacotes {protocol_key} para o destino", dst_ip)
                self.flood_alerts[dst_ip][protocol_key] = current_time

    def cleanup_trackers(self, current_time):
        # Executa periodicamente, precisa de lock
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Executando limpeza dos trackers de ataque...")
        with self.lock:
            # Limpeza do Port Scan Tracker
            ps_window = self.config.get("port_scan_detection", {}).get("time_window_seconds", 10)
            for src_ip in list(self.port_scan_tracker.keys()):
                for ts in list(self.port_scan_tracker[src_ip].keys()):
                    if current_time - ts > ps_window * 1.5: # Manter um pouco mais que a janela
                        del self.port_scan_tracker[src_ip][ts]
                if not self.port_scan_tracker[src_ip]:
                    del self.port_scan_tracker[src_ip]
                    if src_ip in self.port_scan_alerts: del self.port_scan_alerts[src_ip]
                    
            # Limpeza do Brute Force Tracker
            bf_window = self.config.get("brute_force_detection", {}).get("time_window_seconds", 60)
            for src_ip in list(self.brute_force_tracker.keys()):
                for dst_port in list(self.brute_force_tracker[src_ip].keys()):
                    self.brute_force_tracker[src_ip][dst_port] = [t for t in self.brute_force_tracker[src_ip][dst_port] if current_time - t <= bf_window * 1.5]
                    if not self.brute_force_tracker[src_ip][dst_port]:
                        del self.brute_force_tracker[src_ip][dst_port]
                        if src_ip in self.brute_force_alerts and dst_port in self.brute_force_alerts[src_ip]:
                             del self.brute_force_alerts[src_ip][dst_port]
                if not self.brute_force_tracker[src_ip]:
                    del self.brute_force_tracker[src_ip]
                    if src_ip in self.brute_force_alerts: del self.brute_force_alerts[src_ip]
            
            # Limpeza do Flood Tracker
            flood_window = self.config.get("flood_detection", {}).get("time_window_seconds", 5)
            for dst_ip in list(self.flood_tracker.keys()):
                for protocol in list(self.flood_tracker[dst_ip].keys()):
                    self.flood_tracker[dst_ip][protocol] = [t for t in self.flood_tracker[dst_ip][protocol] if current_time - t <= flood_window * 1.5]
                    if not self.flood_tracker[dst_ip][protocol]:
                        del self.flood_tracker[dst_ip][protocol]
                        if dst_ip in self.flood_alerts and protocol in self.flood_alerts[dst_ip]:
                            del self.flood_alerts[dst_ip][protocol]
                if not self.flood_tracker[dst_ip]:
                    del self.flood_tracker[dst_ip]
                    if dst_ip in self.flood_alerts: del self.flood_alerts[dst_ip]
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Limpeza dos trackers concluída.")

# --- Classes da GUI (ConnectionTracker, ReportWindow, AlertConfigWindow) --- 
# (Copiar as classes ConnectionTracker, ConnectionReportWindow, AlertConfigWindow da versão anterior: netsnifferx_gui_alerts_usability.py)
# ConnectionTracker precisa ser modificado para lidar com IP
class ConnectionTracker:
    """
    Classe responsável por rastrear e gerenciar conexões TCP ativas.
    """
    def __init__(self, config):
        self.config = config
        self.connections = {}  
        self.connection_history = {}  
        self.max_history_packets = 100  
        
    def get_connection_id(self, packet):
        # Agora usa a camada IP
        if TCP in packet and IP in packet: 
            return (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
        return None
    
    def store_packet_history(self, conn_id, packet):
        if conn_id not in self.connection_history:
            self.connection_history[conn_id] = []
            
        packet_info = {
            'timestamp': time.time(),
            'flags': packet[TCP].flags,
            'size': len(packet),
            'seq': packet[TCP].seq if hasattr(packet[TCP], 'seq') else 0,
            'ack': packet[TCP].ack if hasattr(packet[TCP], 'ack') else 0,
            'window': packet[TCP].window if hasattr(packet[TCP], 'window') else 0
        }
        
        if len(self.connection_history[conn_id]) >= self.max_history_packets:
            self.connection_history[conn_id].pop(0)
            
        self.connection_history[conn_id].append(packet_info)
    
    def track_packet(self, packet):
        # Esta função agora só processa TCP
        if TCP not in packet or IP not in packet:
            return None
        
        conn_id = self.get_connection_id(packet)
        if not conn_id:
            return None
        
        self.store_packet_history(conn_id, packet)
        
        current_time = time.time()
        flags = packet[TCP].flags
        timeout_threshold = self.config["timeout_threshold"]
        
        if flags & 0x02:  # SYN flag
            self.connections[conn_id] = {
                'start_time': current_time,
                'last_update': current_time,
                'status': 'INICIANDO',
                'packets': 1,
                'flags_history': [flags],
                'alert_triggered': False
            }
            return {
                'protocol': 'TCP',
                'id': conn_id,
                'status': 'INICIANDO',
                'duration': 0,
                'is_suspicious': False,
                'packet_count': 1,
                'severity': 'Normal'
            }
        
        elif (flags & 0x01) or (flags & 0x04):  # FIN or RST flags
            if conn_id in self.connections:
                self.connections[conn_id]['flags_history'].append(flags)
                duration = current_time - self.connections[conn_id]['start_time']
                is_suspicious = duration > timeout_threshold
                status = 'FINALIZADA'
                packet_count = self.connections[conn_id]['packets']
                severity = self.calculate_severity(duration)
                
                result = {
                    'protocol': 'TCP',
                    'id': conn_id,
                    'status': status,
                    'duration': duration,
                    'is_suspicious': is_suspicious,
                    'packet_count': packet_count,
                    'flags_history': self.connections[conn_id]['flags_history'],
                    'severity': severity
                }
                del self.connections[conn_id]
                # Manter histórico por um tempo?
                # if conn_id in self.connection_history: del self.connection_history[conn_id]
                return result
            else: # FIN/RST sem SYN prévio - ignorar
                return None
        
        elif conn_id in self.connections:
            self.connections[conn_id]['last_update'] = current_time
            self.connections[conn_id]['packets'] += 1
            self.connections[conn_id]['flags_history'].append(flags)
            
            duration = current_time - self.connections[conn_id]['start_time']
            is_suspicious = duration > timeout_threshold
            severity = self.calculate_severity(duration)
            
            if is_suspicious and self.connections[conn_id]['status'] != 'SUSPEITA':
                self.connections[conn_id]['status'] = 'SUSPEITA'
            elif not is_suspicious and self.connections[conn_id]['status'] == 'INICIANDO': # Transição de iniciando para em andamento
                 self.connections[conn_id]['status'] = 'EM ANDAMENTO'
                 
            trigger_alert = False
            if is_suspicious and not self.connections[conn_id]['alert_triggered']:
                trigger_alert = True
                self.connections[conn_id]['alert_triggered'] = True
            
            return {
                'protocol': 'TCP',
                'id': conn_id,
                'status': self.connections[conn_id]['status'],
                'duration': duration,
                'is_suspicious': is_suspicious,
                'packet_count': self.connections[conn_id]['packets'],
                'flags_history': self.connections[conn_id]['flags_history'],
                'severity': severity,
                'trigger_alert': trigger_alert
            }
        
        else:
            # Pacote TCP não SYN/FIN/RST para uma conexão não rastreada
            # Ignorar para manter a lógica de rastreamento baseada em SYN
            return None
    
    def calculate_severity(self, duration):
        timeout_threshold = self.config["timeout_threshold"]
        severity_thresholds = self.config["severity_thresholds"]
        
        if duration <= timeout_threshold:
            return 'Normal'
        elif duration <= timeout_threshold * severity_thresholds["Baixo"]:
            return 'Baixo'
        elif duration <= timeout_threshold * severity_thresholds["Médio"]:
            return 'Médio'
        else:
            return 'Alto'
    
    def get_connection_details(self, conn_id):
        # Esta função continua focada em TCP
        timeout_threshold = self.config["timeout_threshold"]
        
        if conn_id in self.connections:
            conn = self.connections[conn_id]
            current_time = time.time()
            duration = current_time - conn['start_time']
            severity = self.calculate_severity(duration)
            
            details = {
                'protocol': 'TCP',
                'id': conn_id,
                'start_time': conn['start_time'],
                'last_update': conn['last_update'],
                'status': conn['status'],
                'duration': duration,
                'packet_count': conn['packets'],
                'is_suspicious': duration > timeout_threshold,
                'flags_history': conn['flags_history'],
                'threshold': timeout_threshold,
                'severity': severity
            }
            
            if conn_id in self.connection_history:
                details['packet_history'] = self.connection_history[conn_id]
            else:
                details['packet_history'] = []
                
            return details
            
        elif conn_id in self.connection_history:
            packets = self.connection_history[conn_id]
            if not packets:
                return None
                
            first_packet = packets[0]
            last_packet = packets[-1]
            duration = last_packet['timestamp'] - first_packet['timestamp']
            severity = self.calculate_severity(duration)
            
            details = {
                'protocol': 'TCP',
                'id': conn_id,
                'start_time': first_packet['timestamp'],
                'last_update': last_packet['timestamp'],
                'status': 'FINALIZADA (Histórico)', 
                'duration': duration,
                'packet_count': len(packets),
                'is_suspicious': duration > timeout_threshold,
                'flags_history': [p['flags'] for p in packets],
                'threshold': timeout_threshold,
                'packet_history': packets,
                'severity': severity
            }
            
            return details
            
        return None

# ConnectionReportWindow e AlertConfigWindow (TCP) são idênticas à versão usability
# ... (código omitido por brevidade, mas deve ser incluído aqui) ...
class ConnectionReportWindow:
    """
    Janela de relatório detalhado para conexões suspeitas.
    """
    def __init__(self, parent, connection_details):
        self.parent = parent
        self.details = connection_details
        
        self.window = tk.Toplevel(parent)
        self.window.title("Relatório Detalhado de Conexão TCP") # Título específico TCP
        self.window.geometry("800x600")
        self.window.minsize(700, 500)
        self.window.transient(parent)
        self.window.grab_set()
        
        self.style = ttk.Style()
        self.style.configure("Title.TLabel", font=("Arial", 12, "bold"))
        self.style.configure("Header.TLabel", font=("Arial", 10, "bold"))
        
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        title_text = f"Conexão TCP: {src_ip}:{src_port} → {dst_ip}:{dst_port}"
        title_label = ttk.Label(main_frame, text=title_text, style="Title.TLabel")
        title_label.pack(fill=tk.X, pady=(0, 10))
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        summary_frame = ttk.Frame(notebook, padding="10")
        notebook.add(summary_frame, text="Resumo")
        self.create_summary_tab(summary_frame)
        
        analysis_frame = ttk.Frame(notebook, padding="10")
        notebook.add(analysis_frame, text="Análise de Suspeita")
        self.create_analysis_tab(analysis_frame)
        
        details_frame = ttk.Frame(notebook, padding="10")
        notebook.add(details_frame, text="Detalhes Técnicos")
        self.create_details_tab(details_frame)
        
        recommendations_frame = ttk.Frame(notebook, padding="10")
        notebook.add(recommendations_frame, text="Recomendações")
        self.create_recommendations_tab(recommendations_frame)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        export_button = ttk.Button(button_frame, text="Exportar Relatório", command=self.export_report)
        export_button.pack(side=tk.LEFT, padx=(0, 5))
        
        close_button = ttk.Button(button_frame, text="Fechar", command=self.window.destroy)
        close_button.pack(side=tk.LEFT)
        
    def create_summary_tab(self, parent):
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        
        info_frame = ttk.LabelFrame(parent, text="Informações da Conexão TCP", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, text="IP de Origem:", style="Header.TLabel").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=src_ip).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text="Porta de Origem:", style="Header.TLabel").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=str(src_port)).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text="IP de Destino:", style="Header.TLabel").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=dst_ip).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text="Porta de Destino:", style="Header.TLabel").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=str(dst_port)).grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text="Status:", style="Header.TLabel").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        status_label = ttk.Label(info_frame, text=self.details['status'])
        status_label.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        if self.details['is_suspicious']:
            status_label.configure(foreground="red")
        elif self.details['status'] == 'FINALIZADA' or self.details['status'] == 'FINALIZADA (Histórico)':
            status_label.configure(foreground="green")
        elif self.details['status'] == 'INICIANDO':
            status_label.configure(foreground="blue")
        
        ttk.Label(info_frame, text="Duração:", style="Header.TLabel").grid(row=2, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"{self.details['duration']:.2f} segundos").grid(row=2, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text="Pacotes:", style="Header.TLabel").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=str(self.details['packet_count'])).grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text="Início:", style="Header.TLabel").grid(row=3, column=2, sticky=tk.W, padx=5, pady=2)
        start_time_str = datetime.datetime.fromtimestamp(self.details['start_time']).strftime('%H:%M:%S')
        ttk.Label(info_frame, text=start_time_str).grid(row=3, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text="Gravidade:", style="Header.TLabel").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        severity_label = ttk.Label(info_frame, text=self.details['severity'])
        severity_label.grid(row=4, column=1, sticky=tk.W, padx=5, pady=2)
        
        if self.details['severity'] == 'Alto':
            severity_label.configure(foreground="red")
        elif self.details['severity'] == 'Médio':
            severity_label.configure(foreground="orange")
        elif self.details['severity'] == 'Baixo':
            severity_label.configure(foreground="#CCCC00") # Amarelo escuro
        
        if self.details['is_suspicious']:
            suspicion_frame = ttk.LabelFrame(parent, text="Resumo da Suspeita", padding="10")
            suspicion_frame.pack(fill=tk.X, pady=(0, 10))
            suspicion_text = f"Esta conexão TCP foi marcada como suspeita porque sua duração ({self.details['duration']:.2f} segundos) " \
                            f"excede o limite configurado de {self.details['threshold']} segundos."
            suspicion_label = ttk.Label(suspicion_frame, text=suspicion_text, wraplength=700)
            suspicion_label.pack(fill=tk.X)
        
        graph_frame = ttk.LabelFrame(parent, text="Duração da Conexão TCP", padding="10")
        graph_frame.pack(fill=tk.BOTH, expand=True)
        fig, ax = plt.subplots(figsize=(5, 3))
        durations = [self.details['duration']]
        threshold = [self.details['threshold']]
        labels = ['Duração Atual']
        bars = ax.bar(labels, durations, color='blue')
        ax.axhline(y=self.details['threshold'], color='red', linestyle='--', label=f'Threshold ({self.details["threshold"]}s)')
        if self.details['is_suspicious']:
            bars[0].set_color('red')
        ax.set_ylabel('Segundos')
        ax.set_title('Duração vs. Threshold')
        ax.legend()
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_analysis_tab(self, parent):
        analysis_frame = ttk.Frame(parent)
        analysis_frame.pack(fill=tk.BOTH, expand=True)
        
        if self.details['is_suspicious']:
            reason_frame = ttk.LabelFrame(analysis_frame, text="Motivo da Suspeita (TCP)", padding="10")
            reason_frame.pack(fill=tk.X, pady=(0, 10))
            reason_text = "Esta conexão TCP foi classificada como suspeita pelos seguintes motivos:\n\n" \
                        f"1. Duração excessiva: {self.details['duration']:.2f} segundos (limite: {self.details['threshold']} segundos)\n"
            flags_history = self.details.get('flags_history', [])
            if flags_history:
                syn_count = sum(1 for f in flags_history if f & 0x02)
                fin_count = sum(1 for f in flags_history if f & 0x01)
                rst_count = sum(1 for f in flags_history if f & 0x04)
                if syn_count > 1:
                    reason_text += f"2. Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão\n"
                if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA' and self.details['status'] != 'FINALIZADA (Histórico)':
                    reason_text += "3. Conexão não finalizada corretamente (sem flags FIN ou RST)\n"
            reason_label = ttk.Label(reason_frame, text=reason_text, wraplength=700, justify=tk.LEFT)
            reason_label.pack(fill=tk.X)
        
        flags_frame = ttk.LabelFrame(analysis_frame, text="Histórico de Flags TCP", padding="10")
        flags_frame.pack(fill=tk.X, pady=(0, 10))
        flags_text = ttk.Label(flags_frame, text="Sequência de flags TCP observados nesta conexão:", wraplength=700)
        flags_text.pack(fill=tk.X, pady=(0, 5))
        flags_display = scrolledtext.ScrolledText(flags_frame, wrap=tk.WORD, height=5)
        flags_display.pack(fill=tk.X)
        flags_history = self.details.get('flags_history', [])
        if flags_history:
            flags_display.insert(tk.END, "Sequência de flags (mais recentes por último):\n")
            for i, flags in enumerate(flags_history):
                flag_str = self.format_tcp_flags(flags)
                flags_display.insert(tk.END, f"{i+1}. {flag_str}\n")
        else:
            flags_display.insert(tk.END, "Nenhum histórico de flags disponível para esta conexão.")
        flags_display.config(state=tk.DISABLED)
        
        if 'packet_history' in self.details and self.details['packet_history']:
            activity_frame = ttk.LabelFrame(analysis_frame, text="Atividade da Conexão TCP", padding="10")
            activity_frame.pack(fill=tk.BOTH, expand=True)
            fig, ax = plt.subplots(figsize=(5, 3))
            history = self.details['packet_history']
            timestamps = [p['timestamp'] - self.details['start_time'] for p in history]
            sizes = [p['size'] for p in history]
            ax.plot(timestamps, sizes, 'o-', label='Tamanho do Pacote')
            ax.axvline(x=self.details['threshold'], color='red', linestyle='--', label=f'Threshold ({self.details["threshold"]}s)')
            ax.set_xlabel('Tempo (segundos)')
            ax.set_ylabel('Tamanho do Pacote (bytes)')
            ax.set_title('Atividade da Conexão ao Longo do Tempo')
            ax.legend()
            canvas = FigureCanvasTkAgg(fig, master=activity_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_details_tab(self, parent):
        details_frame = ttk.Frame(parent)
        details_frame.pack(fill=tk.BOTH, expand=True)
        packets_frame = ttk.LabelFrame(details_frame, text="Histórico de Pacotes TCP", padding="10")
        packets_frame.pack(fill=tk.BOTH, expand=True)
        header_frame = ttk.Frame(packets_frame)
        header_frame.pack(fill=tk.X)
        ttk.Label(header_frame, text="#", width=5, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Tempo", width=10, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Flags", width=15, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Tamanho", width=10, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="SEQ", width=12, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="ACK", width=12, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Window", width=10, style="Header.TLabel").pack(side=tk.LEFT)
        packets_display = scrolledtext.ScrolledText(packets_frame, wrap=tk.WORD, height=15)
        packets_display.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        if 'packet_history' in self.details and self.details['packet_history']:
            history = self.details['packet_history']
            for i, packet in enumerate(history):
                rel_time = packet['timestamp'] - self.details['start_time']
                flag_str = self.format_tcp_flags(packet['flags'])
                line = f"{i+1:<5} {rel_time:<10.2f} {flag_str:<15} {packet['size']:<10} "
                line += f"{packet['seq']:<12} {packet['ack']:<12} {packet['window']:<10}\n"
                if rel_time > self.details['threshold']:
                    packets_display.insert(tk.END, line, "suspicious")
                else:
                    packets_display.insert(tk.END, line)
            packets_display.tag_config("suspicious", foreground="red")
        else:
            packets_display.insert(tk.END, "Nenhum histórico de pacotes TCP disponível para esta conexão.")
        packets_display.config(state=tk.DISABLED)
        
    def create_recommendations_tab(self, parent):
        recommendations_frame = ttk.Frame(parent)
        recommendations_frame.pack(fill=tk.BOTH, expand=True)
        actions_frame = ttk.LabelFrame(recommendations_frame, text="Ações Recomendadas (TCP)", padding="10")
        actions_frame.pack(fill=tk.X, pady=(0, 10))
        if self.details['is_suspicious']:
            actions_text = "Com base na análise desta conexão TCP, recomendamos as seguintes ações:\n\n"
            if self.details['duration'] > self.details['threshold'] * 2:
                actions_text += "1. Investigar o motivo da duração extremamente longa desta conexão\n"
                actions_text += "2. Verificar se esta é uma conexão legítima ou uma tentativa de manter um canal aberto indevidamente\n"
                actions_text += "3. Considerar ajustar as configurações de timeout no servidor ou firewall\n"
            else:
                actions_text += "1. Monitorar esta conexão para verificar se é um comportamento normal para esta aplicação\n"
                actions_text += "2. Considerar ajustar o threshold de detecção se este for um comportamento esperado\n"
            flags_history = self.details.get('flags_history', [])
            if flags_history:
                syn_count = sum(1 for f in flags_history if f & 0x02)
                if syn_count > 1:
                    actions_text += f"4. Investigar as múltiplas tentativas de iniciar conexão (SYN), possível sinal de problemas de rede ou tentativa de ataque\n"
        else:
            actions_text = "Esta conexão TCP não foi classificada como suspeita. Nenhuma ação é necessária."
        actions_label = ttk.Label(actions_frame, text=actions_text, wraplength=700, justify=tk.LEFT)
        actions_label.pack(fill=tk.X)
        info_frame = ttk.LabelFrame(recommendations_frame, text="Informações Adicionais", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        info_text = "Para mais informações sobre análise de conexões TCP e segurança de rede, consulte:\n\n"
        info_text += "• RFC 793: Transmission Control Protocol\n"
        info_text += "• RFC 7414: A Roadmap for TCP Specification Documents\n"
        info_text += "• NIST SP 800-123: Guide to General Server Security\n"
        info_label = ttk.Label(info_frame, text=info_text, wraplength=700, justify=tk.LEFT)
        info_label.pack(fill=tk.X)
        
    def format_tcp_flags(self, flags):
        flag_map = {0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH', 0x10: 'ACK', 0x20: 'URG', 0x40: 'ECE', 0x80: 'CWR'}
        active_flags = [name for bit, name in flag_map.items() if flags & bit]
        return '+'.join(active_flags) if active_flags else 'NONE'
    
    def export_report(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivos de texto", "*.txt"), ("Arquivos HTML", "*.html"), ("Todos os arquivos", "*.*")],
            title="Salvar Relatório Como"
        )
        if not file_path:
            return
        try:
            if file_path.endswith('.html'):
                self.export_as_html(file_path)
            else:
                self.export_as_text(file_path)
            messagebox.showinfo("Exportação Concluída", f"Relatório exportado com sucesso para:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Erro na Exportação", f"Ocorreu um erro ao exportar o relatório:\n{e}")
    
    def export_as_text(self, file_path):
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"RELATÓRIO DETALHADO DE CONEXÃO TCP\n")
            f.write("=" * 80 + "\n\n")
            f.write("INFORMAÇÕES DA CONEXÃO\n")
            f.write("-" * 30 + "\n")
            f.write(f"IP de Origem: {src_ip}\n")
            f.write(f"Porta de Origem: {src_port}\n")
            f.write(f"IP de Destino: {dst_ip}\n")
            f.write(f"Porta de Destino: {dst_port}\n")
            f.write(f"Status: {self.details['status']}\n")
            f.write(f"Duração: {self.details['duration']:.2f} segundos\n")
            f.write(f"Pacotes: {self.details['packet_count']}\n")
            f.write(f"Início: {datetime.datetime.fromtimestamp(self.details['start_time']).strftime('%H:%M:%S')}\n")
            f.write(f"Suspeita: {'Sim' if self.details['is_suspicious'] else 'Não'}\n")
            f.write(f"Gravidade: {self.details['severity']}\n\n")
            if self.details['is_suspicious']:
                f.write("ANÁLISE DE SUSPEITA\n")
                f.write("-" * 30 + "\n")
                f.write(f"Esta conexão TCP foi classificada como suspeita porque sua duração ({self.details['duration']:.2f} segundos) ")
                f.write(f"excede o limite configurado de {self.details['threshold']} segundos.\n\n")
                flags_history = self.details.get('flags_history', [])
                if flags_history:
                    syn_count = sum(1 for f in flags_history if f & 0x02)
                    fin_count = sum(1 for f in flags_history if f & 0x01)
                    rst_count = sum(1 for f in flags_history if f & 0x04)
                    if syn_count > 1:
                        f.write(f"Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão\n")
                    if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA' and self.details['status'] != 'FINALIZADA (Histórico)':
                        f.write("Conexão não finalizada corretamente (sem flags FIN ou RST)\n")
                f.write("\n")
            f.write("HISTÓRICO DE FLAGS TCP\n")
            f.write("-" * 30 + "\n")
            flags_history = self.details.get('flags_history', [])
            if flags_history:
                f.write("Sequência de flags (mais recentes por último):\n")
                for i, flags in enumerate(flags_history):
                    flag_str = self.format_tcp_flags(flags)
                    f.write(f"{i+1}. {flag_str}\n")
            else:
                f.write("Nenhum histórico de flags disponível para esta conexão.\n")
            f.write("\n")
            f.write("HISTÓRICO DE PACOTES TCP\n")
            f.write("-" * 30 + "\n")
            if 'packet_history' in self.details and self.details['packet_history']:
                f.write(f"{'#':<5} {'Tempo':<10} {'Flags':<15} {'Tamanho':<10} {'SEQ':<12} {'ACK':<12} {'Window':<10}\n")
                f.write("-" * 80 + "\n")
                history = self.details['packet_history']
                for i, packet in enumerate(history):
                    rel_time = packet['timestamp'] - self.details['start_time']
                    flag_str = self.format_tcp_flags(packet['flags'])
                    line = f"{i+1:<5} {rel_time:<10.2f} {flag_str:<15} {packet['size']:<10} "
                    line += f"{packet['seq']:<12} {packet['ack']:<12} {packet['window']:<10}\n"
                    f.write(line)
            else:
                f.write("Nenhum histórico de pacotes TCP disponível para esta conexão.\n")
            f.write("\n")
            f.write("AÇÕES RECOMENDADAS (TCP)\n")
            f.write("-" * 30 + "\n")
            if self.details['is_suspicious']:
                f.write("Com base na análise desta conexão TCP, recomendamos as seguintes ações:\n\n")
                if self.details['duration'] > self.details['threshold'] * 2:
                    f.write("1. Investigar o motivo da duração extremamente longa desta conexão\n")
                    f.write("2. Verificar se esta é uma conexão legítima ou uma tentativa de manter um canal aberto indevidamente\n")
                    f.write("3. Considerar ajustar as configurações de timeout no servidor ou firewall\n")
                else:
                    f.write("1. Monitorar esta conexão para verificar se é um comportamento normal para esta aplicação\n")
                    f.write("2. Considerar ajustar o threshold de detecção se este for um comportamento esperado\n")
                if flags_history:
                    syn_count = sum(1 for f in flags_history if f & 0x02)
                    if syn_count > 1:
                        f.write(f"4. Investigar as múltiplas tentativas de iniciar conexão (SYN), possível sinal de problemas de rede ou tentativa de ataque\n")
            else:
                f.write("Esta conexão TCP não foi classificada como suspeita. Nenhuma ação é necessária.\n")
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("Relatório gerado pelo NetSnifferX\n")
            f.write(f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write("Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt\n")
            f.write("=" * 80 + "\n")
    
    def export_as_html(self, file_path):
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Relatório de Conexão TCP</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #3498db; margin-top: 20px; }
        .info-table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        .info-table th, .info-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .info-table th { background-color: #f2f2f2; }
        .suspicious { color: red; }
        .normal { color: green; }
        .severity-Alto { color: red; font-weight: bold; }
        .severity-Médio { color: orange; }
        .severity-Baixo { color: #CCCC00; }
        .packet-table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        .packet-table th, .packet-table td { border: 1px solid #ddd; padding: 6px; text-align: left; font-size: 0.9em; }
        .packet-table th { background-color: #f2f2f2; }
        .packet-row-suspicious { background-color: #ffeeee; }
        .footer { margin-top: 30px; border-top: 1px solid #ddd; padding-top: 10px; font-size: 0.8em; color: #777; }
    </style>
</head>
<body>
""")
            f.write(f"<h1>Relatório Detalhado de Conexão TCP</h1>\n")
            f.write("<h2>Informações da Conexão</h2>\n")
            f.write("<table class='info-table'>\n")
            f.write("  <tr><th>IP de Origem</th><td>" + src_ip + "</td><th>Porta de Origem</th><td>" + str(src_port) + "</td></tr>\n")
            f.write("  <tr><th>IP de Destino</th><td>" + dst_ip + "</td><th>Porta de Destino</th><td>" + str(dst_port) + "</td></tr>\n")
            status_class = "suspicious" if self.details['is_suspicious'] else "normal"
            f.write(f"  <tr><th>Status</th><td class='{status_class}'>{self.details['status']}</td>")
            f.write(f"<th>Duração</th><td>{self.details['duration']:.2f} segundos</td></tr>\n")
            f.write(f"  <tr><th>Pacotes</th><td>{self.details['packet_count']}</td>")
            start_time_str = datetime.datetime.fromtimestamp(self.details['start_time']).strftime('%H:%M:%S')
            f.write(f"<th>Início</th><td>{start_time_str}</td></tr>\n")
            suspicion_text = "Sim" if self.details['is_suspicious'] else "Não"
            suspicion_class = "suspicious" if self.details['is_suspicious'] else "normal"
            f.write(f"  <tr><th>Suspeita</th><td class='{suspicion_class}'>{suspicion_text}</td>")
            f.write(f"<th>Threshold</th><td>{self.details['threshold']} segundos</td></tr>\n")
            severity_class = f"severity-{self.details['severity']}"
            f.write(f"  <tr><th>Gravidade</th><td class='{severity_class}'>{self.details['severity']}</td><td colspan='2'></td></tr>\n")
            f.write("</table>\n")
            if self.details['is_suspicious']:
                f.write("<h2>Análise de Suspeita</h2>\n")
                f.write("<p>Esta conexão TCP foi classificada como suspeita pelos seguintes motivos:</p>\n")
                f.write("<ul>\n")
                f.write(f"  <li>Duração excessiva: {self.details['duration']:.2f} segundos (limite: {self.details['threshold']} segundos)</li>\n")
                flags_history = self.details.get('flags_history', [])
                if flags_history:
                    syn_count = sum(1 for f in flags_history if f & 0x02)
                    fin_count = sum(1 for f in flags_history if f & 0x01)
                    rst_count = sum(1 for f in flags_history if f & 0x04)
                    if syn_count > 1:
                        f.write(f"  <li>Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão</li>\n")
                    if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA' and self.details['status'] != 'FINALIZADA (Histórico)':
                        f.write("  <li>Conexão não finalizada corretamente (sem flags FIN ou RST)</li>\n")
                f.write("</ul>\n")
            f.write("<h2>Histórico de Flags TCP</h2>\n")
            flags_history = self.details.get('flags_history', [])
            if flags_history:
                f.write("<p>Sequência de flags (mais recentes por último):</p>\n")
                f.write("<ol>\n")
                for flags in flags_history:
                    flag_str = self.format_tcp_flags(flags)
                    f.write(f"  <li>{flag_str}</li>\n")
                f.write("</ol>\n")
            else:
                f.write("<p>Nenhum histórico de flags disponível para esta conexão.</p>\n")
            f.write("<h2>Histórico de Pacotes TCP</h2>\n")
            if 'packet_history' in self.details and self.details['packet_history']:
                f.write("<table class='packet-table'>\n")
                f.write("  <tr><th>#</th><th>Tempo (s)</th><th>Flags</th><th>Tamanho</th><th>SEQ</th><th>ACK</th><th>Window</th></tr>\n")
                history = self.details['packet_history']
                for i, packet in enumerate(history):
                    rel_time = packet['timestamp'] - self.details['start_time']
                    flag_str = self.format_tcp_flags(packet['flags'])
                    row_class = "packet-row-suspicious" if rel_time > self.details['threshold'] else ""
                    f.write(f"  <tr class='{row_class}'><td>{i+1}</td><td>{rel_time:.2f}</td><td>{flag_str}</td>")
                    f.write(f"<td>{packet['size']}</td><td>{packet['seq']}</td><td>{packet['ack']}</td><td>{packet['window']}</td></tr>\n")
                f.write("</table>\n")
            else:
                f.write("<p>Nenhum histórico de pacotes TCP disponível para esta conexão.</p>\n")
            f.write("<h2>Ações Recomendadas (TCP)</h2>\n")
            if self.details['is_suspicious']:
                f.write("<p>Com base na análise desta conexão TCP, recomendamos as seguintes ações:</p>\n")
                f.write("<ol>\n")
                if self.details['duration'] > self.details['threshold'] * 2:
                    f.write("  <li>Investigar o motivo da duração extremamente longa desta conexão</li>\n")
                    f.write("  <li>Verificar se esta é uma conexão legítima ou uma tentativa de manter um canal aberto indevidamente</li>\n")
                    f.write("  <li>Considerar ajustar as configurações de timeout no servidor ou firewall</li>\n")
                else:
                    f.write("  <li>Monitorar esta conexão para verificar se é um comportamento normal para esta aplicação</li>\n")
                    f.write("  <li>Considerar ajustar o threshold de detecção se este for um comportamento esperado</li>\n")
                if flags_history:
                    syn_count = sum(1 for f in flags_history if f & 0x02)
                    if syn_count > 1:
                        f.write(f"  <li>Investigar as múltiplas tentativas de iniciar conexão (SYN), possível sinal de problemas de rede ou tentativa de ataque</li>\n")
                f.write("</ol>\n")
            else:
                f.write("<p>Esta conexão TCP não foi classificada como suspeita. Nenhuma ação é necessária.</p>\n")
            f.write("<div class='footer'>\n")
            f.write(f"  <p>Relatório gerado pelo NetSnifferX em {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>\n")
            f.write("  <p>Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt</p>\n")
            f.write("</div>\n")
            f.write("</body>\n</html>")

class AlertConfigWindow:
    """
    Janela de configuração para os alertas de conexões TCP suspeitas.
    """
    def __init__(self, parent, config, callback):
        self.parent = parent
        self.config = config
        self.callback = callback # Função para chamar ao salvar
        
        self.window = tk.Toplevel(parent)
        self.window.title("Configurações de Alerta (TCP)") # Título específico TCP
        self.window.geometry("500x400")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Variáveis Tkinter
        self.enable_visual = tk.BooleanVar(value=self.config["enable_visual_alerts"])
        self.enable_sound = tk.BooleanVar(value=self.config["enable_sound_alerts"])
        self.threshold_low = tk.DoubleVar(value=self.config["severity_thresholds"]["Baixo"])
        self.threshold_medium = tk.DoubleVar(value=self.config["severity_thresholds"]["Médio"])
        self.threshold_high = tk.DoubleVar(value=self.config["severity_thresholds"]["Alto"])
        self.sound_low = tk.StringVar(value=self.config["alert_sounds"]["Baixo"])
        self.sound_medium = tk.StringVar(value=self.config["alert_sounds"]["Médio"])
        self.sound_high = tk.StringVar(value=self.config["alert_sounds"]["Alto"])
        
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Configurações Gerais ---
        general_frame = ttk.LabelFrame(main_frame, text="Geral (Alertas TCP)", padding="10")
        general_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Checkbutton(general_frame, text="Habilitar Alertas Visuais (Pop-up)", variable=self.enable_visual).pack(anchor=tk.W)
        ttk.Checkbutton(general_frame, text="Habilitar Alertas Sonoros", variable=self.enable_sound).pack(anchor=tk.W)
        
        # --- Níveis de Gravidade ---
        severity_frame = ttk.LabelFrame(main_frame, text="Níveis de Gravidade (Multiplicador do Threshold Base TCP)", padding="10")
        severity_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(severity_frame, text="Baixo (x Threshold):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(severity_frame, from_=1.1, to=10.0, increment=0.1, textvariable=self.threshold_low, width=5).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(severity_frame, text="Médio (x Threshold):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(severity_frame, from_=1.2, to=20.0, increment=0.1, textvariable=self.threshold_medium, width=5).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(severity_frame, text="Alto (x Threshold):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(severity_frame, from_=1.3, to=50.0, increment=0.1, textvariable=self.threshold_high, width=5).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # --- Sons de Alerta (Windows) ---
        if winsound:
            sound_frame = ttk.LabelFrame(main_frame, text="Sons de Alerta (Padrão do Windows)", padding="10")
            sound_frame.pack(fill=tk.X, pady=(0, 10))
            
            # Opções de som padrão do Windows
            sound_options = ["SystemAsterisk", "SystemExclamation", "SystemHand", "SystemQuestion", "SystemDefault"]
            
            ttk.Label(sound_frame, text="Baixo:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            ttk.Combobox(sound_frame, textvariable=self.sound_low, values=sound_options, state="readonly").grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
            ttk.Button(sound_frame, text="Testar", command=lambda: self.play_sound(self.sound_low.get())).grid(row=0, column=2, padx=5)
            
            ttk.Label(sound_frame, text="Médio:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
            ttk.Combobox(sound_frame, textvariable=self.sound_medium, values=sound_options, state="readonly").grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
            ttk.Button(sound_frame, text="Testar", command=lambda: self.play_sound(self.sound_medium.get())).grid(row=1, column=2, padx=5)
            
            ttk.Label(sound_frame, text="Alto:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
            ttk.Combobox(sound_frame, textvariable=self.sound_high, values=sound_options, state="readonly").grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
            ttk.Button(sound_frame, text="Testar", command=lambda: self.play_sound(self.sound_high.get())).grid(row=2, column=2, padx=5)
        else:
            ttk.Label(main_frame, text="Alertas sonoros não disponíveis neste sistema.").pack()
            
        # --- Botões ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        save_button = ttk.Button(button_frame, text="Salvar", command=self.save_and_close)
        save_button.pack(side=tk.RIGHT)
        
        cancel_button = ttk.Button(button_frame, text="Cancelar", command=self.window.destroy)
        cancel_button.pack(side=tk.RIGHT, padx=(0, 5))
        
    def play_sound(self, sound_alias):
        if winsound:
            try:
                winsound.PlaySound(sound_alias, winsound.SND_ALIAS | winsound.SND_ASYNC)
            except Exception as e:
                messagebox.showerror("Erro de Som", f"Não foi possível tocar o som '{sound_alias}':\n{e}")
        
    def save_and_close(self):
        low = self.threshold_low.get()
        medium = self.threshold_medium.get()
        high = self.threshold_high.get()
        
        if not (1 < low < medium < high):
            messagebox.showerror("Erro de Validação", "Os thresholds de gravidade devem ser crescentes e maiores que 1.")
            return
            
        self.config["enable_visual_alerts"] = self.enable_visual.get()
        self.config["enable_sound_alerts"] = self.enable_sound.get()
        self.config["severity_thresholds"]["Baixo"] = low
        self.config["severity_thresholds"]["Médio"] = medium
        self.config["severity_thresholds"]["Alto"] = high
        self.config["alert_sounds"]["Baixo"] = self.sound_low.get()
        self.config["alert_sounds"]["Médio"] = self.sound_medium.get()
        self.config["alert_sounds"]["Alto"] = self.sound_high.get()
        
        self.callback(self.config)
        self.window.destroy()

# --- Janela de Configuração de Ataques (NOVA) --- 
class AttackConfigWindow:
    def __init__(self, parent, config, callback):
        self.parent = parent
        self.config = config
        self.callback = callback
        
        self.window = tk.Toplevel(parent)
        self.window.title("Configurações de Detecção de Ataques")
        self.window.geometry("650x550") # Maior
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Variáveis Tkinter
        self.attack_detection_enabled = tk.BooleanVar(value=self.config.get("attack_detection_enabled", True))
        self.attack_visual_alerts_enabled = tk.BooleanVar(value=self.config.get("attack_visual_alerts_enabled", True))
        
        # Port Scan
        ps_conf = self.config.get("port_scan_detection", DEFAULT_CONFIG["port_scan_detection"])
        self.ps_enabled = tk.BooleanVar(value=ps_conf.get("enabled", True))
        self.ps_threshold_ports = tk.IntVar(value=ps_conf.get("threshold_ports", 15))
        self.ps_window = tk.IntVar(value=ps_conf.get("time_window_seconds", 10))
        
        # Brute Force
        bf_conf = self.config.get("brute_force_detection", DEFAULT_CONFIG["brute_force_detection"])
        self.bf_enabled = tk.BooleanVar(value=bf_conf.get("enabled", True))
        self.bf_ports_str = tk.StringVar(value=", ".join(map(str, bf_conf.get("ports_to_monitor", []))))
        self.bf_threshold_attempts = tk.IntVar(value=bf_conf.get("threshold_failed_attempts", 5))
        self.bf_window = tk.IntVar(value=bf_conf.get("time_window_seconds", 60))
        
        # Flood
        flood_conf = self.config.get("flood_detection", DEFAULT_CONFIG["flood_detection"])
        self.flood_enabled = tk.BooleanVar(value=flood_conf.get("enabled", True))
        self.flood_syn_pps = tk.IntVar(value=flood_conf.get("syn_flood_threshold_pps", 100))
        self.flood_udp_pps = tk.IntVar(value=flood_conf.get("udp_flood_threshold_pps", 150))
        self.flood_icmp_pps = tk.IntVar(value=flood_conf.get("icmp_flood_threshold_pps", 100))
        self.flood_window = tk.IntVar(value=flood_conf.get("time_window_seconds", 5))
        
        # Som de Alerta de Ataque
        self.attack_alert_sound = tk.StringVar(value=self.config.get("attack_alert_sound", "SystemHand"))
        
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Configurações Gerais de Ataque ---
        general_attack_frame = ttk.LabelFrame(main_frame, text="Geral (Detecção de Ataques)", padding="10")
        general_attack_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Checkbutton(general_attack_frame, text="Habilitar Detecção de Ataques (Geral)", variable=self.attack_detection_enabled).pack(anchor=tk.W)
        ttk.Checkbutton(general_attack_frame, text="Habilitar Alertas Visuais (Pop-up) para Ataques", variable=self.attack_visual_alerts_enabled).pack(anchor=tk.W)
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        ps_frame = ttk.Frame(notebook, padding="10")
        notebook.add(ps_frame, text="Port Scan")
        self.create_ps_tab(ps_frame)
        
        bf_frame = ttk.Frame(notebook, padding="10")
        notebook.add(bf_frame, text="Brute Force")
        self.create_bf_tab(bf_frame)
        
        flood_frame = ttk.Frame(notebook, padding="10")
        notebook.add(flood_frame, text="Flood/DDoS")
        self.create_flood_tab(flood_frame)
        
        # Som de Alerta
        if winsound:
            sound_frame = ttk.LabelFrame(main_frame, text="Som de Alerta de Ataque (Padrão do Windows)", padding="10")
            sound_frame.pack(fill=tk.X, pady=(0, 10))
            sound_options = ["SystemAsterisk", "SystemExclamation", "SystemHand", "SystemQuestion", "SystemDefault"]
            ttk.Combobox(sound_frame, textvariable=self.attack_alert_sound, values=sound_options, state="readonly").pack(side=tk.LEFT, padx=5)
            ttk.Button(sound_frame, text="Testar", command=lambda: self.play_sound(self.attack_alert_sound.get())).pack(side=tk.LEFT, padx=5)
        
        # Botões
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        save_button = ttk.Button(button_frame, text="Salvar", command=self.save_and_close)
        save_button.pack(side=tk.RIGHT)
        cancel_button = ttk.Button(button_frame, text="Cancelar", command=self.window.destroy)
        cancel_button.pack(side=tk.RIGHT, padx=(0, 5))

    def create_ps_tab(self, parent):
        ttk.Checkbutton(parent, text="Habilitar Detecção de Port Scan", variable=self.ps_enabled).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        ttk.Label(parent, text="Threshold (portas distintas):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(parent, from_=2, to=100, textvariable=self.ps_threshold_ports, width=5).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="Janela de Tempo (segundos):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(parent, from_=1, to=60, textvariable=self.ps_window, width=5).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="(Detecta múltiplos SYNs para portas diferentes de uma origem)").grid(row=3, column=0, columnspan=3, sticky=tk.W, padx=5, pady=10, ipadx=5)

    def create_bf_tab(self, parent):
        ttk.Checkbutton(parent, text="Habilitar Detecção de Brute Force (Tentativas)", variable=self.bf_enabled).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        ttk.Label(parent, text="Portas Monitoradas (separadas por vírgula):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.bf_ports_str, width=30).grid(row=1, column=1, columnspan=2, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="Threshold (tentativas conexão):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(parent, from_=2, to=50, textvariable=self.bf_threshold_attempts, width=5).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="Janela de Tempo (segundos):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(parent, from_=10, to=300, textvariable=self.bf_window, width=5).grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="(Detecta múltiplos SYNs para portas específicas de uma origem. Básico.)").grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=5, pady=10, ipadx=5)

    def create_flood_tab(self, parent):
        ttk.Checkbutton(parent, text="Habilitar Detecção de Flood/DDoS", variable=self.flood_enabled).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        ttk.Label(parent, text="Threshold SYN Flood (pacotes/seg):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(parent, from_=10, to=10000, textvariable=self.flood_syn_pps, width=7).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="Threshold UDP Flood (pacotes/seg):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(parent, from_=10, to=10000, textvariable=self.flood_udp_pps, width=7).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="Threshold ICMP Flood (pacotes/seg):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(parent, from_=10, to=10000, textvariable=self.flood_icmp_pps, width=7).grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="Janela de Tempo (segundos):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(parent, from_=1, to=30, textvariable=self.flood_window, width=5).grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(parent, text="(Detecta alto volume de pacotes para um destino)").grid(row=5, column=0, columnspan=3, sticky=tk.W, padx=5, pady=10, ipadx=5)

    def play_sound(self, sound_alias):
        if winsound:
            try:
                winsound.PlaySound(sound_alias, winsound.SND_ALIAS | winsound.SND_ASYNC)
            except Exception as e:
                messagebox.showerror("Erro de Som", f"Não foi possível tocar o som '{sound_alias}':\n{e}")

    def save_and_close(self):
        try:
            # Validar e converter portas BF
            bf_ports_list = []
            if self.bf_ports_str.get().strip():
                bf_ports_list = [int(p.strip()) for p in self.bf_ports_str.get().split(',') if p.strip().isdigit()]
            
            new_config = self.config.copy() # Começa com a config atual
            new_config["attack_detection_enabled"] = self.attack_detection_enabled.get()
            new_config["attack_visual_alerts_enabled"] = self.attack_visual_alerts_enabled.get()
            new_config["port_scan_detection"] = {
                "enabled": self.ps_enabled.get(),
                "threshold_ports": self.ps_threshold_ports.get(),
                "time_window_seconds": self.ps_window.get()
            }
            new_config["brute_force_detection"] = {
                "enabled": self.bf_enabled.get(),
                "ports_to_monitor": bf_ports_list,
                "threshold_failed_attempts": self.bf_threshold_attempts.get(),
                "time_window_seconds": self.bf_window.get()
            }
            new_config["flood_detection"] = {
                "enabled": self.flood_enabled.get(),
                "syn_flood_threshold_pps": self.flood_syn_pps.get(),
                "udp_flood_threshold_pps": self.flood_udp_pps.get(),
                "icmp_flood_threshold_pps": self.flood_icmp_pps.get(),
                "time_window_seconds": self.flood_window.get()
            }
            new_config["attack_alert_sound"] = self.attack_alert_sound.get()
            
            self.callback(new_config) # Chama o callback da GUI principal
            self.window.destroy()
            
        except ValueError:
            messagebox.showerror("Erro de Validação", "Portas para Brute Force devem ser números inteiros separados por vírgula.")
        except Exception as e:
            messagebox.showerror("Erro ao Salvar", f"Ocorreu um erro inesperado: {e}")

# --- Classe Principal da GUI (Modificada) --- 
class NetSnifferXGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSnifferX - Monitoramento com Detecção de Ataques (Base Estável)") 
        self.root.geometry("1000x700") # Aumentar tamanho para nova área
        self.root.minsize(900, 600)
        
        self.config = load_config()
        
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("Header.TLabel", font=("Arial", 10, "bold")) 
        self.style.configure("Title.TLabel", font=("Arial", 16, "bold"))
        self.style.configure("Alert.TLabel", font=("Arial", 10, "bold"), foreground="red")
        self.style.configure("Attack.TLabel", font=("Arial", 10, "bold"), foreground="#FF8C00") # Laranja escuro para ataques
        
        self.is_capturing = False
        self.capture_thread = None
        self.stop_capture = threading.Event()
        self.packet_queue = queue.Queue()
        self.tcp_connection_count = 0
        self.suspicious_count = 0
        self.attack_alert_count = 0 # Novo contador
        self.tcp_connections = {} 
        self.alert_count = 0
        self.alert_popup_active = False 
        
        self.timeout_threshold = tk.IntVar(value=self.config["timeout_threshold"])
        self.interface = tk.StringVar(value=self.config["interface"])
        self.filter = tk.StringVar(value=self.config["filter"])
        self.duration = tk.IntVar(value=self.config["duration"])
        self.enable_visual_alerts_var = tk.BooleanVar(value=self.config["enable_visual_alerts"]) # Alertas TCP
        self.enable_attack_detection_var = tk.BooleanVar(value=self.config.get("attack_detection_enabled", True))
        
        # Instanciar AttackDetector
        self.attack_detector = AttackDetector(self.config, self.trigger_attack_alert)
        
        self.create_widgets()
        self.process_packet_queue()
        self.tracker = ConnectionTracker(self.config) 
        
    def create_widgets(self):
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)
        
        title_frame = ttk.Frame(top_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        title_label = ttk.Label(title_frame, text="NetSnifferX", style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        subtitle_label = ttk.Label(title_frame, text="Monitoramento com Detecção de Ataques")
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        
        config_frame = ttk.LabelFrame(top_frame, text="Configurações", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Linha 1 Config
        ttk.Label(config_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(config_frame, textvariable=self.interface, width=15).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(config_frame, text="(vazio = todas)").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(config_frame, text="Filtro (Scapy):").grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(config_frame, textvariable=self.filter, width=20).grid(row=0, column=4, sticky=tk.W, padx=5, pady=2)
        
        # Linha 2 Config
        ttk.Label(config_frame, text="Threshold TCP (s):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Spinbox(config_frame, from_=1, to=60, textvariable=self.timeout_threshold, width=5).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(config_frame, text="Duração Captura (s):").grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Spinbox(config_frame, from_=0, to=3600, textvariable=self.duration, width=5).grid(row=1, column=4, sticky=tk.W, padx=5, pady=2)
        ttk.Label(config_frame, text="(0 = indefinido)").grid(row=1, column=5, sticky=tk.W, padx=5, pady=2)
        
        # Linha 3 Config - Botões
        alert_config_button = ttk.Button(config_frame, text="Configurar Alertas TCP", command=self.open_alert_config)
        alert_config_button.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        attack_config_button = ttk.Button(config_frame, text="Configurar Detecção Ataques", command=self.open_attack_config)
        attack_config_button.grid(row=2, column=3, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        # --- Painel Principal com Divisão --- 
        main_panel = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_panel.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # --- Frame Superior (Controles e Tráfego Normal) ---
        top_panel_frame = ttk.Frame(main_panel, padding=(0,0,0,10)) # Padding inferior
        main_panel.add(top_panel_frame, weight=3) # Dar mais peso inicial

        button_frame = ttk.Frame(top_panel_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        self.start_button = ttk.Button(button_frame, text="Iniciar Captura", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        self.stop_button = ttk.Button(button_frame, text="Parar Captura", command=self.stop_capture_cmd, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        self.clear_button = ttk.Button(button_frame, text="Limpar Tudo", command=self.clear_all_displays)
        self.clear_button.pack(side=tk.LEFT, padx=(5, 0))
        
        self.visual_alert_check = ttk.Checkbutton(button_frame, text="Alertas Pop-up (TCP)", variable=self.enable_visual_alerts_var, command=self.toggle_visual_alerts)
        self.visual_alert_check.pack(side=tk.LEFT, padx=(15, 0))
        self.attack_detect_check = ttk.Checkbutton(button_frame, text="Detecção Ataques", variable=self.enable_attack_detection_var, command=self.toggle_attack_detection)
        self.attack_detect_check.pack(side=tk.LEFT, padx=(15, 0))
        
        stats_frame = ttk.Frame(top_panel_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        self.status_label = ttk.Label(stats_frame, text="Status: Pronto")
        self.status_label.pack(side=tk.LEFT)
        self.tcp_count_label = ttk.Label(stats_frame, text="TCP Conexões: 0") 
        self.tcp_count_label.pack(side=tk.LEFT, padx=(15, 0))
        self.suspicious_label = ttk.Label(stats_frame, text="TCP Suspeitas: 0") 
        self.suspicious_label.pack(side=tk.LEFT, padx=(15, 0))
        self.alert_label = ttk.Label(stats_frame, text="Alertas TCP: 0", style="Alert.TLabel") 
        self.alert_label.pack(side=tk.LEFT, padx=(15, 0))
        self.attack_alert_label = ttk.Label(stats_frame, text="Ataques Detectados: 0", style="Attack.TLabel") # Novo label
        self.attack_alert_label.pack(side=tk.LEFT, padx=(15, 0))
        
        # Modificado para exibir todos os protocolos
        display_frame = ttk.LabelFrame(top_panel_frame, text="Tráfego de Rede Detectado", padding="10")
        display_frame.pack(fill=tk.BOTH, expand=True)
        header_frame = ttk.Frame(display_frame)
        header_frame.pack(fill=tk.X)
        ttk.Label(header_frame, text="Horário", width=9, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Proto", width=5, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Origem", width=22, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Destino", width=22, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Status/Info", width=15, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Duração/Tam", width=10, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Pacotes", width=7, style="Header.TLabel").pack(side=tk.LEFT)
        
        self.connection_display = scrolledtext.ScrolledText(display_frame, wrap=tk.NONE, height=10) # wrap=NONE e altura menor
        self.connection_display.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.connection_display.config(state=tk.DISABLED)
        self.connection_display.bind("<Double-1>", self.on_connection_click)
        
        # Tags para protocolos
        self.connection_display.tag_config("TCP_INICIANDO", foreground="blue")
        self.connection_display.tag_config("TCP_EM_ANDAMENTO", foreground="black")
        self.connection_display.tag_config("TCP_FINALIZADA", foreground="green")
        self.connection_display.tag_config("TCP_SUSPEITA", foreground="red")
        self.connection_display.tag_config("UDP", foreground="purple")
        self.connection_display.tag_config("ICMP", foreground="orange")
        self.connection_display.tag_config("ERROR", foreground="red")
        
        legend_frame = ttk.LabelFrame(top_panel_frame, text="Legenda", padding="5")
        legend_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(legend_frame, text="TCP Iniciando", foreground="blue").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="TCP Ativa", foreground="black").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="TCP Finalizada", foreground="green").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="TCP Suspeita", foreground="red").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="UDP", foreground="purple").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="ICMP", foreground="orange").pack(side=tk.LEFT, padx=(0, 10))
        tip_label = ttk.Label(legend_frame, text="Dica: Clique duplo em TCP Suspeita para relatório", font=("Arial", 8, "italic"))
        tip_label.pack(side=tk.RIGHT)

        # --- Frame Inferior (Alertas de Ataque) ---
        bottom_panel_frame = ttk.Frame(main_panel, padding=(0,10,0,0)) # Padding superior
        main_panel.add(bottom_panel_frame, weight=1) # Menos peso inicial

        attack_display_frame = ttk.LabelFrame(bottom_panel_frame, text="Alertas de Segurança Detectados", padding="10")
        attack_display_frame.pack(fill=tk.BOTH, expand=True)
        attack_header_frame = ttk.Frame(attack_display_frame)
        attack_header_frame.pack(fill=tk.X)
        ttk.Label(attack_header_frame, text="Horário", width=9, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(attack_header_frame, text="Tipo Ataque", width=20, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(attack_header_frame, text="Origem/Info", width=30, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(attack_header_frame, text="Destino/Detalhe", width=30, style="Header.TLabel").pack(side=tk.LEFT)

        self.attack_display = scrolledtext.ScrolledText(attack_display_frame, wrap=tk.NONE, height=5) # wrap=NONE
        self.attack_display.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.attack_display.config(state=tk.DISABLED)
        self.attack_display.tag_config("ATTACK_Port Scan", foreground="#FF8C00")
        self.attack_display.tag_config("ATTACK_Brute Force (Tentativa)", foreground="#DC143C") # Crimson Red
        self.attack_display.tag_config("ATTACK_SYN Flood", foreground="#8B0000") # Dark Red
        self.attack_display.tag_config("ATTACK_UDP Flood", foreground="#8B0000")
        self.attack_display.tag_config("ATTACK_ICMP Flood", foreground="#8B0000")
        
        footer_frame = ttk.Frame(self.root)
        footer_frame.pack(fill=tk.X, padx=10, pady=(5, 10))
        ttk.Label(footer_frame, text="Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt").pack(side=tk.LEFT)
        
    def open_alert_config(self):
        # Abre a janela de config de alertas TCP (existente)
        self.config["enable_visual_alerts"] = self.enable_visual_alerts_var.get()
        AlertConfigWindow(self.root, self.config, self.save_alert_config)
        
    def save_alert_config(self, new_config):
        # Salva config de alertas TCP (existente)
        self.config.update(new_config) # Atualiza apenas as chaves relevantes
        self.enable_visual_alerts_var.set(self.config["enable_visual_alerts"])
        save_config(self.config)
        self.tracker = ConnectionTracker(self.config) # Reinicia tracker TCP
        messagebox.showinfo("Configuração Salva", "Configurações de alerta TCP salvas.")

    def open_attack_config(self):
        # Abre nova janela de config de detecção de ataques
        AttackConfigWindow(self.root, self.config, self.save_attack_config)

    def save_attack_config(self, new_config):
        # Salva config de detecção de ataques
        self.config.update(new_config)
        self.enable_attack_detection_var.set(self.config.get("attack_detection_enabled", True))
        save_config(self.config)
        self.attack_detector.update_config(self.config) # Atualiza config no detector
        messagebox.showinfo("Configuração Salva", "Configurações de detecção de ataques salvas.")

    def toggle_visual_alerts(self):
        # Controla apenas alertas TCP
        self.config["enable_visual_alerts"] = self.enable_visual_alerts_var.get()
        save_config(self.config) 
        
    def toggle_attack_detection(self):
        self.config["attack_detection_enabled"] = self.enable_attack_detection_var.get()
        save_config(self.config)
        self.attack_detector.update_config(self.config)
        status = "ativada" if self.config["attack_detection_enabled"] else "desativada"
        print(f"Detecção de ataques {status}.")
        
    def start_capture(self):
        if self.is_capturing:
            return
        
        # Salvar configs da GUI antes de iniciar
        self.config["timeout_threshold"] = self.timeout_threshold.get()
        self.config["interface"] = self.interface.get()
        self.config["filter"] = self.filter.get()
        self.config["duration"] = self.duration.get()
        self.config["enable_visual_alerts"] = self.enable_visual_alerts_var.get()
        self.config["attack_detection_enabled"] = self.enable_attack_detection_var.get()
        save_config(self.config)
        
        # Reiniciar trackers e contadores
        self.tracker = ConnectionTracker(self.config)
        self.attack_detector = AttackDetector(self.config, self.trigger_attack_alert) # Reinicia detector
        self.tcp_connection_count = 0
        self.suspicious_count = 0
        self.alert_count = 0
        self.attack_alert_count = 0
        self.tcp_connections = {}
        self.update_stats()
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Capturando...")
        
        self.stop_capture.clear()
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def stop_capture_cmd(self):
        if not self.is_capturing:
            return
        self.stop_capture.set()
        self.status_label.config(text="Status: Parando...")
        self.stop_button.config(state=tk.DISABLED)
    
    def capture_packets(self):
        # Usa a versão com L3socket forçado para Windows (da correção anterior)
        try:
            iface = self.config["interface"] if self.config["interface"] else None
            filter_str = self.config["filter"]
            duration = self.config["duration"] if self.config["duration"] > 0 else None
            
            l2_socket = None
            if platform.system() == "Windows":
                try:
                    l2_socket = conf.L3socket
                    print("Usando L3socket para captura no Windows.")
                except AttributeError:
                    print("Aviso: conf.L3socket não disponível. Usando captura padrão.")
            
            sniff(
                filter=filter_str,
                prn=self.packet_handler,
                store=0,
                iface=iface,
                timeout=duration,
                stop_filter=lambda _: self.stop_capture.is_set(),
                L2socket=l2_socket 
            )
        except PermissionError:
             self.packet_queue.put(("ERROR", "Erro de Permissão: Execute como administrador."))
        except OSError as e:
            if "No such device" in str(e) or "Interface not found" in str(e):
                self.packet_queue.put(("ERROR", f"Erro: Interface '{iface}' não encontrada."))
            else:
                self.packet_queue.put(("ERROR", f"Erro de Sistema Operacional: {e}"))
        except Exception as e:
            self.packet_queue.put(("ERROR", f"Erro durante a captura: {e}"))
        finally:
            self.is_capturing = False
            self.packet_queue.put(("STATUS", "Pronto"))
    
    def packet_handler(self, packet):
        # Coloca o pacote bruto na fila para processamento posterior
        self.packet_queue.put(("RAW_PACKET", packet))
    
    def process_packet_queue(self):
        # Processa pacotes da fila para evitar bloquear a captura
        try:
            while not self.packet_queue.empty():
                msg_type, data = self.packet_queue.get_nowait()
                
                if msg_type == "RAW_PACKET":
                    if self.alert_popup_active: # Pausa para pop-up TCP
                        # Repõe o pacote na fila se pausado
                        self.packet_queue.put((msg_type, data))
                        break # Sai do loop while para não processar mais nada agora
                        
                    packet = data
                    
                    # 1. Processar para Detecção de Ataques (se habilitado)
                    if self.config.get("attack_detection_enabled", False):
                        # Idealmente, isso rodaria em outra thread/processo para não impactar TCP
                        # Por ora, chamamos diretamente, mas com limpeza periódica
                        self.attack_detector.process_packet(packet)
                    
                    # 2. Processar para Rastreamento TCP e Exibição
                    display_info = None
                    protocol_display = None # Para UDP/ICMP
                    
                    if TCP in packet:
                        conn_info = self.tracker.track_packet(packet)
                        if conn_info:
                            display_info = conn_info
                            protocol_display = 'TCP'
                            # Atualizar contadores TCP
                            if conn_info['id'] not in self.tcp_connections:
                                self.tcp_connection_count += 1
                            if conn_info['is_suspicious'] and (conn_info['id'] not in self.tcp_connections or not self.tcp_connections[conn_info['id']]['is_suspicious']):
                                self.suspicious_count += 1
                            self.tcp_connections[conn_info['id']] = conn_info # Atualiza ou adiciona
                            if conn_info.get('trigger_alert', False):
                                self.trigger_tcp_alert(conn_info) 
                                
                    elif UDP in packet and IP in packet:
                        protocol_display = 'UDP'
                        display_info = {
                            'protocol': 'UDP',
                            'id': (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport),
                            'size': len(packet)
                        }
                        
                    elif ICMP in packet and IP in packet:
                        protocol_display = 'ICMP'
                        display_info = {
                            'protocol': 'ICMP',
                            'id': (packet[IP].src, 0, packet[IP].dst, 0), # Portas não aplicáveis
                            'type_code': (packet[ICMP].type, packet[ICMP].code),
                            'size': len(packet)
                        }
                        
                    # Exibir informações de tráfego (TCP, UDP, ICMP)
                    if display_info:
                        self.display_traffic(display_info)
                        if protocol_display == 'TCP': # Atualiza stats apenas para TCP por enquanto
                            self.update_stats()
                        
                elif msg_type == "ERROR":
                    self.display_error(data)
                elif msg_type == "STATUS":
                    self.status_label.config(text=f"Status: {data}")
                    if data == "Pronto":
                        self.start_button.config(state=tk.NORMAL)
                        self.stop_button.config(state=tk.DISABLED)
                        
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_packet_queue) # Aumentar um pouco o delay para dar tempo à GUI
    
    def display_traffic(self, info):
        """Exibe informações de tráfego (TCP, UDP, ICMP) na interface principal."""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        protocol = info['protocol']
        src_ip, src_port, dst_ip, dst_port = info['id']
        
        status_info = "-"
        duration_size = "-"
        pkts = "-"
        tag = protocol # Tag padrão
        
        if protocol == 'TCP':
            status_info = info['status']
            duration_size = f"{info['duration']:.2f}"
            pkts = str(info['packet_count'])
            tag = f"TCP_{status_info}"
            if info['is_suspicious']: tag = "TCP_SUSPEITA"
        elif protocol == 'UDP':
            status_info = f"Porta {dst_port}"
            duration_size = f"{info['size']} B"
            tag = "UDP"
        elif protocol == 'ICMP':
            status_info = get_icmp_description(info['type_code'])
            duration_size = f"{info['size']} B"
            tag = "ICMP"
            
        line = f"{timestamp:<9} {protocol:<5} {src_ip}:{src_port:<22} {dst_ip}:{dst_port:<22} {status_info:<15} {duration_size:<10} {pkts:<7}\n"
        
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.insert(tk.END, line, tag)
        self.connection_display.see(tk.END)
        self.connection_display.config(state=tk.DISABLED)
        
    def display_attack_alert(self, alert_info):
        """Exibe um alerta de ataque detectado na área de segurança."""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        attack_type = alert_info['type']
        source_info = alert_info['source']
        details = alert_info['details']
        target_info = alert_info.get('target', '-') # Alvo pode não ser aplicável
        
        line = f"{timestamp:<9} {attack_type:<20} {source_info:<30} {target_info + ' (' + details + ')':<30}\n"
        tag = f"ATTACK_{attack_type}"
        
        self.attack_display.config(state=tk.NORMAL)
        self.attack_display.insert(tk.END, line, tag)
        self.attack_display.see(tk.END)
        self.attack_display.config(state=tk.DISABLED)

    def display_error(self, error_msg):
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.insert(tk.END, f"ERRO: {error_msg}\n", "ERROR")
        self.connection_display.see(tk.END)
        self.connection_display.config(state=tk.DISABLED)
        messagebox.showerror("Erro", error_msg)
        self.is_capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Erro")
    
    def update_stats(self):
        self.tcp_count_label.config(text=f"TCP Conexões: {self.tcp_connection_count}")
        self.suspicious_label.config(text=f"TCP Suspeitas: {self.suspicious_count}")
        self.alert_label.config(text=f"Alertas TCP: {self.alert_count}")
        self.attack_alert_label.config(text=f"Ataques Detectados: {self.attack_alert_count}")
    
    def clear_all_displays(self):
        # Limpa display de tráfego TCP
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.delete(1.0, tk.END)
        self.connection_display.config(state=tk.DISABLED)
        # Limpa display de alertas de ataque
        self.attack_display.config(state=tk.NORMAL)
        self.attack_display.delete(1.0, tk.END)
        self.attack_display.config(state=tk.DISABLED)
        # Reinicia contadores e trackers
        self.tcp_connection_count = 0
        self.suspicious_count = 0
        self.alert_count = 0
        self.attack_alert_count = 0
        self.tcp_connections = {}
        self.tracker = ConnectionTracker(self.config) 
        self.attack_detector = AttackDetector(self.config, self.trigger_attack_alert) # Reinicia detector
        self.update_stats()
    
    def on_connection_click(self, event):
        # Ação de clique duplo só funciona para TCP suspeito no display superior
        try:
            widget = event.widget
            if widget != self.connection_display: return # Ignora cliques no display de ataques
            
            index = widget.index(f"@{event.x},{event.y}")
            line_start = widget.index(f"{index} linestart")
            line_end = widget.index(f"{index} lineend")
            line = widget.get(line_start, line_end)
            if not line or len(line.split()) < 6: # Ajustado para nova coluna Proto
                return
                
            # Extrair ID da conexão TCP da linha formatada
            parts = line.split()
            protocol = parts[1]
            if protocol != 'TCP': # Só permite clique em TCP
                return
                
            src_parts = parts[2].split(':')
            dst_parts = parts[3].split(':')
            if len(src_parts) < 2 or len(dst_parts) < 2:
                return
            src_ip = src_parts[0]
            src_port = int(src_parts[1])
            dst_ip = dst_parts[0]
            dst_port = int(dst_parts[1])
            conn_id = (src_ip, src_port, dst_ip, dst_port)
            
            # Obter detalhes apenas se for TCP e suspeito
            conn_details = self.tracker.get_connection_details(conn_id)
            
            if conn_details and conn_details['is_suspicious']:
                ConnectionReportWindow(self.root, conn_details)
            elif conn_details:
                 messagebox.showinfo("Informação", "Relatórios detalhados estão disponíveis apenas para conexões TCP suspeitas.")
                
        except Exception as e:
            print(f"Erro no clique TCP: {e}") 
    
    def trigger_tcp_alert(self, conn_info):
        # Alertas para conexões TCP suspeitas (longas)
        if self.alert_popup_active: return

        self.alert_count += 1
        self.update_stats()
        src_ip, src_port, dst_ip, dst_port = conn_info['id']
        severity = conn_info['severity']

        if self.config["enable_visual_alerts"]: # Usa config TCP
            alert_title = f"Alerta de Conexão TCP Suspeita ({severity})"
            alert_message = f"Conexão TCP suspeita detectada:\n"
            alert_message += f"Origem: {src_ip}:{src_port}\n"
            alert_message += f"Destino: {dst_ip}:{dst_port}\n"
            alert_message += f"Duração: {conn_info['duration']:.2f}s\n"
            alert_message += f"Gravidade: {severity}"

            try:
                self.alert_popup_active = True
                messagebox.showwarning(alert_title, alert_message)
            finally:
                self.alert_popup_active = False
            
            self.flash_alert_label(self.alert_label, "red")

        if self.config["enable_sound_alerts"] and winsound: # Usa config TCP
            try:
                sound_alias = self.config["alert_sounds"].get(severity, "SystemDefault")
                winsound.PlaySound(sound_alias, winsound.SND_ALIAS | winsound.SND_ASYNC)
            except Exception as e:
                print(f"Erro ao tocar som de alerta TCP: {e}")
                
    def trigger_attack_alert(self, attack_type, source_info, details, target_info):
        # Callback chamado pelo AttackDetector
        self.attack_alert_count += 1
        self.update_stats()
        
        alert_info = {
            'type': attack_type,
            'source': source_info,
            'details': details,
            'target': target_info
        }
        self.display_attack_alert(alert_info)
        
        # Alerta visual/sonoro para ataques
        if self.config.get("attack_visual_alerts_enabled", True): # Usa config de ataque
            alert_title = f"Alerta de Segurança: {attack_type}"
            alert_message = f"Possível ataque detectado:\n"
            alert_message += f"Tipo: {attack_type}\n"
            alert_message += f"Origem/Info: {source_info}\n"
            alert_message += f"Destino/Detalhe: {target_info}\n"
            alert_message += f"Detalhes: {details}"
            
            # Usar showinfo para não pausar a captura?
            # Ou criar um pop-up não modal?
            # Por enquanto, usar showwarning mas sem pausar (sem alert_popup_active)
            messagebox.showwarning(alert_title, alert_message)
            self.flash_alert_label(self.attack_alert_label, "#FF8C00") # Laranja escuro

        if self.config["enable_sound_alerts"] and winsound: # Usar config geral de som?
            try:
                sound_alias = self.config.get("attack_alert_sound", "SystemHand")
                winsound.PlaySound(sound_alias, winsound.SND_ALIAS | winsound.SND_ASYNC)
            except Exception as e:
                print(f"Erro ao tocar som de alerta de ataque: {e}")
    
    def flash_alert_label(self, label_widget, active_color, count=5):
        # Função genérica para piscar labels
        current_color = label_widget.cget("foreground")
        default_color = self.style.lookup(label_widget.cget("style"), "foreground")
        next_color = active_color if current_color == default_color else default_color
        label_widget.config(foreground=next_color)
        if count > 0:
            self.root.after(200, self.flash_alert_label, label_widget, active_color, count - 1)
        else:
            # Garante que a cor final seja a ativa se houver alertas
            if label_widget == self.alert_label and self.alert_count > 0:
                 label_widget.config(foreground=active_color)
            elif label_widget == self.attack_alert_label and self.attack_alert_count > 0:
                 label_widget.config(foreground=active_color)
            else:
                 label_widget.config(foreground=default_color) 

# --- Função Principal --- 
def main():
    root = tk.Tk()
    app = NetSnifferXGUI(root)
    def on_closing():
        if app.is_capturing:
            if messagebox.askokcancel("Sair", "A captura está em andamento. Deseja realmente sair?"):
                app.stop_capture.set()
                # Salvar config antes de sair
                app.config["timeout_threshold"] = app.timeout_threshold.get()
                app.config["interface"] = app.interface.get()
                app.config["filter"] = app.filter.get()
                app.config["duration"] = app.duration.get()
                app.config["enable_visual_alerts"] = app.enable_visual_alerts_var.get()
                app.config["attack_detection_enabled"] = app.enable_attack_detection_var.get()
                save_config(app.config)
                root.destroy()
        else:
            # Salvar config antes de sair
            app.config["timeout_threshold"] = app.timeout_threshold.get()
            app.config["interface"] = app.interface.get()
            app.config["filter"] = app.filter.get()
            app.config["duration"] = app.duration.get()
            app.config["enable_visual_alerts"] = app.enable_visual_alerts_var.get()
            app.config["attack_detection_enabled"] = app.enable_attack_detection_var.get()
            save_config(app.config)
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()

