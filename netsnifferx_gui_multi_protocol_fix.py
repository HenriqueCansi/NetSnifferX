#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetSnifferX - Monitoramento e análise de conexões de rede em tempo real com interface gráfica, relatórios e alertas configuráveis
Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt
Versão: GUI com Suporte Multi-Protocolo (TCP, UDP, ICMP) - FIX Captura TCP

NOTA IMPORTANTE: Este script requer privilégios de administrador para capturar pacotes.
Execute com: python netsnifferx_gui_multi_protocol_fix.py
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

DEFAULT_CONFIG = {
    "timeout_threshold": 10, # Aplicável apenas a TCP
    "interface": "",
    "filter": "tcp or udp or icmp", # Filtro padrão agora inclui UDP e ICMP
    "duration": 0,
    "enable_visual_alerts": True, # Aplicável apenas a TCP
    "enable_sound_alerts": True, # Aplicável apenas a TCP
    "severity_thresholds": { # Aplicável apenas a TCP
        "Baixo": 2,  
        "Médio": 5,  
        "Alto": 10  
    },
    "alert_sounds": { # Aplicável apenas a TCP
        "Baixo": "SystemAsterisk",
        "Médio": "SystemExclamation",
        "Alto": "SystemHand"
    }
}

# Mapeamento de tipos ICMP comuns
ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
    15: "Information Request",
    16: "Information Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply"
}

# Mapeamento de códigos ICMP para Tipo 3 (Destination Unreachable)
ICMP_CODES_TYPE_3 = {
    0: "Net Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed and Don\'t Fragment was Set",
    5: "Source Route Failed",
    6: "Destination Network Unknown",
    7: "Destination Host Unknown",
    8: "Source Host Isolated",
    9: "Communication with Destination Network is Administratively Prohibited",
    10: "Communication with Destination Host is Administratively Prohibited",
    11: "Destination Network Unreachable for Type of Service",
    12: "Destination Host Unreachable for Type of Service",
    13: "Communication Administratively Prohibited",
    14: "Host Precedence Violation",
    15: "Precedence Cutoff in Effect"
}

def get_icmp_description(type_code):
    """Retorna uma descrição textual para o tipo/código ICMP."""
    icmp_type, icmp_code = type_code
    type_desc = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
    code_desc = ""
    if icmp_type == 3:
        code_desc = f" (Code {icmp_code}: {ICMP_CODES_TYPE_3.get(icmp_code, 'Unknown')})"
    elif icmp_code != 0: # Para outros tipos, geralmente o código é 0
        code_desc = f" (Code {icmp_code})"
    return f"{type_desc}{code_desc}"

def load_config():
    """Carrega as configurações do arquivo JSON."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                # Garantir que todas as chaves padrão existam
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                    elif isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            # Verificar se a subchave existe antes de acessá-la
                            if isinstance(config.get(key), dict) and sub_key not in config[key]:
                                config[key][sub_key] = sub_value
                # Garantir que o filtro padrão seja atualizado se não existir ou for antigo
                if "filter" not in config or config["filter"] == "tcp":
                    config["filter"] = DEFAULT_CONFIG["filter"]
                return config
        except Exception as e:
            print(f"Erro ao carregar configuração: {e}. Usando padrão.")
            return DEFAULT_CONFIG.copy()
    else:
        return DEFAULT_CONFIG.copy()

def save_config(config):
    """Salva as configurações no arquivo JSON."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Erro ao salvar configuração: {e}")

class ConnectionTracker:
    """
    Classe responsável por rastrear e gerenciar conexões TCP ativas.
    (Mantida focada em TCP por enquanto)
    """
    def __init__(self, config):
        self.config = config
        self.connections = {}  
        self.connection_history = {}  
        self.max_history_packets = 100  
        
    def get_connection_id(self, packet):
        if TCP in packet and IP in packet: # Garantir que tem camada IP
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
        if TCP not in packet:
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
                # Remover histórico também? Ou manter por um tempo?
                # if conn_id in self.connection_history: del self.connection_history[conn_id]
                return result
            else: # FIN/RST sem SYN prévio - ignorar ou tratar como erro?
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

class ConnectionReportWindow:
    # Sem alterações necessárias aqui, pois só lida com detalhes TCP
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
    # Sem alterações necessárias aqui
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

class NetSnifferXGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSnifferX - Monitoramento de Rede (TCP/UDP/ICMP)") # Título atualizado
        self.root.geometry("950x650") # Aumentar um pouco a largura
        self.root.minsize(850, 550)
        
        self.config = load_config()
        
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("Header.TLabel", font=("Arial", 12, "bold"))
        self.style.configure("Title.TLabel", font=("Arial", 16, "bold"))
        self.style.configure("Alert.TLabel", font=("Arial", 10, "bold"), foreground="red")
        
        self.is_capturing = False
        self.capture_thread = None
        self.stop_capture = threading.Event()
        self.packet_queue = queue.Queue()
        self.tcp_connection_count = 0
        self.udp_packet_count = 0
        self.icmp_packet_count = 0
        self.suspicious_count = 0
        self.tcp_connections = {} # Para rastrear cliques e relatórios TCP
        self.alert_count = 0
        self.alert_popup_active = False 
        
        self.timeout_threshold = tk.IntVar(value=self.config["timeout_threshold"])
        self.interface = tk.StringVar(value=self.config["interface"])
        self.filter = tk.StringVar(value=self.config["filter"])
        self.duration = tk.IntVar(value=self.config["duration"])
        self.enable_visual_alerts_var = tk.BooleanVar(value=self.config["enable_visual_alerts"])
        
        self.create_widgets()
        self.process_packet_queue()
        self.tracker = ConnectionTracker(self.config) # Tracker ainda focado em TCP
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        title_label = ttk.Label(title_frame, text="NetSnifferX", style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        subtitle_label = ttk.Label(title_frame, text="Monitoramento de Rede (TCP/UDP/ICMP)") # Subtítulo atualizado
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        
        config_frame = ttk.LabelFrame(main_frame, text="Configurações", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(config_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.interface, width=15).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="(vazio = todas)").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="Filtro (Scapy):").grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.filter, width=20).grid(row=0, column=4, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="Threshold TCP (s):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(config_frame, from_=1, to=60, textvariable=self.timeout_threshold, width=5).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="Duração Captura (s):").grid(row=1, column=3, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(config_frame, from_=0, to=3600, textvariable=self.duration, width=5).grid(row=1, column=4, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="(0 = indefinido)").grid(row=1, column=5, sticky=tk.W, padx=5, pady=5)
        
        alert_config_button = ttk.Button(config_frame, text="Configurar Alertas TCP", command=self.open_alert_config)
        alert_config_button.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        self.start_button = ttk.Button(button_frame, text="Iniciar Captura", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        self.stop_button = ttk.Button(button_frame, text="Parar Captura", command=self.stop_capture_cmd, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        self.clear_button = ttk.Button(button_frame, text="Limpar", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=(5, 0))
        
        self.visual_alert_check = ttk.Checkbutton(button_frame, text="Alertas Pop-up (TCP)", variable=self.enable_visual_alerts_var, command=self.toggle_visual_alerts)
        self.visual_alert_check.pack(side=tk.LEFT, padx=(15, 0))
        
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        self.status_label = ttk.Label(stats_frame, text="Status: Pronto")
        self.status_label.pack(side=tk.LEFT)
        self.tcp_count_label = ttk.Label(stats_frame, text="TCP Conexões: 0") # Label TCP
        self.tcp_count_label.pack(side=tk.LEFT, padx=(20, 0))
        self.udp_count_label = ttk.Label(stats_frame, text="UDP Pacotes: 0") # Label UDP
        self.udp_count_label.pack(side=tk.LEFT, padx=(20, 0))
        self.icmp_count_label = ttk.Label(stats_frame, text="ICMP Pacotes: 0") # Label ICMP
        self.icmp_count_label.pack(side=tk.LEFT, padx=(20, 0))
        self.suspicious_label = ttk.Label(stats_frame, text="TCP Suspeitas: 0") # Label Suspeitas TCP
        self.suspicious_label.pack(side=tk.LEFT, padx=(20, 0))
        self.alert_label = ttk.Label(stats_frame, text="Alertas TCP: 0", style="Alert.TLabel") # Label Alertas TCP
        self.alert_label.pack(side=tk.LEFT, padx=(20, 0))
        
        display_frame = ttk.LabelFrame(main_frame, text="Tráfego de Rede Detectado", padding="10")
        display_frame.pack(fill=tk.BOTH, expand=True)
        header_frame = ttk.Frame(display_frame)
        header_frame.pack(fill=tk.X)
        # Ajustar cabeçalhos para acomodar mais informações
        ttk.Label(header_frame, text="Horário", width=9, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Proto", width=5, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Origem", width=20, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Destino", width=20, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Info/Status", width=20, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(header_frame, text="Detalhes", width=15, style="Header.TLabel").pack(side=tk.LEFT)
        
        self.connection_display = scrolledtext.ScrolledText(display_frame, wrap=tk.WORD, height=20)
        self.connection_display.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.connection_display.config(state=tk.DISABLED)
        self.connection_display.bind("<Double-1>", self.on_connection_click)
        
        # Definir tags de cores para protocolos
        self.connection_display.tag_config("TCP_INICIANDO", foreground="blue")
        self.connection_display.tag_config("TCP_EM_ANDAMENTO", foreground="black")
        self.connection_display.tag_config("TCP_FINALIZADA", foreground="green")
        self.connection_display.tag_config("TCP_SUSPEITA", foreground="red")
        self.connection_display.tag_config("UDP", foreground="purple")
        self.connection_display.tag_config("ICMP", foreground="orange")
        self.connection_display.tag_config("ERROR", foreground="red")
        
        legend_frame = ttk.LabelFrame(main_frame, text="Legenda", padding="5")
        legend_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(legend_frame, text="TCP Iniciando", foreground="blue").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="TCP Ativa", foreground="black").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="TCP Finalizada", foreground="green").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="TCP Suspeita", foreground="red").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="UDP", foreground="purple").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(legend_frame, text="ICMP", foreground="orange").pack(side=tk.LEFT, padx=(0, 10))
        tip_label = ttk.Label(legend_frame, text="Dica: Clique duplo em TCP Suspeita para relatório", font=("Arial", 8, "italic"))
        tip_label.pack(side=tk.RIGHT)
        
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(footer_frame, text="Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt").pack(side=tk.LEFT)
        
    def open_alert_config(self):
        self.config["enable_visual_alerts"] = self.enable_visual_alerts_var.get()
        AlertConfigWindow(self.root, self.config, self.save_alert_config)
        
    def save_alert_config(self, new_config):
        self.config = new_config
        self.enable_visual_alerts_var.set(self.config["enable_visual_alerts"])
        save_config(self.config)
        if self.is_capturing:
            messagebox.showinfo("Configuração Salva", "As novas configurações de alerta TCP serão aplicadas na próxima captura.")
        else:
            self.tracker = ConnectionTracker(self.config)
            messagebox.showinfo("Configuração Salva", "Configurações de alerta TCP salvas com sucesso.")
            
    def toggle_visual_alerts(self):
        self.config["enable_visual_alerts"] = self.enable_visual_alerts_var.get()
        save_config(self.config) 
        
    def start_capture(self):
        if self.is_capturing:
            return
        
        self.config["timeout_threshold"] = self.timeout_threshold.get()
        self.config["interface"] = self.interface.get()
        self.config["filter"] = self.filter.get()
        self.config["duration"] = self.duration.get()
        self.config["enable_visual_alerts"] = self.enable_visual_alerts_var.get()
        save_config(self.config)
        
        self.tracker = ConnectionTracker(self.config)
        self.tcp_connection_count = 0
        self.udp_packet_count = 0
        self.icmp_packet_count = 0
        self.suspicious_count = 0
        self.alert_count = 0
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
        try:
            iface = self.config["interface"] if self.config["interface"] else None
            filter_str = self.config["filter"]
            duration = self.config["duration"] if self.config["duration"] > 0 else None
            
            # CORREÇÃO: Forçar L3socket para melhorar captura no Windows
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
                L2socket=l2_socket # Aplicar L3socket se disponível
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
        # Coloca qualquer pacote IP na fila para processamento
        if IP in packet:
            self.packet_queue.put(("RAW_PACKET", packet))
    
    def process_packet_queue(self):
        try:
            while not self.packet_queue.empty():
                msg_type, data = self.packet_queue.get_nowait()
                
                if msg_type == "RAW_PACKET":
                    if self.alert_popup_active:
                        continue # Ignora processamento se pop-up TCP estiver ativo
                        
                    packet = data
                    display_info = None
                    
                    # Processar TCP
                    if TCP in packet:
                        conn_info = self.tracker.track_packet(packet)
                        if conn_info:
                            display_info = conn_info
                            # Atualizar contadores TCP
                            if conn_info['id'] not in self.tcp_connections:
                                self.tcp_connection_count += 1
                            if conn_info['is_suspicious'] and (conn_info['id'] not in self.tcp_connections or not self.tcp_connections[conn_info['id']]['is_suspicious']):
                                self.suspicious_count += 1
                            self.tcp_connections[conn_info['id']] = conn_info # Atualiza ou adiciona
                            if conn_info.get('trigger_alert', False):
                                self.trigger_alert(conn_info)
                                
                    # Processar UDP
                    elif UDP in packet:
                        self.udp_packet_count += 1
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                        size = len(packet)
                        display_info = {
                            'protocol': 'UDP',
                            'id': (src_ip, src_port, dst_ip, dst_port),
                            'size': size
                        }
                        
                    # Processar ICMP
                    elif ICMP in packet:
                        self.icmp_packet_count += 1
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        icmp_type = packet[ICMP].type
                        icmp_code = packet[ICMP].code
                        size = len(packet)
                        display_info = {
                            'protocol': 'ICMP',
                            'id': (src_ip, dst_ip, icmp_type, icmp_code),
                            'type_code': (icmp_type, icmp_code),
                            'size': size
                        }
                        
                    # Exibir informações processadas
                    if display_info:
                        self.display_traffic(display_info)
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
            self.root.after(100, self.process_packet_queue) 
    
    def display_traffic(self, info):
        """Exibe informações de tráfego TCP, UDP ou ICMP na interface."""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        protocol = info['protocol']
        line = f"{timestamp:<9} {protocol:<5} "
        tag = protocol # Tag base
        
        if protocol == 'TCP':
            src_ip, src_port, dst_ip, dst_port = info['id']
            status = info['status']
            duration = round(info['duration'], 2)
            line += f"{src_ip}:{src_port:<20} {dst_ip}:{dst_port:<20} {status:<20} {duration:<15.2f}"
            tag = f"TCP_{status}" # Tag específica TCP
            if info['is_suspicious']: tag = "TCP_SUSPEITA"
            
        elif protocol == 'UDP':
            src_ip, src_port, dst_ip, dst_port = info['id']
            size = info['size']
            line += f"{src_ip}:{src_port:<20} {dst_ip}:{dst_port:<20} {'UDP Packet':<20} {'Size: ' + str(size):<15}"
            tag = "UDP"
            
        elif protocol == 'ICMP':
            src_ip, dst_ip, _, _ = info['id']
            type_code = info['type_code']
            description = get_icmp_description(type_code)
            size = info['size']
            line += f"{src_ip:<20s} {dst_ip:<20s} {description:<20} {'Size: ' + str(size):<15}"
            tag = "ICMP"
            
        line += "\n"
        
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.insert(tk.END, line, tag)
        self.connection_display.see(tk.END)
        self.connection_display.config(state=tk.DISABLED)
    
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
        self.udp_count_label.config(text=f"UDP Pacotes: {self.udp_packet_count}")
        self.icmp_count_label.config(text=f"ICMP Pacotes: {self.icmp_packet_count}")
        self.suspicious_label.config(text=f"TCP Suspeitas: {self.suspicious_count}")
        self.alert_label.config(text=f"Alertas TCP: {self.alert_count}")
    
    def clear_display(self):
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.delete(1.0, tk.END)
        self.connection_display.config(state=tk.DISABLED)
        self.tcp_connection_count = 0
        self.udp_packet_count = 0
        self.icmp_packet_count = 0
        self.suspicious_count = 0
        self.alert_count = 0
        self.tcp_connections = {}
        self.tracker = ConnectionTracker(self.config) # Reiniciar tracker TCP
        self.update_stats()
    
    def on_connection_click(self, event):
        # Ação de clique duplo só funciona para TCP suspeito
        try:
            index = self.connection_display.index(f"@{event.x},{event.y}")
            line_start = self.connection_display.index(f"{index} linestart")
            line_end = self.connection_display.index(f"{index} lineend")
            line = self.connection_display.get(line_start, line_end)
            if not line or len(line.split()) < 5:
                return
                
            # Verificar se a linha clicada é TCP
            parts = line.split()
            if len(parts) < 2 or parts[1] != 'TCP':
                # print("Clique não foi em uma linha TCP.")
                return
                
            # Extrair ID da conexão TCP
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
            # else: # Não mostrar nada se não for TCP suspeito ou não encontrado
            #    messagebox.showinfo("Informação", "Detalhes da conexão TCP não encontrados ou não suspeitos.")
                
        except Exception as e:
            print(f"Erro no clique: {e}") # Logar erro para debug
            # messagebox.showerror("Erro", f"Erro ao processar clique: {e}")
    
    def trigger_alert(self, conn_info):
        # Alertas continuam focados em TCP
        if conn_info['protocol'] != 'TCP':
            return
            
        if self.alert_popup_active:
            return

        self.alert_count += 1
        self.update_stats()
        src_ip, src_port, dst_ip, dst_port = conn_info['id']
        severity = conn_info['severity']

        if self.enable_visual_alerts_var.get():
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
            
            self.flash_alert_label()

        if self.config["enable_sound_alerts"] and winsound:
            try:
                sound_alias = self.config["alert_sounds"].get(severity, "SystemDefault")
                winsound.PlaySound(sound_alias, winsound.SND_ALIAS | winsound.SND_ASYNC)
            except Exception as e:
                print(f"Erro ao tocar som de alerta: {e}")
    
    def flash_alert_label(self, count=5):
        current_color = self.alert_label.cget("foreground")
        next_color = "red" if current_color == "black" else "black"
        self.alert_label.config(foreground=next_color)
        if count > 0:
            self.root.after(200, self.flash_alert_label, count - 1)
        else:
            if self.alert_count > 0:
                 self.alert_label.config(foreground="red")
            else:
                 self.alert_label.config(foreground="black") 

def main():
    root = tk.Tk()
    app = NetSnifferXGUI(root)
    def on_closing():
        if app.is_capturing:
            if messagebox.askokcancel("Sair", "A captura está em andamento. Deseja realmente sair?"):
                app.stop_capture.set()
                app.config["timeout_threshold"] = app.timeout_threshold.get()
                app.config["interface"] = app.interface.get()
                app.config["filter"] = app.filter.get()
                app.config["duration"] = app.duration.get()
                app.config["enable_visual_alerts"] = app.enable_visual_alerts_var.get()
                save_config(app.config)
                root.destroy()
        else:
            app.config["timeout_threshold"] = app.timeout_threshold.get()
            app.config["interface"] = app.interface.get()
            app.config["filter"] = app.filter.get()
            app.config["duration"] = app.duration.get()
            app.config["enable_visual_alerts"] = app.enable_visual_alerts_var.get()
            save_config(app.config)
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
