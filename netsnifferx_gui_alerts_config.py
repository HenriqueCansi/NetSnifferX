#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetSnifferX - Monitoramento e análise de conexões TCP em tempo real com interface gráfica, relatórios e alertas configuráveis
Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt

NOTA IMPORTANTE: Este script requer privilégios de administrador para capturar pacotes.
Execute com: python netsnifferx_gui_alerts_config.py
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
from scapy.all import sniff, TCP
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
    "timeout_threshold": 10,
    "interface": "",
    "filter": "tcp",
    "duration": 0,
    "enable_visual_alerts": True,
    "enable_sound_alerts": True,
    "severity_thresholds": {
        "Baixo": 2,  # Multiplicador do threshold base
        "Médio": 5,  # Multiplicador do threshold base
        "Alto": 10  # Multiplicador do threshold base
    },
    "alert_sounds": {
        "Baixo": "SystemAsterisk",
        "Médio": "SystemExclamation",
        "Alto": "SystemHand"
    }
}

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
                            if sub_key not in config[key]:
                                config[key][sub_key] = sub_value
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
    """
    def __init__(self, config):
        """
        Inicializa o rastreador de conexões.
        
        Args:
            config (dict): Dicionário de configuração
        """
        self.config = config
        self.connections = {}  # Dicionário para armazenar conexões ativas
        self.connection_history = {}  # Histórico de pacotes por conexão
        self.max_history_packets = 100  # Máximo de pacotes armazenados por conexão
        
    def get_connection_id(self, packet):
        """
        Gera um ID único para a conexão baseado nos IPs e portas.
        """
        if TCP in packet and hasattr(packet, 'src') and hasattr(packet, 'dst'):
            return (packet.src, packet[TCP].sport, packet.dst, packet[TCP].dport)
        return None
    
    def store_packet_history(self, conn_id, packet):
        """
        Armazena o pacote no histórico da conexão.
        """
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
        """
        Rastreia um pacote TCP e atualiza o estado das conexões.
        """
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
                    'id': conn_id,
                    'status': status,
                    'duration': duration,
                    'is_suspicious': is_suspicious,
                    'packet_count': packet_count,
                    'flags_history': self.connections[conn_id]['flags_history'],
                    'severity': severity
                }
                del self.connections[conn_id]
                return result
        
        elif conn_id in self.connections:
            self.connections[conn_id]['last_update'] = current_time
            self.connections[conn_id]['packets'] += 1
            self.connections[conn_id]['flags_history'].append(flags)
            
            duration = current_time - self.connections[conn_id]['start_time']
            is_suspicious = duration > timeout_threshold
            severity = self.calculate_severity(duration)
            
            if is_suspicious and self.connections[conn_id]['status'] != 'SUSPEITA':
                self.connections[conn_id]['status'] = 'SUSPEITA'
            
            trigger_alert = False
            if is_suspicious and not self.connections[conn_id]['alert_triggered']:
                trigger_alert = True
                self.connections[conn_id]['alert_triggered'] = True
            
            return {
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
            self.connections[conn_id] = {
                'start_time': current_time,
                'last_update': current_time,
                'status': 'EM ANDAMENTO',
                'packets': 1,
                'flags_history': [flags],
                'alert_triggered': False
            }
            return {
                'id': conn_id,
                'status': 'EM ANDAMENTO',
                'duration': 0,
                'is_suspicious': False,
                'packet_count': 1,
                'flags_history': [flags],
                'severity': 'Normal'
            }
    
    def calculate_severity(self, duration):
        """
        Calcula o nível de gravidade com base na duração e nos thresholds configurados.
        """
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
        """
        Obtém detalhes completos de uma conexão para o relatório.
        """
        timeout_threshold = self.config["timeout_threshold"]
        
        if conn_id in self.connections:
            conn = self.connections[conn_id]
            current_time = time.time()
            duration = current_time - conn['start_time']
            severity = self.calculate_severity(duration)
            
            details = {
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
                'id': conn_id,
                'start_time': first_packet['timestamp'],
                'last_update': last_packet['timestamp'],
                'status': 'FINALIZADA',
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
    """
    Janela de relatório detalhado para conexões suspeitas.
    """
    def __init__(self, parent, connection_details):
        self.parent = parent
        self.details = connection_details
        
        self.window = tk.Toplevel(parent)
        self.window.title("Relatório Detalhado de Conexão")
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
        title_text = f"Conexão: {src_ip}:{src_port} → {dst_ip}:{dst_port}"
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
        
        info_frame = ttk.LabelFrame(parent, text="Informações da Conexão", padding="10")
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
        elif self.details['status'] == 'FINALIZADA':
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
            severity_label.configure(foreground="#CCCC00")
        
        if self.details['is_suspicious']:
            suspicion_frame = ttk.LabelFrame(parent, text="Resumo da Suspeita", padding="10")
            suspicion_frame.pack(fill=tk.X, pady=(0, 10))
            suspicion_text = f"Esta conexão foi marcada como suspeita porque sua duração ({self.details['duration']:.2f} segundos) " \
                            f"excede o limite configurado de {self.details['threshold']} segundos."
            suspicion_label = ttk.Label(suspicion_frame, text=suspicion_text, wraplength=700)
            suspicion_label.pack(fill=tk.X)
        
        graph_frame = ttk.LabelFrame(parent, text="Duração da Conexão", padding="10")
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
            reason_frame = ttk.LabelFrame(analysis_frame, text="Motivo da Suspeita", padding="10")
            reason_frame.pack(fill=tk.X, pady=(0, 10))
            reason_text = "Esta conexão foi classificada como suspeita pelos seguintes motivos:\n\n" \
                        f"1. Duração excessiva: {self.details['duration']:.2f} segundos (limite: {self.details['threshold']} segundos)\n"
            flags_history = self.details.get('flags_history', [])
            if flags_history:
                syn_count = sum(1 for f in flags_history if f & 0x02)
                fin_count = sum(1 for f in flags_history if f & 0x01)
                rst_count = sum(1 for f in flags_history if f & 0x04)
                if syn_count > 1:
                    reason_text += f"2. Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão\n"
                if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA':
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
            activity_frame = ttk.LabelFrame(analysis_frame, text="Atividade da Conexão", padding="10")
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
        packets_frame = ttk.LabelFrame(details_frame, text="Histórico de Pacotes", padding="10")
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
            packets_display.insert(tk.END, "Nenhum histórico de pacotes disponível para esta conexão.")
        packets_display.config(state=tk.DISABLED)
        
    def create_recommendations_tab(self, parent):
        recommendations_frame = ttk.Frame(parent)
        recommendations_frame.pack(fill=tk.BOTH, expand=True)
        actions_frame = ttk.LabelFrame(recommendations_frame, text="Ações Recomendadas", padding="10")
        actions_frame.pack(fill=tk.X, pady=(0, 10))
        if self.details['is_suspicious']:
            actions_text = "Com base na análise desta conexão, recomendamos as seguintes ações:\n\n"
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
            actions_text = "Esta conexão não foi classificada como suspeita. Nenhuma ação é necessária."
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
        with open(file_path, 'w') as f:
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
                f.write(f"Esta conexão foi classificada como suspeita porque sua duração ({self.details['duration']:.2f} segundos) ")
                f.write(f"excede o limite configurado de {self.details['threshold']} segundos.\n\n")
                flags_history = self.details.get('flags_history', [])
                if flags_history:
                    syn_count = sum(1 for f in flags_history if f & 0x02)
                    fin_count = sum(1 for f in flags_history if f & 0x01)
                    rst_count = sum(1 for f in flags_history if f & 0x04)
                    if syn_count > 1:
                        f.write(f"Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão\n")
                    if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA':
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
            f.write("HISTÓRICO DE PACOTES\n")
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
                f.write("Nenhum histórico de pacotes disponível para esta conexão.\n")
            f.write("\n")
            f.write("AÇÕES RECOMENDADAS\n")
            f.write("-" * 30 + "\n")
            if self.details['is_suspicious']:
                f.write("Com base na análise desta conexão, recomendamos as seguintes ações:\n\n")
                if self.details['duration'] > self.details['threshold'] * 2:
                    f.write("1. Investigar o motivo da duração extremamente longa desta conexão\n")
                    f.write("2. Verificar se esta é uma conexão legítima ou uma tentativa de manter um canal aberto indevidamente\n")
                    f.write("3. Considerar ajustar as configurações de timeout no servidor ou firewall\n")
                else:
                    f.write("1. Monitorar esta conexão para verificar se é um comportamento normal para esta aplicação\n")
                    f.write("2. Considerar ajustar o threshold de detecção se este for um comportamento esperado\n")
                if flags_history and syn_count > 1:
                    f.write(f"4. Investigar as múltiplas tentativas de iniciar conexão (SYN), possível sinal de problemas de rede ou tentativa de ataque\n")
            else:
                f.write("Esta conexão não foi classificada como suspeita. Nenhuma ação é necessária.\n")
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("Relatório gerado pelo NetSnifferX\n")
            f.write(f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write("Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt\n")
            f.write("=" * 80 + "\n")
    
    def export_as_html(self, file_path):
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        with open(file_path, 'w') as f:
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
                f.write("<p>Esta conexão foi classificada como suspeita pelos seguintes motivos:</p>\n")
                f.write("<ul>\n")
                f.write(f"  <li>Duração excessiva: {self.details['duration']:.2f} segundos (limite: {self.details['threshold']} segundos)</li>\n")
                flags_history = self.details.get('flags_history', [])
                if flags_history:
                    syn_count = sum(1 for f in flags_history if f & 0x02)
                    fin_count = sum(1 for f in flags_history if f & 0x01)
                    rst_count = sum(1 for f in flags_history if f & 0x04)
                    if syn_count > 1:
                        f.write(f"  <li>Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão</li>\n")
                    if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA':
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
            f.write("<h2>Histórico de Pacotes</h2>\n")
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
                f.write("<p>Nenhum histórico de pacotes disponível para esta conexão.</p>\n")
            f.write("<h2>Ações Recomendadas</h2>\n")
            if self.details['is_suspicious']:
                f.write("<p>Com base na análise desta conexão, recomendamos as seguintes ações:</p>\n")
                f.write("<ol>\n")
                if self.details['duration'] > self.details['threshold'] * 2:
                    f.write("  <li>Investigar o motivo da duração extremamente longa desta conexão</li>\n")
                    f.write("  <li>Verificar se esta é uma conexão legítima ou uma tentativa de manter um canal aberto indevidamente</li>\n")
                    f.write("  <li>Considerar ajustar as configurações de timeout no servidor ou firewall</li>\n")
                else:
                    f.write("  <li>Monitorar esta conexão para verificar se é um comportamento normal para esta aplicação</li>\n")
                    f.write("  <li>Considerar ajustar o threshold de detecção se este for um comportamento esperado</li>\n")
                if flags_history and syn_count > 1:
                    f.write(f"  <li>Investigar as múltiplas tentativas de iniciar conexão (SYN), possível sinal de problemas de rede ou tentativa de ataque</li>\n")
                f.write("</ol>\n")
            else:
                f.write("<p>Esta conexão não foi classificada como suspeita. Nenhuma ação é necessária.</p>\n")
            f.write("<div class='footer'>\n")
            f.write(f"  <p>Relatório gerado pelo NetSnifferX em {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>\n")
            f.write("  <p>Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt</p>\n")
            f.write("</div>\n")
            f.write("</body>\n</html>")

class AlertConfigWindow:
    """
    Janela para configurar os alertas.
    """
    def __init__(self, parent, config, callback):
        self.parent = parent
        self.config = config
        self.callback = callback # Função para chamar ao salvar
        
        self.window = tk.Toplevel(parent)
        self.window.title("Configurações de Alerta")
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
        general_frame = ttk.LabelFrame(main_frame, text="Geral", padding="10")
        general_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Checkbutton(general_frame, text="Habilitar Alertas Visuais (Pop-up)", variable=self.enable_visual).pack(anchor=tk.W)
        ttk.Checkbutton(general_frame, text="Habilitar Alertas Sonoros", variable=self.enable_sound).pack(anchor=tk.W)
        
        # --- Níveis de Gravidade ---
        severity_frame = ttk.LabelFrame(main_frame, text="Níveis de Gravidade (Multiplicador do Threshold Base)", padding="10")
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
        """Toca um som de sistema do Windows."""
        if winsound:
            try:
                winsound.PlaySound(sound_alias, winsound.SND_ALIAS | winsound.SND_ASYNC)
            except Exception as e:
                messagebox.showerror("Erro de Som", f"Não foi possível tocar o som '{sound_alias}':\n{e}")
        
    def save_and_close(self):
        """Salva as configurações e fecha a janela."""
        # Validar thresholds
        low = self.threshold_low.get()
        medium = self.threshold_medium.get()
        high = self.threshold_high.get()
        
        if not (1 < low < medium < high):
            messagebox.showerror("Erro de Validação", "Os thresholds de gravidade devem ser crescentes e maiores que 1.")
            return
            
        # Atualizar dicionário de configuração
        self.config["enable_visual_alerts"] = self.enable_visual.get()
        self.config["enable_sound_alerts"] = self.enable_sound.get()
        self.config["severity_thresholds"]["Baixo"] = low
        self.config["severity_thresholds"]["Médio"] = medium
        self.config["severity_thresholds"]["Alto"] = high
        self.config["alert_sounds"]["Baixo"] = self.sound_low.get()
        self.config["alert_sounds"]["Médio"] = self.sound_medium.get()
        self.config["alert_sounds"]["Alto"] = self.sound_high.get()
        
        # Chamar callback para salvar e aplicar
        self.callback(self.config)
        self.window.destroy()

class NetSnifferXGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSnifferX - Monitoramento de Conexões TCP")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Carregar configuração
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
        self.connection_count = 0
        self.suspicious_count = 0
        self.connections = {}
        self.alert_count = 0
        
        # Variáveis Tkinter para configurações principais
        self.timeout_threshold = tk.IntVar(value=self.config["timeout_threshold"])
        self.interface = tk.StringVar(value=self.config["interface"])
        self.filter = tk.StringVar(value=self.config["filter"])
        self.duration = tk.IntVar(value=self.config["duration"])
        
        self.create_widgets()
        self.process_packet_queue()
        self.tracker = ConnectionTracker(self.config)
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        title_label = ttk.Label(title_frame, text="NetSnifferX", style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        subtitle_label = ttk.Label(title_frame, text="Monitoramento e análise de conexões TCP em tempo real")
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        
        config_frame = ttk.LabelFrame(main_frame, text="Configurações", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(config_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.interface, width=15).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="(vazio = todas)").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="Filtro:").grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.filter, width=15).grid(row=0, column=4, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="Threshold (s):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(config_frame, from_=1, to=60, textvariable=self.timeout_threshold, width=5).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="Duração (s):").grid(row=1, column=3, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(config_frame, from_=0, to=3600, textvariable=self.duration, width=5).grid(row=1, column=4, sticky=tk.W, padx=5, pady=5)
        ttk.Label(config_frame, text="(0 = indefinido)").grid(row=1, column=5, sticky=tk.W, padx=5, pady=5)
        
        # Botão para Configurações de Alerta
        alert_config_button = ttk.Button(config_frame, text="Configurar Alertas", command=self.open_alert_config)
        alert_config_button.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        self.start_button = ttk.Button(button_frame, text="Iniciar Captura", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        self.stop_button = ttk.Button(button_frame, text="Parar Captura", command=self.stop_capture_cmd, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        self.clear_button = ttk.Button(button_frame, text="Limpar", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=(5, 0))
        
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        self.status_label = ttk.Label(stats_frame, text="Status: Pronto")
        self.status_label.pack(side=tk.LEFT)
        self.conn_count_label = ttk.Label(stats_frame, text="Conexões: 0")
        self.conn_count_label.pack(side=tk.LEFT, padx=(20, 0))
        self.suspicious_label = ttk.Label(stats_frame, text="Suspeitas: 0")
        self.suspicious_label.pack(side=tk.LEFT, padx=(20, 0))
        self.alert_label = ttk.Label(stats_frame, text="Alertas: 0", style="Alert.TLabel")
        self.alert_label.pack(side=tk.LEFT, padx=(20, 0))
        
        display_frame = ttk.LabelFrame(main_frame, text="Conexões TCP Detectadas", padding="10")
        display_frame.pack(fill=tk.BOTH, expand=True)
        header_frame = ttk.Frame(display_frame)
        header_frame.pack(fill=tk.X)
        ttk.Label(header_frame, text="Horário", width=10, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Origem", width=22, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Destino", width=22, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Status", width=12, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Duração (s)", width=10, style="Header.TLabel").pack(side=tk.LEFT)
        self.connection_display = scrolledtext.ScrolledText(display_frame, wrap=tk.WORD, height=20)
        self.connection_display.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.connection_display.config(state=tk.DISABLED)
        self.connection_display.bind("<Double-1>", self.on_connection_click)
        
        legend_frame = ttk.LabelFrame(main_frame, text="Legenda", padding="5")
        legend_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(legend_frame, text="Iniciando", foreground="blue").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Em Andamento", foreground="black").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Finalizada", foreground="green").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Suspeita", foreground="red").pack(side=tk.LEFT)
        tip_label = ttk.Label(legend_frame, text="Dica: Clique duplo em uma conexão suspeita para ver relatório detalhado", font=("Arial", 8, "italic"))
        tip_label.pack(side=tk.RIGHT)
        
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(footer_frame, text="Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt").pack(side=tk.LEFT)
        
    def open_alert_config(self):
        """Abre a janela de configuração de alertas."""
        AlertConfigWindow(self.root, self.config, self.save_alert_config)
        
    def save_alert_config(self, new_config):
        """Salva e aplica as novas configurações de alerta."""
        self.config = new_config
        save_config(self.config)
        # Atualizar o tracker com a nova config, se necessário
        if self.is_capturing:
            messagebox.showinfo("Configuração Salva", "As novas configurações de alerta serão aplicadas na próxima captura.")
        else:
            self.tracker = ConnectionTracker(self.config)
            messagebox.showinfo("Configuração Salva", "Configurações de alerta salvas com sucesso.")
            
    def start_capture(self):
        if self.is_capturing:
            return
        
        # Atualizar config com valores da UI principal
        self.config["timeout_threshold"] = self.timeout_threshold.get()
        self.config["interface"] = self.interface.get()
        self.config["filter"] = self.filter.get()
        self.config["duration"] = self.duration.get()
        save_config(self.config) # Salvar config principal também
        
        self.tracker = ConnectionTracker(self.config)
        self.connection_count = 0
        self.suspicious_count = 0
        self.alert_count = 0
        self.connections = {}
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
            from scapy.config import conf
            sniff(
                filter=filter_str,
                prn=self.packet_handler,
                store=0,
                iface=iface,
                timeout=duration,
                stop_filter=lambda _: self.stop_capture.is_set(),
                L2socket=conf.L3socket
            )
        except Exception as e:
            self.packet_queue.put(("ERROR", f"Erro durante a captura: {e}"))
        finally:
            self.is_capturing = False
            self.packet_queue.put(("STATUS", "Pronto"))
    
    def packet_handler(self, packet):
        if TCP in packet:
            conn_info = self.tracker.track_packet(packet)
            if conn_info:
                self.packet_queue.put(("PACKET", conn_info))
    
    def process_packet_queue(self):
        try:
            while not self.packet_queue.empty():
                msg_type, data = self.packet_queue.get_nowait()
                if msg_type == "PACKET":
                    self.display_connection(data)
                    self.connection_count += 1
                    if data['is_suspicious']:
                        self.suspicious_count += 1
                    self.update_stats()
                    self.connections[data['id']] = data
                    if data.get('trigger_alert', False):
                        self.trigger_alert(data)
                elif msg_type == "ERROR":
                    self.display_error(data)
                elif msg_type == "STATUS":
                    self.status_label.config(text=f"Status: {data}")
                    if data == "Pronto":
                        self.start_button.config(state=tk.NORMAL)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_packet_queue)
    
    def display_connection(self, conn_info):
        src_ip, src_port, dst_ip, dst_port = conn_info['id']
        status = conn_info['status']
        duration = round(conn_info['duration'], 2)
        if conn_info['is_suspicious']:
            color = "red"
        elif status == 'INICIANDO':
            color = "blue"
        elif status == 'FINALIZADA':
            color = "green"
        else:
            color = "black"
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        line = f"{timestamp:<10} {src_ip}:{src_port:<22} {dst_ip}:{dst_port:<22} {status:<12} {duration:<10.2f}\n"
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.insert(tk.END, line, color)
        self.connection_display.tag_config(color, foreground=color)
        self.connection_display.see(tk.END)
        self.connection_display.config(state=tk.DISABLED)
    
    def display_error(self, error_msg):
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.insert(tk.END, f"ERRO: {error_msg}\n", "error")
        self.connection_display.tag_config("error", foreground="red")
        self.connection_display.see(tk.END)
        self.connection_display.config(state=tk.DISABLED)
        messagebox.showerror("Erro", error_msg)
        self.is_capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Erro")
    
    def update_stats(self):
        self.conn_count_label.config(text=f"Conexões: {self.connection_count}")
        self.suspicious_label.config(text=f"Suspeitas: {self.suspicious_count}")
        self.alert_label.config(text=f"Alertas: {self.alert_count}")
    
    def clear_display(self):
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.delete(1.0, tk.END)
        self.connection_display.config(state=tk.DISABLED)
        self.connection_count = 0
        self.suspicious_count = 0
        self.alert_count = 0
        self.connections = {}
        self.update_stats()
    
    def on_connection_click(self, event):
        try:
            index = self.connection_display.index(f"@{event.x},{event.y}")
            line_start = self.connection_display.index(f"{index} linestart")
            line_end = self.connection_display.index(f"{index} lineend")
            line = self.connection_display.get(line_start, line_end)
            if not line or len(line.split()) < 5:
                return
            parts = line.split()
            if len(parts) < 5:
                return
            src_parts = parts[1].split(':')
            dst_parts = parts[2].split(':')
            if len(src_parts) < 2 or len(dst_parts) < 2:
                return
            src_ip = src_parts[0]
            src_port = int(src_parts[1])
            dst_ip = dst_parts[0]
            dst_port = int(dst_parts[1])
            conn_id = (src_ip, src_port, dst_ip, dst_port)
            if conn_id in self.connections and self.connections[conn_id]['is_suspicious']:
                conn_details = self.tracker.get_connection_details(conn_id)
                if conn_details:
                    ConnectionReportWindow(self.root, conn_details)
                else:
                    messagebox.showinfo("Informação", "Detalhes da conexão não disponíveis.")
            else:
                messagebox.showinfo("Informação", "Relatórios detalhados estão disponíveis apenas para conexões suspeitas.")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao processar clique: {e}")
    
    def trigger_alert(self, conn_info):
        self.alert_count += 1
        self.update_stats()
        src_ip, src_port, dst_ip, dst_port = conn_info['id']
        severity = conn_info['severity']
        if self.config["enable_visual_alerts"]:
            alert_title = f"Alerta de Conexão Suspeita ({severity})"
            alert_message = f"Conexão suspeita detectada:\n"
            alert_message += f"Origem: {src_ip}:{src_port}\n"
            alert_message += f"Destino: {dst_ip}:{dst_port}\n"
            alert_message += f"Duração: {conn_info['duration']:.2f}s\n"
            alert_message += f"Gravidade: {severity}"
            messagebox.showwarning(alert_title, alert_message)
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
            self.alert_label.config(foreground="red")

def main():
    root = tk.Tk()
    app = NetSnifferXGUI(root)
    def on_closing():
        if app.is_capturing:
            if messagebox.askokcancel("Sair", "A captura está em andamento. Deseja realmente sair?"):
                app.stop_capture.set()
                # Salvar config ao sair
                app.config["timeout_threshold"] = app.timeout_threshold.get()
                app.config["interface"] = app.interface.get()
                app.config["filter"] = app.filter.get()
                app.config["duration"] = app.duration.get()
                save_config(app.config)
                root.destroy()
        else:
            # Salvar config ao sair
            app.config["timeout_threshold"] = app.timeout_threshold.get()
            app.config["interface"] = app.interface.get()
            app.config["filter"] = app.filter.get()
            app.config["duration"] = app.duration.get()
            save_config(app.config)
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
