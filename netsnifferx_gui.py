#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetSnifferX - Monitoramento e análise de conexões TCP em tempo real com interface gráfica
Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt

NOTA IMPORTANTE: Este script requer privilégios de administrador para capturar pacotes.
Execute com: python netsnifferx_gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import datetime
import argparse
import queue
from scapy.all import sniff, TCP

class ConnectionTracker:
    """
    Classe responsável por rastrear e gerenciar conexões TCP ativas.
    """
    def __init__(self, timeout_threshold=10):
        """
        Inicializa o rastreador de conexões.
        
        Args:
            timeout_threshold (int): Tempo em segundos para considerar uma conexão como longa/suspeita
        """
        self.connections = {}  # Dicionário para armazenar conexões ativas
        self.timeout_threshold = timeout_threshold
        
    def get_connection_id(self, packet):
        """
        Gera um ID único para a conexão baseado nos IPs e portas.
        
        Args:
            packet: Pacote TCP capturado
            
        Returns:
            tuple: Tupla contendo (IP origem, porta origem, IP destino, porta destino)
        """
        if TCP in packet and hasattr(packet, 'src') and hasattr(packet, 'dst'):
            return (packet.src, packet[TCP].sport, packet.dst, packet[TCP].dport)
        return None
    
    def track_packet(self, packet):
        """
        Rastreia um pacote TCP e atualiza o estado das conexões.
        
        Args:
            packet: Pacote TCP capturado
            
        Returns:
            dict: Informações sobre a conexão processada ou None
        """
        if TCP not in packet:
            return None
        
        conn_id = self.get_connection_id(packet)
        if not conn_id:
            return None
        
        current_time = time.time()
        flags = packet[TCP].flags
        
        # Verifica se é início de conexão (SYN)
        if flags & 0x02:  # SYN flag
            self.connections[conn_id] = {
                'start_time': current_time,
                'last_update': current_time,
                'status': 'INICIANDO',
                'packets': 1
            }
            return {
                'id': conn_id,
                'status': 'INICIANDO',
                'duration': 0,
                'is_suspicious': False
            }
        
        # Verifica se é fim de conexão (FIN ou RST)
        elif (flags & 0x01) or (flags & 0x04):  # FIN or RST flags
            if conn_id in self.connections:
                duration = current_time - self.connections[conn_id]['start_time']
                is_suspicious = duration > self.timeout_threshold
                status = 'FINALIZADA'
                
                result = {
                    'id': conn_id,
                    'status': status,
                    'duration': duration,
                    'is_suspicious': is_suspicious
                }
                
                # Remove a conexão da lista de ativas
                del self.connections[conn_id]
                return result
        
        # Atualiza conexão existente
        elif conn_id in self.connections:
            self.connections[conn_id]['last_update'] = current_time
            self.connections[conn_id]['packets'] += 1
            
            duration = current_time - self.connections[conn_id]['start_time']
            is_suspicious = duration > self.timeout_threshold
            
            if is_suspicious and self.connections[conn_id]['status'] != 'SUSPEITA':
                self.connections[conn_id]['status'] = 'SUSPEITA'
            
            return {
                'id': conn_id,
                'status': self.connections[conn_id]['status'],
                'duration': duration,
                'is_suspicious': is_suspicious
            }
        
        # Nova conexão detectada no meio (pacote sem SYN inicial)
        else:
            self.connections[conn_id] = {
                'start_time': current_time,
                'last_update': current_time,
                'status': 'EM ANDAMENTO',
                'packets': 1
            }
            return {
                'id': conn_id,
                'status': 'EM ANDAMENTO',
                'duration': 0,
                'is_suspicious': False
            }

class NetSnifferXGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSnifferX - Monitoramento de Conexões TCP")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Configuração de estilo
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("Header.TLabel", font=("Arial", 12, "bold"))
        self.style.configure("Title.TLabel", font=("Arial", 16, "bold"))
        
        # Variáveis
        self.is_capturing = False
        self.capture_thread = None
        self.stop_capture = threading.Event()
        self.packet_queue = queue.Queue()
        self.timeout_threshold = tk.IntVar(value=10)
        self.interface = tk.StringVar(value="")
        self.filter = tk.StringVar(value="tcp")
        self.duration = tk.IntVar(value=0)
        self.connection_count = 0
        self.suspicious_count = 0
        
        # Criar layout
        self.create_widgets()
        
        # Iniciar processamento de pacotes na fila
        self.process_packet_queue()
        
        # Tracker de conexões
        self.tracker = ConnectionTracker(timeout_threshold=self.timeout_threshold.get())
        
    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(title_frame, text="NetSnifferX", style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = ttk.Label(title_frame, text="Monitoramento e análise de conexões TCP em tempo real")
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Frame de configurações
        config_frame = ttk.LabelFrame(main_frame, text="Configurações", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Grid de configurações
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
        
        # Frame de botões
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_button = ttk.Button(button_frame, text="Iniciar Captura", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_button = ttk.Button(button_frame, text="Parar Captura", command=self.stop_capture_cmd, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        
        self.clear_button = ttk.Button(button_frame, text="Limpar", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=(5, 0))
        
        # Frame de estatísticas
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = ttk.Label(stats_frame, text="Status: Pronto")
        self.status_label.pack(side=tk.LEFT)
        
        self.conn_count_label = ttk.Label(stats_frame, text="Conexões: 0")
        self.conn_count_label.pack(side=tk.LEFT, padx=(20, 0))
        
        self.suspicious_label = ttk.Label(stats_frame, text="Suspeitas: 0")
        self.suspicious_label.pack(side=tk.LEFT, padx=(20, 0))
        
        # Frame de exibição
        display_frame = ttk.LabelFrame(main_frame, text="Conexões TCP Detectadas", padding="10")
        display_frame.pack(fill=tk.BOTH, expand=True)
        
        # Cabeçalho da tabela
        header_frame = ttk.Frame(display_frame)
        header_frame.pack(fill=tk.X)
        
        ttk.Label(header_frame, text="Horário", width=10, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Origem", width=22, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Destino", width=22, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Status", width=12, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Duração (s)", width=10, style="Header.TLabel").pack(side=tk.LEFT)
        
        # Área de texto para exibição das conexões
        self.connection_display = scrolledtext.ScrolledText(display_frame, wrap=tk.WORD, height=20)
        self.connection_display.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.connection_display.config(state=tk.DISABLED)
        
        # Legenda
        legend_frame = ttk.LabelFrame(main_frame, text="Legenda", padding="5")
        legend_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(legend_frame, text="Iniciando", foreground="blue").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Em Andamento", foreground="black").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Finalizada", foreground="green").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Suspeita", foreground="red").pack(side=tk.LEFT)
        
        # Rodapé
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(footer_frame, text="Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt").pack(side=tk.LEFT)
        
    def start_capture(self):
        if self.is_capturing:
            return
        
        # Atualizar o tracker com o novo threshold
        self.tracker = ConnectionTracker(timeout_threshold=self.timeout_threshold.get())
        
        # Limpar contadores
        self.connection_count = 0
        self.suspicious_count = 0
        self.update_stats()
        
        # Atualizar interface
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Capturando...")
        
        # Iniciar captura em thread separada
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
            # Preparar parâmetros
            iface = self.interface.get() if self.interface.get() else None
            filter_str = self.filter.get()
            duration = self.duration.get() if self.duration.get() > 0 else None
            
            # Usar L3socket para compatibilidade com Windows
            from scapy.config import conf
            
            # Iniciar captura
            sniff(
                filter=filter_str,
                prn=self.packet_handler,
                store=0,
                iface=iface,
                timeout=duration,
                stop_filter=lambda _: self.stop_capture.is_set(),
                L2socket=conf.L3socket  # Usar L3socket em vez do padrão
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
                
                elif msg_type == "ERROR":
                    self.display_error(data)
                
                elif msg_type == "STATUS":
                    self.status_label.config(text=f"Status: {data}")
                    if data == "Pronto":
                        self.start_button.config(state=tk.NORMAL)
        
        except queue.Empty:
            pass
        finally:
            # Agendar próxima verificação
            self.root.after(100, self.process_packet_queue)
    
    def display_connection(self, conn_info):
        src_ip, src_port, dst_ip, dst_port = conn_info['id']
        status = conn_info['status']
        duration = round(conn_info['duration'], 2)
        
        # Definir cor com base no status
        if conn_info['is_suspicious']:
            color = "red"
        elif status == 'INICIANDO':
            color = "blue"
        elif status == 'FINALIZADA':
            color = "green"
        else:
            color = "black"
        
        # Formatar linha
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        line = f"{timestamp:<10} {src_ip}:{src_port:<22} {dst_ip}:{dst_port:<22} {status:<12} {duration:<10.2f}\n"
        
        # Adicionar à área de texto
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
        
        # Resetar interface
        self.is_capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Erro")
    
    def update_stats(self):
        self.conn_count_label.config(text=f"Conexões: {self.connection_count}")
        self.suspicious_label.config(text=f"Suspeitas: {self.suspicious_count}")
    
    def clear_display(self):
        self.connection_display.config(state=tk.NORMAL)
        self.connection_display.delete(1.0, tk.END)
        self.connection_display.config(state=tk.DISABLED)
        
        # Resetar contadores
        self.connection_count = 0
        self.suspicious_count = 0
        self.update_stats()

def main():
    root = tk.Tk()
    app = NetSnifferXGUI(root)
    
    # Configurar encerramento limpo
    def on_closing():
        if app.is_capturing:
            if messagebox.askokcancel("Sair", "A captura está em andamento. Deseja realmente sair?"):
                app.stop_capture.set()
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Iniciar loop principal
    root.mainloop()

if __name__ == "__main__":
    main()
