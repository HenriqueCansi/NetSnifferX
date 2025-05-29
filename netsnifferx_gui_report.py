#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetSnifferX - Monitoramento e análise de conexões TCP em tempo real com interface gráfica
Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt

NOTA IMPORTANTE: Este script requer privilégios de administrador para capturar pacotes.
Execute com: python netsnifferx_gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import datetime
import argparse
import queue
import os
from scapy.all import sniff, TCP
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

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
        self.connection_history = {}  # Histórico de pacotes por conexão
        self.max_history_packets = 100  # Máximo de pacotes armazenados por conexão
        
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
    
    def store_packet_history(self, conn_id, packet):
        """
        Armazena o pacote no histórico da conexão.
        
        Args:
            conn_id: ID da conexão
            packet: Pacote TCP capturado
        """
        if conn_id not in self.connection_history:
            self.connection_history[conn_id] = []
            
        # Adicionar pacote ao histórico com timestamp
        packet_info = {
            'timestamp': time.time(),
            'flags': packet[TCP].flags,
            'size': len(packet),
            'seq': packet[TCP].seq if hasattr(packet[TCP], 'seq') else 0,
            'ack': packet[TCP].ack if hasattr(packet[TCP], 'ack') else 0,
            'window': packet[TCP].window if hasattr(packet[TCP], 'window') else 0
        }
        
        # Limitar o tamanho do histórico (buffer circular)
        if len(self.connection_history[conn_id]) >= self.max_history_packets:
            self.connection_history[conn_id].pop(0)
            
        self.connection_history[conn_id].append(packet_info)
    
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
        
        # Armazenar pacote no histórico
        self.store_packet_history(conn_id, packet)
        
        current_time = time.time()
        flags = packet[TCP].flags
        
        # Verifica se é início de conexão (SYN)
        if flags & 0x02:  # SYN flag
            self.connections[conn_id] = {
                'start_time': current_time,
                'last_update': current_time,
                'status': 'INICIANDO',
                'packets': 1,
                'flags_history': [flags]
            }
            return {
                'id': conn_id,
                'status': 'INICIANDO',
                'duration': 0,
                'is_suspicious': False,
                'packet_count': 1
            }
        
        # Verifica se é fim de conexão (FIN ou RST)
        elif (flags & 0x01) or (flags & 0x04):  # FIN or RST flags
            if conn_id in self.connections:
                # Atualizar histórico de flags
                self.connections[conn_id]['flags_history'].append(flags)
                
                duration = current_time - self.connections[conn_id]['start_time']
                is_suspicious = duration > self.timeout_threshold
                status = 'FINALIZADA'
                packet_count = self.connections[conn_id]['packets']
                
                result = {
                    'id': conn_id,
                    'status': status,
                    'duration': duration,
                    'is_suspicious': is_suspicious,
                    'packet_count': packet_count,
                    'flags_history': self.connections[conn_id]['flags_history']
                }
                
                # Remove a conexão da lista de ativas
                del self.connections[conn_id]
                return result
        
        # Atualiza conexão existente
        elif conn_id in self.connections:
            self.connections[conn_id]['last_update'] = current_time
            self.connections[conn_id]['packets'] += 1
            
            # Atualizar histórico de flags
            self.connections[conn_id]['flags_history'].append(flags)
            
            duration = current_time - self.connections[conn_id]['start_time']
            is_suspicious = duration > self.timeout_threshold
            
            if is_suspicious and self.connections[conn_id]['status'] != 'SUSPEITA':
                self.connections[conn_id]['status'] = 'SUSPEITA'
            
            return {
                'id': conn_id,
                'status': self.connections[conn_id]['status'],
                'duration': duration,
                'is_suspicious': is_suspicious,
                'packet_count': self.connections[conn_id]['packets'],
                'flags_history': self.connections[conn_id]['flags_history']
            }
        
        # Nova conexão detectada no meio (pacote sem SYN inicial)
        else:
            self.connections[conn_id] = {
                'start_time': current_time,
                'last_update': current_time,
                'status': 'EM ANDAMENTO',
                'packets': 1,
                'flags_history': [flags]
            }
            return {
                'id': conn_id,
                'status': 'EM ANDAMENTO',
                'duration': 0,
                'is_suspicious': False,
                'packet_count': 1,
                'flags_history': [flags]
            }
    
    def get_connection_details(self, conn_id):
        """
        Obtém detalhes completos de uma conexão para o relatório.
        
        Args:
            conn_id: ID da conexão
            
        Returns:
            dict: Detalhes da conexão ou None se não encontrada
        """
        # Verificar se a conexão está ativa
        if conn_id in self.connections:
            conn = self.connections[conn_id]
            current_time = time.time()
            duration = current_time - conn['start_time']
            
            details = {
                'id': conn_id,
                'start_time': conn['start_time'],
                'last_update': conn['last_update'],
                'status': conn['status'],
                'duration': duration,
                'packet_count': conn['packets'],
                'is_suspicious': duration > self.timeout_threshold,
                'flags_history': conn['flags_history'],
                'threshold': self.timeout_threshold
            }
            
            # Adicionar histórico de pacotes se disponível
            if conn_id in self.connection_history:
                details['packet_history'] = self.connection_history[conn_id]
            else:
                details['packet_history'] = []
                
            return details
            
        # Verificar no histórico para conexões finalizadas
        elif conn_id in self.connection_history:
            # Para conexões finalizadas, temos apenas o histórico de pacotes
            # Tentar reconstruir informações básicas
            packets = self.connection_history[conn_id]
            if not packets:
                return None
                
            first_packet = packets[0]
            last_packet = packets[-1]
            
            details = {
                'id': conn_id,
                'start_time': first_packet['timestamp'],
                'last_update': last_packet['timestamp'],
                'status': 'FINALIZADA',
                'duration': last_packet['timestamp'] - first_packet['timestamp'],
                'packet_count': len(packets),
                'is_suspicious': (last_packet['timestamp'] - first_packet['timestamp']) > self.timeout_threshold,
                'flags_history': [p['flags'] for p in packets],
                'threshold': self.timeout_threshold,
                'packet_history': packets
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
        
        # Criar janela
        self.window = tk.Toplevel(parent)
        self.window.title("Relatório Detalhado de Conexão")
        self.window.geometry("800x600")
        self.window.minsize(700, 500)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Configurar estilo
        self.style = ttk.Style()
        self.style.configure("Title.TLabel", font=("Arial", 12, "bold"))
        self.style.configure("Header.TLabel", font=("Arial", 10, "bold"))
        
        # Criar interface
        self.create_widgets()
        
    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        title_text = f"Conexão: {src_ip}:{src_port} → {dst_ip}:{dst_port}"
        title_label = ttk.Label(main_frame, text=title_text, style="Title.TLabel")
        title_label.pack(fill=tk.X, pady=(0, 10))
        
        # Notebook (abas)
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Aba de resumo
        summary_frame = ttk.Frame(notebook, padding="10")
        notebook.add(summary_frame, text="Resumo")
        self.create_summary_tab(summary_frame)
        
        # Aba de análise
        analysis_frame = ttk.Frame(notebook, padding="10")
        notebook.add(analysis_frame, text="Análise de Suspeita")
        self.create_analysis_tab(analysis_frame)
        
        # Aba de detalhes técnicos
        details_frame = ttk.Frame(notebook, padding="10")
        notebook.add(details_frame, text="Detalhes Técnicos")
        self.create_details_tab(details_frame)
        
        # Aba de recomendações
        recommendations_frame = ttk.Frame(notebook, padding="10")
        notebook.add(recommendations_frame, text="Recomendações")
        self.create_recommendations_tab(recommendations_frame)
        
        # Botões
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        export_button = ttk.Button(button_frame, text="Exportar Relatório", command=self.export_report)
        export_button.pack(side=tk.LEFT, padx=(0, 5))
        
        close_button = ttk.Button(button_frame, text="Fechar", command=self.window.destroy)
        close_button.pack(side=tk.LEFT)
        
    def create_summary_tab(self, parent):
        # Informações básicas da conexão
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        
        # Frame de informações
        info_frame = ttk.LabelFrame(parent, text="Informações da Conexão", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Grid de informações
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
        
        # Colorir o status
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
        
        # Resumo da suspeita
        if self.details['is_suspicious']:
            suspicion_frame = ttk.LabelFrame(parent, text="Resumo da Suspeita", padding="10")
            suspicion_frame.pack(fill=tk.X, pady=(0, 10))
            
            suspicion_text = f"Esta conexão foi marcada como suspeita porque sua duração ({self.details['duration']:.2f} segundos) " \
                            f"excede o limite configurado de {self.details['threshold']} segundos."
            
            suspicion_label = ttk.Label(suspicion_frame, text=suspicion_text, wraplength=700)
            suspicion_label.pack(fill=tk.X)
        
        # Gráfico simples de duração
        graph_frame = ttk.LabelFrame(parent, text="Duração da Conexão", padding="10")
        graph_frame.pack(fill=tk.BOTH, expand=True)
        
        fig, ax = plt.subplots(figsize=(5, 3))
        
        # Dados para o gráfico
        durations = [self.details['duration']]
        threshold = [self.details['threshold']]
        labels = ['Duração Atual']
        
        # Criar barras
        bars = ax.bar(labels, durations, color='blue')
        
        # Adicionar linha de threshold
        ax.axhline(y=self.details['threshold'], color='red', linestyle='--', label=f'Threshold ({self.details["threshold"]}s)')
        
        # Colorir a barra baseado na suspeita
        if self.details['is_suspicious']:
            bars[0].set_color('red')
        
        ax.set_ylabel('Segundos')
        ax.set_title('Duração vs. Threshold')
        ax.legend()
        
        # Adicionar o gráfico ao frame
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_analysis_tab(self, parent):
        # Frame de análise
        analysis_frame = ttk.Frame(parent)
        analysis_frame.pack(fill=tk.BOTH, expand=True)
        
        # Motivo da suspeita
        if self.details['is_suspicious']:
            reason_frame = ttk.LabelFrame(analysis_frame, text="Motivo da Suspeita", padding="10")
            reason_frame.pack(fill=tk.X, pady=(0, 10))
            
            reason_text = "Esta conexão foi classificada como suspeita pelos seguintes motivos:\n\n" \
                        f"1. Duração excessiva: {self.details['duration']:.2f} segundos (limite: {self.details['threshold']} segundos)\n"
            
            # Analisar padrões de flags
            flags_history = self.details.get('flags_history', [])
            if flags_history:
                syn_count = sum(1 for f in flags_history if f & 0x02)  # SYN
                fin_count = sum(1 for f in flags_history if f & 0x01)  # FIN
                rst_count = sum(1 for f in flags_history if f & 0x04)  # RST
                
                if syn_count > 1:
                    reason_text += f"2. Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão\n"
                
                if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA':
                    reason_text += "3. Conexão não finalizada corretamente (sem flags FIN ou RST)\n"
            
            reason_label = ttk.Label(reason_frame, text=reason_text, wraplength=700, justify=tk.LEFT)
            reason_label.pack(fill=tk.X)
        
        # Histórico de flags
        flags_frame = ttk.LabelFrame(analysis_frame, text="Histórico de Flags TCP", padding="10")
        flags_frame.pack(fill=tk.X, pady=(0, 10))
        
        flags_text = ttk.Label(flags_frame, text="Sequência de flags TCP observados nesta conexão:", wraplength=700)
        flags_text.pack(fill=tk.X, pady=(0, 5))
        
        # Criar área de texto para exibir flags
        flags_display = scrolledtext.ScrolledText(flags_frame, wrap=tk.WORD, height=5)
        flags_display.pack(fill=tk.X)
        
        # Preencher com histórico de flags
        flags_history = self.details.get('flags_history', [])
        if flags_history:
            flags_display.insert(tk.END, "Sequência de flags (mais recentes por último):\n")
            
            for i, flags in enumerate(flags_history):
                flag_str = self.format_tcp_flags(flags)
                flags_display.insert(tk.END, f"{i+1}. {flag_str}\n")
        else:
            flags_display.insert(tk.END, "Nenhum histórico de flags disponível para esta conexão.")
        
        flags_display.config(state=tk.DISABLED)
        
        # Gráfico de atividade
        if 'packet_history' in self.details and self.details['packet_history']:
            activity_frame = ttk.LabelFrame(analysis_frame, text="Atividade da Conexão", padding="10")
            activity_frame.pack(fill=tk.BOTH, expand=True)
            
            fig, ax = plt.subplots(figsize=(5, 3))
            
            # Extrair dados do histórico
            history = self.details['packet_history']
            timestamps = [p['timestamp'] - self.details['start_time'] for p in history]  # Tempo relativo ao início
            sizes = [p['size'] for p in history]
            
            # Plotar tamanhos de pacotes ao longo do tempo
            ax.plot(timestamps, sizes, 'o-', label='Tamanho do Pacote')
            
            # Marcar o threshold
            ax.axvline(x=self.details['threshold'], color='red', linestyle='--', 
                      label=f'Threshold ({self.details["threshold"]}s)')
            
            ax.set_xlabel('Tempo (segundos)')
            ax.set_ylabel('Tamanho do Pacote (bytes)')
            ax.set_title('Atividade da Conexão ao Longo do Tempo')
            ax.legend()
            
            # Adicionar o gráfico ao frame
            canvas = FigureCanvasTkAgg(fig, master=activity_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_details_tab(self, parent):
        # Frame de detalhes
        details_frame = ttk.Frame(parent)
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        # Histórico de pacotes
        packets_frame = ttk.LabelFrame(details_frame, text="Histórico de Pacotes", padding="10")
        packets_frame.pack(fill=tk.BOTH, expand=True)
        
        # Cabeçalho da tabela
        header_frame = ttk.Frame(packets_frame)
        header_frame.pack(fill=tk.X)
        
        ttk.Label(header_frame, text="#", width=5, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Tempo", width=10, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Flags", width=15, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Tamanho", width=10, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="SEQ", width=12, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="ACK", width=12, style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(header_frame, text="Window", width=10, style="Header.TLabel").pack(side=tk.LEFT)
        
        # Área de texto para exibir pacotes
        packets_display = scrolledtext.ScrolledText(packets_frame, wrap=tk.WORD, height=15)
        packets_display.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Preencher com histórico de pacotes
        if 'packet_history' in self.details and self.details['packet_history']:
            history = self.details['packet_history']
            
            for i, packet in enumerate(history):
                # Calcular tempo relativo
                rel_time = packet['timestamp'] - self.details['start_time']
                
                # Formatar flags
                flag_str = self.format_tcp_flags(packet['flags'])
                
                # Formatar linha
                line = f"{i+1:<5} {rel_time:<10.2f} {flag_str:<15} {packet['size']:<10} "
                line += f"{packet['seq']:<12} {packet['ack']:<12} {packet['window']:<10}\n"
                
                # Colorir pacotes após o threshold
                if rel_time > self.details['threshold']:
                    packets_display.insert(tk.END, line, "suspicious")
                else:
                    packets_display.insert(tk.END, line)
            
            # Configurar tags
            packets_display.tag_config("suspicious", foreground="red")
        else:
            packets_display.insert(tk.END, "Nenhum histórico de pacotes disponível para esta conexão.")
        
        packets_display.config(state=tk.DISABLED)
        
    def create_recommendations_tab(self, parent):
        # Frame de recomendações
        recommendations_frame = ttk.Frame(parent)
        recommendations_frame.pack(fill=tk.BOTH, expand=True)
        
        # Recomendações baseadas na análise
        actions_frame = ttk.LabelFrame(recommendations_frame, text="Ações Recomendadas", padding="10")
        actions_frame.pack(fill=tk.X, pady=(0, 10))
        
        if self.details['is_suspicious']:
            actions_text = "Com base na análise desta conexão, recomendamos as seguintes ações:\n\n"
            
            # Recomendações específicas baseadas no tipo de suspeita
            if self.details['duration'] > self.details['threshold'] * 2:
                actions_text += "1. Investigar o motivo da duração extremamente longa desta conexão\n"
                actions_text += "2. Verificar se esta é uma conexão legítima ou uma tentativa de manter um canal aberto indevidamente\n"
                actions_text += "3. Considerar ajustar as configurações de timeout no servidor ou firewall\n"
            else:
                actions_text += "1. Monitorar esta conexão para verificar se é um comportamento normal para esta aplicação\n"
                actions_text += "2. Considerar ajustar o threshold de detecção se este for um comportamento esperado\n"
            
            # Verificar padrões de flags
            flags_history = self.details.get('flags_history', [])
            if flags_history:
                syn_count = sum(1 for f in flags_history if f & 0x02)  # SYN
                
                if syn_count > 1:
                    actions_text += f"4. Investigar as múltiplas tentativas de iniciar conexão (SYN), possível sinal de problemas de rede ou tentativa de ataque\n"
        else:
            actions_text = "Esta conexão não foi classificada como suspeita. Nenhuma ação é necessária."
        
        actions_label = ttk.Label(actions_frame, text=actions_text, wraplength=700, justify=tk.LEFT)
        actions_label.pack(fill=tk.X)
        
        # Informações adicionais
        info_frame = ttk.LabelFrame(recommendations_frame, text="Informações Adicionais", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        info_text = "Para mais informações sobre análise de conexões TCP e segurança de rede, consulte:\n\n"
        info_text += "• RFC 793: Transmission Control Protocol\n"
        info_text += "• RFC 7414: A Roadmap for TCP Specification Documents\n"
        info_text += "• NIST SP 800-123: Guide to General Server Security\n"
        
        info_label = ttk.Label(info_frame, text=info_text, wraplength=700, justify=tk.LEFT)
        info_label.pack(fill=tk.X)
        
    def format_tcp_flags(self, flags):
        """
        Formata as flags TCP para exibição.
        
        Args:
            flags: Valor numérico das flags TCP
            
        Returns:
            str: String formatada com as flags ativas
        """
        flag_map = {
            0x01: 'FIN',
            0x02: 'SYN',
            0x04: 'RST',
            0x08: 'PSH',
            0x10: 'ACK',
            0x20: 'URG',
            0x40: 'ECE',
            0x80: 'CWR'
        }
        
        active_flags = []
        for bit, name in flag_map.items():
            if flags & bit:
                active_flags.append(name)
                
        if active_flags:
            return '+'.join(active_flags)
        else:
            return 'NONE'
    
    def export_report(self):
        """
        Exporta o relatório para um arquivo.
        """
        # Perguntar onde salvar
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivos de texto", "*.txt"), ("Arquivos HTML", "*.html"), ("Todos os arquivos", "*.*")],
            title="Salvar Relatório Como"
        )
        
        if not file_path:
            return
        
        try:
            # Determinar formato baseado na extensão
            if file_path.endswith('.html'):
                self.export_as_html(file_path)
            else:
                self.export_as_text(file_path)
                
            messagebox.showinfo("Exportação Concluída", f"Relatório exportado com sucesso para:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Erro na Exportação", f"Ocorreu um erro ao exportar o relatório:\n{e}")
    
    def export_as_text(self, file_path):
        """
        Exporta o relatório como texto simples.
        
        Args:
            file_path: Caminho do arquivo para salvar
        """
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        
        with open(file_path, 'w') as f:
            # Título
            f.write("=" * 80 + "\n")
            f.write(f"RELATÓRIO DETALHADO DE CONEXÃO TCP\n")
            f.write("=" * 80 + "\n\n")
            
            # Informações básicas
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
            f.write(f"Suspeita: {'Sim' if self.details['is_suspicious'] else 'Não'}\n\n")
            
            # Análise de suspeita
            if self.details['is_suspicious']:
                f.write("ANÁLISE DE SUSPEITA\n")
                f.write("-" * 30 + "\n")
                f.write(f"Esta conexão foi classificada como suspeita porque sua duração ({self.details['duration']:.2f} segundos) ")
                f.write(f"excede o limite configurado de {self.details['threshold']} segundos.\n\n")
                
                # Analisar padrões de flags
                flags_history = self.details.get('flags_history', [])
                if flags_history:
                    syn_count = sum(1 for f in flags_history if f & 0x02)  # SYN
                    fin_count = sum(1 for f in flags_history if f & 0x01)  # FIN
                    rst_count = sum(1 for f in flags_history if f & 0x04)  # RST
                    
                    if syn_count > 1:
                        f.write(f"Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão\n")
                    
                    if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA':
                        f.write("Conexão não finalizada corretamente (sem flags FIN ou RST)\n")
                
                f.write("\n")
            
            # Histórico de flags
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
            
            # Histórico de pacotes
            f.write("HISTÓRICO DE PACOTES\n")
            f.write("-" * 30 + "\n")
            
            if 'packet_history' in self.details and self.details['packet_history']:
                f.write(f"{'#':<5} {'Tempo':<10} {'Flags':<15} {'Tamanho':<10} {'SEQ':<12} {'ACK':<12} {'Window':<10}\n")
                f.write("-" * 80 + "\n")
                
                history = self.details['packet_history']
                for i, packet in enumerate(history):
                    # Calcular tempo relativo
                    rel_time = packet['timestamp'] - self.details['start_time']
                    
                    # Formatar flags
                    flag_str = self.format_tcp_flags(packet['flags'])
                    
                    # Formatar linha
                    line = f"{i+1:<5} {rel_time:<10.2f} {flag_str:<15} {packet['size']:<10} "
                    line += f"{packet['seq']:<12} {packet['ack']:<12} {packet['window']:<10}\n"
                    
                    f.write(line)
            else:
                f.write("Nenhum histórico de pacotes disponível para esta conexão.\n")
            
            f.write("\n")
            
            # Recomendações
            f.write("AÇÕES RECOMENDADAS\n")
            f.write("-" * 30 + "\n")
            
            if self.details['is_suspicious']:
                f.write("Com base na análise desta conexão, recomendamos as seguintes ações:\n\n")
                
                # Recomendações específicas baseadas no tipo de suspeita
                if self.details['duration'] > self.details['threshold'] * 2:
                    f.write("1. Investigar o motivo da duração extremamente longa desta conexão\n")
                    f.write("2. Verificar se esta é uma conexão legítima ou uma tentativa de manter um canal aberto indevidamente\n")
                    f.write("3. Considerar ajustar as configurações de timeout no servidor ou firewall\n")
                else:
                    f.write("1. Monitorar esta conexão para verificar se é um comportamento normal para esta aplicação\n")
                    f.write("2. Considerar ajustar o threshold de detecção se este for um comportamento esperado\n")
                
                # Verificar padrões de flags
                if flags_history and syn_count > 1:
                    f.write(f"4. Investigar as múltiplas tentativas de iniciar conexão (SYN), possível sinal de problemas de rede ou tentativa de ataque\n")
            else:
                f.write("Esta conexão não foi classificada como suspeita. Nenhuma ação é necessária.\n")
            
            f.write("\n")
            
            # Rodapé
            f.write("=" * 80 + "\n")
            f.write("Relatório gerado pelo NetSnifferX\n")
            f.write(f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write("Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt\n")
            f.write("=" * 80 + "\n")
    
    def export_as_html(self, file_path):
        """
        Exporta o relatório como HTML.
        
        Args:
            file_path: Caminho do arquivo para salvar
        """
        src_ip, src_port, dst_ip, dst_port = self.details['id']
        
        with open(file_path, 'w') as f:
            # Cabeçalho HTML
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
        .packet-table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        .packet-table th, .packet-table td { border: 1px solid #ddd; padding: 6px; text-align: left; font-size: 0.9em; }
        .packet-table th { background-color: #f2f2f2; }
        .packet-row-suspicious { background-color: #ffeeee; }
        .footer { margin-top: 30px; border-top: 1px solid #ddd; padding-top: 10px; font-size: 0.8em; color: #777; }
    </style>
</head>
<body>
""")
            
            # Título
            f.write(f"<h1>Relatório Detalhado de Conexão TCP</h1>\n")
            
            # Informações básicas
            f.write("<h2>Informações da Conexão</h2>\n")
            f.write("<table class='info-table'>\n")
            f.write("  <tr><th>IP de Origem</th><td>" + src_ip + "</td><th>Porta de Origem</th><td>" + str(src_port) + "</td></tr>\n")
            f.write("  <tr><th>IP de Destino</th><td>" + dst_ip + "</td><th>Porta de Destino</th><td>" + str(dst_port) + "</td></tr>\n")
            
            # Status com cor
            status_class = "suspicious" if self.details['is_suspicious'] else "normal"
            f.write(f"  <tr><th>Status</th><td class='{status_class}'>{self.details['status']}</td>")
            
            # Duração
            f.write(f"<th>Duração</th><td>{self.details['duration']:.2f} segundos</td></tr>\n")
            
            # Outros detalhes
            f.write(f"  <tr><th>Pacotes</th><td>{self.details['packet_count']}</td>")
            start_time_str = datetime.datetime.fromtimestamp(self.details['start_time']).strftime('%H:%M:%S')
            f.write(f"<th>Início</th><td>{start_time_str}</td></tr>\n")
            
            # Suspeita
            suspicion_text = "Sim" if self.details['is_suspicious'] else "Não"
            suspicion_class = "suspicious" if self.details['is_suspicious'] else "normal"
            f.write(f"  <tr><th>Suspeita</th><td class='{suspicion_class}'>{suspicion_text}</td>")
            f.write(f"<th>Threshold</th><td>{self.details['threshold']} segundos</td></tr>\n")
            
            f.write("</table>\n")
            
            # Análise de suspeita
            if self.details['is_suspicious']:
                f.write("<h2>Análise de Suspeita</h2>\n")
                f.write("<p>Esta conexão foi classificada como suspeita pelos seguintes motivos:</p>\n")
                f.write("<ul>\n")
                f.write(f"  <li>Duração excessiva: {self.details['duration']:.2f} segundos (limite: {self.details['threshold']} segundos)</li>\n")
                
                # Analisar padrões de flags
                flags_history = self.details.get('flags_history', [])
                if flags_history:
                    syn_count = sum(1 for f in flags_history if f & 0x02)  # SYN
                    fin_count = sum(1 for f in flags_history if f & 0x01)  # FIN
                    rst_count = sum(1 for f in flags_history if f & 0x04)  # RST
                    
                    if syn_count > 1:
                        f.write(f"  <li>Múltiplos flags SYN detectados ({syn_count}), possível tentativa de reconexão</li>\n")
                    
                    if fin_count == 0 and rst_count == 0 and self.details['status'] != 'FINALIZADA':
                        f.write("  <li>Conexão não finalizada corretamente (sem flags FIN ou RST)</li>\n")
                
                f.write("</ul>\n")
            
            # Histórico de flags
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
            
            # Histórico de pacotes
            f.write("<h2>Histórico de Pacotes</h2>\n")
            
            if 'packet_history' in self.details and self.details['packet_history']:
                f.write("<table class='packet-table'>\n")
                f.write("  <tr><th>#</th><th>Tempo (s)</th><th>Flags</th><th>Tamanho</th><th>SEQ</th><th>ACK</th><th>Window</th></tr>\n")
                
                history = self.details['packet_history']
                for i, packet in enumerate(history):
                    # Calcular tempo relativo
                    rel_time = packet['timestamp'] - self.details['start_time']
                    
                    # Formatar flags
                    flag_str = self.format_tcp_flags(packet['flags'])
                    
                    # Determinar classe da linha
                    row_class = "packet-row-suspicious" if rel_time > self.details['threshold'] else ""
                    
                    # Formatar linha
                    f.write(f"  <tr class='{row_class}'><td>{i+1}</td><td>{rel_time:.2f}</td><td>{flag_str}</td>")
                    f.write(f"<td>{packet['size']}</td><td>{packet['seq']}</td><td>{packet['ack']}</td><td>{packet['window']}</td></tr>\n")
                
                f.write("</table>\n")
            else:
                f.write("<p>Nenhum histórico de pacotes disponível para esta conexão.</p>\n")
            
            # Recomendações
            f.write("<h2>Ações Recomendadas</h2>\n")
            
            if self.details['is_suspicious']:
                f.write("<p>Com base na análise desta conexão, recomendamos as seguintes ações:</p>\n")
                f.write("<ol>\n")
                
                # Recomendações específicas baseadas no tipo de suspeita
                if self.details['duration'] > self.details['threshold'] * 2:
                    f.write("  <li>Investigar o motivo da duração extremamente longa desta conexão</li>\n")
                    f.write("  <li>Verificar se esta é uma conexão legítima ou uma tentativa de manter um canal aberto indevidamente</li>\n")
                    f.write("  <li>Considerar ajustar as configurações de timeout no servidor ou firewall</li>\n")
                else:
                    f.write("  <li>Monitorar esta conexão para verificar se é um comportamento normal para esta aplicação</li>\n")
                    f.write("  <li>Considerar ajustar o threshold de detecção se este for um comportamento esperado</li>\n")
                
                # Verificar padrões de flags
                if flags_history and syn_count > 1:
                    f.write(f"  <li>Investigar as múltiplas tentativas de iniciar conexão (SYN), possível sinal de problemas de rede ou tentativa de ataque</li>\n")
                
                f.write("</ol>\n")
            else:
                f.write("<p>Esta conexão não foi classificada como suspeita. Nenhuma ação é necessária.</p>\n")
            
            # Rodapé
            f.write("<div class='footer'>\n")
            f.write(f"  <p>Relatório gerado pelo NetSnifferX em {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>\n")
            f.write("  <p>Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt</p>\n")
            f.write("</div>\n")
            
            # Fechar HTML
            f.write("</body>\n</html>")

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
        self.connections = {}  # Armazenar conexões para relatórios
        
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
        
        # Configurar evento de clique duplo
        self.connection_display.bind("<Double-1>", self.on_connection_click)
        
        # Legenda
        legend_frame = ttk.LabelFrame(main_frame, text="Legenda", padding="5")
        legend_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(legend_frame, text="Iniciando", foreground="blue").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Em Andamento", foreground="black").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Finalizada", foreground="green").pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(legend_frame, text="Suspeita", foreground="red").pack(side=tk.LEFT)
        
        # Dica sobre clique duplo
        tip_label = ttk.Label(legend_frame, text="Dica: Clique duplo em uma conexão suspeita para ver relatório detalhado", font=("Arial", 8, "italic"))
        tip_label.pack(side=tk.RIGHT)
        
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
        self.connections = {}
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
                    
                    # Armazenar conexão para relatório
                    self.connections[data['id']] = data
                
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
        self.connections = {}
        self.update_stats()
    
    def on_connection_click(self, event):
        """
        Manipula o evento de clique duplo em uma conexão.
        """
        try:
            # Obter a linha clicada
            index = self.connection_display.index(f"@{event.x},{event.y}")
            line_start = self.connection_display.index(f"{index} linestart")
            line_end = self.connection_display.index(f"{index} lineend")
            line = self.connection_display.get(line_start, line_end)
            
            # Verificar se a linha contém uma conexão
            if not line or len(line.split()) < 5:
                return
            
            # Extrair informações da conexão
            parts = line.split()
            if len(parts) < 5:
                return
                
            # Formato esperado: timestamp src_ip:src_port dst_ip:dst_port status duration
            src_parts = parts[1].split(':')
            dst_parts = parts[2].split(':')
            
            if len(src_parts) < 2 or len(dst_parts) < 2:
                return
                
            src_ip = src_parts[0]
            src_port = int(src_parts[1])
            dst_ip = dst_parts[0]
            dst_port = int(dst_parts[1])
            
            conn_id = (src_ip, src_port, dst_ip, dst_port)
            
            # Verificar se é uma conexão suspeita
            if conn_id in self.connections and self.connections[conn_id]['is_suspicious']:
                # Obter detalhes completos da conexão
                conn_details = self.tracker.get_connection_details(conn_id)
                
                if conn_details:
                    # Abrir janela de relatório
                    ConnectionReportWindow(self.root, conn_details)
                else:
                    messagebox.showinfo("Informação", "Detalhes da conexão não disponíveis.")
            else:
                messagebox.showinfo("Informação", "Relatórios detalhados estão disponíveis apenas para conexões suspeitas.")
                
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao processar clique: {e}")

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
