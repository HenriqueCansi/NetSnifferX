#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetSnifferX - Monitoramento e análise de conexões TCP em tempo real
Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt

NOTA IMPORTANTE: Este script requer privilégios de root para capturar pacotes.
Execute com: sudo python3 netsnifferx.py
"""

from scapy.all import sniff, TCP
import time
import datetime
import argparse

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

def format_connection_info(conn_info):
    """
    Formata as informações da conexão para exibição.
    
    Args:
        conn_info (dict): Informações da conexão
        
    Returns:
        str: String formatada com informações da conexão
    """
    if not conn_info:
        return ""
    
    src_ip, src_port, dst_ip, dst_port = conn_info['id']
    status = conn_info['status']
    duration = round(conn_info['duration'], 2)
    
    # Formatação colorida para terminal (ANSI escape codes)
    if conn_info['is_suspicious']:
        color_code = '\033[91m'  # Vermelho para conexões suspeitas
    elif status == 'INICIANDO':
        color_code = '\033[94m'  # Azul para conexões iniciando
    elif status == 'FINALIZADA':
        color_code = '\033[92m'  # Verde para conexões finalizadas
    else:
        color_code = '\033[0m'   # Normal para outras
    
    reset_code = '\033[0m'
    
    return f"{color_code}[{datetime.datetime.now().strftime('%H:%M:%S')}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Status: {status} | Duração: {duration}s{reset_code}"

def packet_callback(packet, tracker):
    """
    Função de callback chamada para cada pacote capturado.
    
    Args:
        packet: Pacote capturado pelo Scapy
        tracker: Instância do ConnectionTracker
    """
    if TCP in packet:
        conn_info = tracker.track_packet(packet)
        if conn_info:
            print(format_connection_info(conn_info))

def main():
    """
    Função principal do programa.
    """
    parser = argparse.ArgumentParser(description='NetSnifferX - Monitoramento e análise de conexões TCP em tempo real')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Tempo em segundos para considerar uma conexão como suspeita (padrão: 10)')
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Interface de rede para captura (padrão: todas)')
    parser.add_argument('-f', '--filter', type=str, default="tcp",
                        help='Filtro BPF para captura (padrão: "tcp")')
    parser.add_argument('-d', '--duration', type=int, default=0,
                        help='Duração da captura em segundos (0 para infinito, padrão: 0)')
    
    args = parser.parse_args()
    
    print("NetSnifferX - Monitoramento e análise de conexões TCP em tempo real")
    print("Desenvolvido por: Henrique Laste Cansi e Lucas Klug Arndt")
    print("=" * 80)
    print(f"Iniciando captura de pacotes TCP na interface: {args.interface or 'todas'}")
    print(f"Filtro: {args.filter}")
    print(f"Threshold para conexões suspeitas: {args.timeout} segundos")
    if args.duration > 0:
        print(f"Duração da captura: {args.duration} segundos")
    else:
        print("Duração da captura: indefinida (pressione Ctrl+C para encerrar)")
    print("=" * 80)
    
    # Cria o rastreador de conexões
    tracker = ConnectionTracker(timeout_threshold=args.timeout)
    
    try:
        # Usando L3socket para compatibilidade com Windows sem Winpcap
        from scapy.config import conf
        # Inicia a captura de pacotes TCP
        sniff(
            filter=args.filter,
            prn=lambda pkt: packet_callback(pkt, tracker),
            store=0,
            iface=args.interface,
            timeout=args.duration if args.duration > 0 else None,
            L2socket=conf.L3socket  # Usar L3socket em vez do padrão
        )
        if args.duration > 0:
            print("\nCaptura de pacotes concluída após o tempo definido.")
    except KeyboardInterrupt:
        print("\nCaptura de pacotes encerrada pelo usuário.")
    except Exception as e:
        print(f"\nErro durante a captura de pacotes: {e}")
        print("\nNOTA: A captura de pacotes requer privilégios de administrador.")
        print("Execute o script com: python netsnifferx.py")
        
if __name__ == "__main__":
    main()
