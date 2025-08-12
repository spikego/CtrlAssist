import threading
import time
import socket
import struct
from typing import List, Dict
import psutil
import json
from datetime import datetime
import ctypes
from ctypes import wintypes

class NetworkEngine:
    def __init__(self):
        self.capturing = False
        self.packets = []
        self.capture_thread = None
        self.packet_count = 0
        self.hooked_pid = None
        self.filters = {
            'protocol': 'all',
            'port': None,
            'ip': None
        }
        
    def start_packet_capture(self, pid=None) -> bool:
        """开始抓包"""
        if self.capturing:
            return False
            
        try:
            self.capturing = True
            self.packets = []
            self.packet_count = 0
            self.hooked_pid = pid
            self.start_time = time.time()
            self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
            self.capture_thread.start()
            return True
        except Exception:
            return False
    
    def stop_packet_capture(self) -> bool:
        """停止抓包"""
        self.capturing = False
        return True
    
    def get_packets(self) -> List[Dict]:
        """获取抓包结果"""
        return self.packets[-50:]  # 返回最近50个包
    
    def clear_packets(self):
        """清除抓包结果"""
        self.packets = []
    
    def _capture_packets(self):
        """抓包主循环"""
        try:
            # 创建原始套接字
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind(('0.0.0.0', 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            while self.capturing:
                try:
                    data, addr = sock.recvfrom(65535)
                    packet_info = self._parse_packet(data)
                    if packet_info:
                        self.packets.append(packet_info)
                        # 保持最近1000个包
                        if len(self.packets) > 1000:
                            self.packets = self.packets[-1000:]
                except Exception:
                    continue
                    
        except Exception:
            # 如果无法创建原始套接字，使用网络连接信息模拟
            self._simulate_network_activity()
    
    def _parse_packet(self, data: bytes) -> Dict:
        """解析数据包"""
        try:
            self.packet_count += 1
            
            # 解析IP头
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            if version != 4:
                return None
                
            total_length = ip_header[2]
            identification = ip_header[3]
            flags_fragment = ip_header[4]
            ttl = ip_header[5]
            protocol = ip_header[6]
            checksum = ip_header[7]
            src_addr = socket.inet_ntoa(ip_header[8])
            dst_addr = socket.inet_ntoa(ip_header[9])
            
            protocol_name = {
                1: 'ICMP',
                6: 'TCP', 
                17: 'UDP',
                2: 'IGMP',
                89: 'OSPF'
            }.get(protocol, f'Protocol-{protocol}')
            
            # 解析传输层
            src_port = dst_port = None
            if protocol in [6, 17]:  # TCP or UDP
                if len(data) >= 24:
                    transport_header = struct.unpack('!HH', data[20:24])
                    src_port = transport_header[0]
                    dst_port = transport_header[1]
            
            packet_info = {
                'no': self.packet_count,
                'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src': src_addr,
                'dst': dst_addr,
                'protocol': protocol_name,
                'length': len(data),
                'info': self._get_packet_info(protocol, data, src_port, dst_port),
                'src_port': src_port,
                'dst_port': dst_port,
                'ttl': ttl,
                'id': identification,
                'flags': self._parse_flags(flags_fragment),
                'raw_data': data.hex()[:100] + '...' if len(data) > 50 else data.hex()
            }
            
            # 应用过滤器
            if self._should_filter_packet(packet_info):
                return None
                
            return packet_info
        except Exception:
            return None
    
    def _get_packet_info(self, protocol: int, data: bytes, src_port: int, dst_port: int) -> str:
        """获取数据包信息"""
        if protocol == 6:  # TCP
            if src_port == 80 or dst_port == 80:
                return "HTTP"
            elif src_port == 443 or dst_port == 443:
                return "HTTPS"
            elif src_port == 21 or dst_port == 21:
                return "FTP"
            elif src_port == 22 or dst_port == 22:
                return "SSH"
            elif src_port == 25 or dst_port == 25:
                return "SMTP"
            else:
                return f"TCP {src_port} → {dst_port}"
        elif protocol == 17:  # UDP
            if src_port == 53 or dst_port == 53:
                return "DNS"
            elif src_port == 67 or dst_port == 68:
                return "DHCP"
            else:
                return f"UDP {src_port} → {dst_port}"
        elif protocol == 1:  # ICMP
            return "ICMP Echo/Reply"
        else:
            return f"Protocol {protocol}"
    
    def _parse_flags(self, flags_fragment: int) -> str:
        """解析IP标志"""
        flags = (flags_fragment >> 13) & 0x7
        flag_str = ""
        if flags & 0x4:
            flag_str += "DF "
        if flags & 0x2:
            flag_str += "MF "
        return flag_str.strip()
    
    def _should_filter_packet(self, packet: Dict) -> bool:
        """检查是否应该过滤数据包"""
        protocol = packet.get('protocol', '').lower()
        if self.filters['protocol'] != 'all' and protocol != self.filters['protocol'].lower():
            return True
        
        src_port = packet.get('src_port')
        dst_port = packet.get('dst_port')
        if self.filters['port'] and src_port != self.filters['port'] and dst_port != self.filters['port']:
            return True
        
        src_ip = packet.get('src', '')
        dst_ip = packet.get('dst', '')
        if self.filters['ip'] and self.filters['ip'] not in src_ip and self.filters['ip'] not in dst_ip:
            return True
        
        return False
    
    def set_filter(self, filter_type: str, value: str):
        """设置过滤器"""
        if filter_type in self.filters:
            self.filters[filter_type] = value
    
    def get_statistics(self) -> Dict:
        """获取网络统计信息"""
        if not self.packets:
            return {}
            
        protocols = {}
        total_bytes = 0
        
        for packet in self.packets:
            protocol = packet.get('protocol', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
            length = packet.get('length', 0)
            if length is not None:
                total_bytes += length
        
        return {
            'total_packets': len(self.packets),
            'total_bytes': total_bytes,
            'protocols': protocols,
            'capture_time': time.time() - getattr(self, 'start_time', time.time())
        }
    
    def _simulate_network_activity(self):
        """监控网络连接活动"""
        self.start_time = time.time()
        prev_connections = set()
        
        while self.capturing:
            try:
                # 获取网络连接，如果指定了PID则只监控该进程
                if self.hooked_pid:
                    connections = self._get_process_connections(self.hooked_pid)
                else:
                    connections = psutil.net_connections(kind='inet')
                    
                current_connections = set()
                
                for conn in connections:
                    if conn.laddr and conn.raddr:
                        conn_key = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port, conn.type.name)
                        current_connections.add(conn_key)
                        
                        # 检测新连接或活跃连接
                        if conn_key not in prev_connections or conn.status == 'ESTABLISHED':
                            self.packet_count += 1
                            
                            protocol = 'TCP' if conn.type.name == 'SOCK_STREAM' else 'UDP'
                            info = f"{conn.laddr.port} → {conn.raddr.port} [{conn.status}]"
                            
                            # 如果是进程hook，添加进程信息
                            if self.hooked_pid:
                                try:
                                    process = psutil.Process(self.hooked_pid)
                                    info += f" [PID:{self.hooked_pid} {process.name()}]"
                                except:
                                    info += f" [PID:{self.hooked_pid}]"
                            
                            packet_info = {
                                'no': self.packet_count,
                                'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                                'src': conn.laddr.ip,
                                'dst': conn.raddr.ip,
                                'protocol': protocol,
                                'length': 60,
                                'info': info,
                                'src_port': conn.laddr.port,
                                'dst_port': conn.raddr.port,
                                'ttl': 64,
                                'flags': 'PSH ACK' if conn.status == 'ESTABLISHED' else '',
                                'raw_data': f'Connection: {conn.status}',
                                'pid': self.hooked_pid if self.hooked_pid else getattr(conn, 'pid', None)
                            }
                            
                            if not self._should_filter_packet(packet_info):
                                self.packets.append(packet_info)
                                if len(self.packets) > 1000:
                                    self.packets = self.packets[-1000:]
                
                prev_connections = current_connections
                time.sleep(0.5)  # 更频繁的检查
                
            except Exception as e:
                time.sleep(1)
    
    def _get_process_connections(self, pid: int):
        """获取指定进程的网络连接"""
        try:
            process = psutil.Process(pid)
            return process.connections(kind='inet')
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    
    def hook_process(self, pid: int) -> bool:
        """Hook指定进程的网络流量"""
        try:
            # 验证进程是否存在
            process = psutil.Process(pid)
            self.hooked_pid = pid
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def unhook_process(self):
        """取消进程hook"""
        self.hooked_pid = None
    
    def get_hooked_process_info(self) -> Dict:
        """获取被hook进程的信息"""
        if not self.hooked_pid:
            return {}
        
        try:
            process = psutil.Process(self.hooked_pid)
            return {
                'pid': self.hooked_pid,
                'name': process.name(),
                'exe': process.exe(),
                'status': process.status(),
                'memory_info': process.memory_info()._asdict(),
                'cpu_percent': process.cpu_percent(),
                'connections_count': len(process.connections(kind='inet'))
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {'error': 'Process not accessible'}