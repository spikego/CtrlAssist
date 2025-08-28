import threading
import time
import socket
import struct
from typing import List, Dict, Optional, Set
import psutil
import json
from datetime import datetime
import ctypes
from ctypes import wintypes
import logging
import dpkt
import winreg
import os
from collections import defaultdict

# 设置日志
logger = logging.getLogger(__name__)

class NetworkStats:
    def __init__(self):
        self.total_bytes = 0
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.process_stats = defaultdict(int)
        self.start_time = time.time()

    def update(self, packet: Dict):
        """更新统计信息"""
        self.total_bytes += packet.get('length', 0)
        self.packet_count += 1
        self.protocol_stats[packet.get('protocol', 'Unknown')] += 1

        if packet.get('src_port'):
            self.port_stats[packet['src_port']] += 1
        if packet.get('dst_port'):
            self.port_stats[packet['dst_port']] += 1

        self.ip_stats[packet.get('src', 'Unknown')] += 1
        self.ip_stats[packet.get('dst', 'Unknown')] += 1

        if packet.get('process_name'):
            self.process_stats[packet['process_name']] += 1

    def get_summary(self) -> Dict:
        """获取统计摘要"""
        duration = time.time() - self.start_time
        return {
            'duration': round(duration, 2),
            'total_bytes': self.total_bytes,
            'packet_count': self.packet_count,
            'bytes_per_second': round(self.total_bytes / duration if duration > 0 else 0, 2),
            'packets_per_second': round(self.packet_count / duration if duration > 0 else 0, 2),
            'top_protocols': dict(sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_ports': dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_ips': dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_processes': dict(sorted(self.process_stats.items(), key=lambda x: x[1], reverse=True)[:5])
        }

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
            'ip': None,
            'process': None
        }
        self.stats = NetworkStats()
        self.process_connections = {}
        self.known_ports = self._load_known_ports()

    def _load_known_ports(self) -> Dict[int, str]:
        """加载已知端口服务"""
        known_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            53: 'DNS',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            3306: 'MySQL',
            1433: 'MSSQL',
            3389: 'RDP',
            5900: 'VNC'
        }
        
        try:
            # 从 Windows 注册表加载额外的端口映射
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Services') as key:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, name) as svc_key:
                            try:
                                port = winreg.QueryValueEx(svc_key, 'Port')[0]
                                if isinstance(port, int):
                                    known_ports[port] = name
                            except WindowsError:
                                pass
                        i += 1
                    except WindowsError:
                        break
        except WindowsError:
            pass

        return known_ports

    def start_packet_capture(self, pid: Optional[int] = None) -> bool:
        """开始抓包"""
        if self.capturing:
            return False
            
        try:
            self.capturing = True
            self.packets = []
            self.packet_count = 0
            self.hooked_pid = pid
            self.stats = NetworkStats()
            self.process_connections = {}
            self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
            self.capture_thread.start()
            logger.info("Packet capture started" + (f" for PID {pid}" if pid else ""))
            return True
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            return False
    
    def stop_packet_capture(self) -> bool:
        """停止抓包"""
        self.capturing = False
        logger.info("Packet capture stopped")
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
    
    def _parse_packet(self, data: bytes) -> Optional[Dict]:
        """解析数据包"""
        try:
            self.packet_count += 1
            
            # 尝试解析为 IPv4 或 IPv6
            ip_version = data[0] >> 4

            if ip_version == 4:
                return self._parse_ipv4_packet(data)
            elif ip_version == 6:
                return self._parse_ipv6_packet(data)
            else:
                return None

        except Exception as e:
            logger.debug(f"Packet parsing error: {e}")
            return None

    def _parse_ipv4_packet(self, data: bytes) -> Optional[Dict]:
        """解析 IPv4 数据包"""
        try:
            # 解析IP头
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            version_ihl = ip_header[0]
            ihl = version_ihl & 0xF
            ip_header_length = ihl * 4

            total_length = ip_header[2]
            identification = ip_header[3]
            flags_fragment = ip_header[4]
            ttl = ip_header[5]
            protocol = ip_header[6]
            checksum = ip_header[7]
            src_addr = socket.inet_ntoa(ip_header[8])
            dst_addr = socket.inet_ntoa(ip_header[9])
            
            # 获取协议相关信息
            protocol_info = self._get_protocol_info(protocol, data[ip_header_length:])
            if not protocol_info:
                return None

            packet_info = {
                'no': self.packet_count,
                'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src': src_addr,
                'dst': dst_addr,
                'protocol': protocol_info['protocol'],
                'length': len(data),
                'info': protocol_info['info'],
                'src_port': protocol_info.get('src_port'),
                'dst_port': protocol_info.get('dst_port'),
                'ttl': ttl,
                'id': identification,
                'flags': self._parse_flags(flags_fragment),
                'raw_data': data.hex()[:100] + '...' if len(data) > 50 else data.hex(),
                'process_name': self._get_process_name(src_addr, protocol_info.get('src_port'),
                                                     dst_addr, protocol_info.get('dst_port'))
            }
            
            # 应用过滤器
            if self._should_filter_packet(packet_info):
                return None

            # 更新统计信息
            self.stats.update(packet_info)

            return packet_info

        except Exception as e:
            logger.debug(f"IPv4 packet parsing error: {e}")
            return None

    def _parse_ipv6_packet(self, data: bytes) -> Optional[Dict]:
        """解析 IPv6 数据包"""
        try:
            # 解析IPv6头 (40字节固定长度)
            ipv6_header = struct.unpack('!IHBB16s16s', data[:40])
            version_class_flow = ipv6_header[0]
            payload_length = ipv6_header[1]
            next_header = ipv6_header[2]
            hop_limit = ipv6_header[3]
            src_addr = socket.inet_ntop(socket.AF_INET6, ipv6_header[4])
            dst_addr = socket.inet_ntop(socket.AF_INET6, ipv6_header[5])

            # 获取协议相关信息
            protocol_info = self._get_protocol_info(next_header, data[40:])
            if not protocol_info:
                return None

            packet_info = {
                'no': self.packet_count,
                'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src': src_addr,
                'dst': dst_addr,
                'protocol': protocol_info['protocol'],
                'length': len(data),
                'info': protocol_info['info'],
                'src_port': protocol_info.get('src_port'),
                'dst_port': protocol_info.get('dst_port'),
                'hop_limit': hop_limit,
                'next_header': next_header,
                'raw_data': data.hex()[:100] + '...' if len(data) > 50 else data.hex(),
                'process_name': self._get_process_name(src_addr, protocol_info.get('src_port'),
                                                     dst_addr, protocol_info.get('dst_port'))
            }

            # 应用过滤器
            if self._should_filter_packet(packet_info):
                return None

            # 更新统计信息
            self.stats.update(packet_info)

            return packet_info

        except Exception as e:
            logger.debug(f"IPv6 packet parsing error: {e}")
            return None

    def _get_protocol_info(self, protocol: int, data: bytes) -> Optional[Dict]:
        """解析协议信息"""
        try:
            protocol_name = {
                1: 'ICMP',
                6: 'TCP',
                17: 'UDP',
                2: 'IGMP',
                58: 'ICMPv6',
                89: 'OSPF'
            }.get(protocol, f'Protocol-{protocol}')

            result = {
                'protocol': protocol_name,
                'info': f'Unknown {protocol_name} packet'
            }

            if protocol in [6, 17]:  # TCP or UDP
                if len(data) >= 4:
                    ports = struct.unpack('!HH', data[:4])
                    result['src_port'] = ports[0]
                    result['dst_port'] = ports[1]

                    # 获取已知端口的服务名
                    service_name = self._get_service_name(ports[1])  # 使用目标端口

                    if protocol == 6:  # TCP
                        if len(data) >= 20:
                            tcp_header = struct.unpack('!HH4s4sHH', data[4:20])
                            flags = tcp_header[5]
                            flag_str = self._parse_tcp_flags(flags)
                            result['info'] = f"{service_name} {ports[0]} → {ports[1]} [{flag_str}]"

                            # 如果是 HTTP/HTTPS 流量，尝试解析
                            if ports[1] in [80, 443] and len(data) > 20:
                                http_info = self._parse_http(data[20:])
                                if http_info:
                                    result['info'] = http_info
                    else:  # UDP
                        result['info'] = f"{service_name} {ports[0]} → {ports[1]}"

                        # 如果是 DNS 流量，尝试解析
                        if ports[1] == 53 and len(data) > 8:
                            dns_info = self._parse_dns(data[8:])
                            if dns_info:
                                result['info'] = dns_info

            elif protocol == 1:  # ICMP
                if len(data) >= 2:
                    icmp_type, icmp_code = struct.unpack('!BB', data[:2])
                    result['info'] = self._get_icmp_type_string(icmp_type, icmp_code)

            return result

        except Exception as e:
            logger.debug(f"Protocol parsing error: {e}")
            return None

    def _get_service_name(self, port: int) -> str:
        """获取端口对应的服务名称"""
        return self.known_ports.get(port, str(port))

    def _parse_tcp_flags(self, flags: int) -> str:
        """解析TCP标志位"""
        flag_chars = []
        if flags & 0x01: flag_chars.append('FIN')
        if flags & 0x02: flag_chars.append('SYN')
        if flags & 0x04: flag_chars.append('RST')
        if flags & 0x08: flag_chars.append('PSH')
        if flags & 0x10: flag_chars.append('ACK')
        if flags & 0x20: flag_chars.append('URG')
        return ' '.join(flag_chars)

    def _parse_http(self, data: bytes) -> Optional[str]:
        """解析HTTP数据"""
        try:
            http_data = data.decode('utf-8', errors='ignore')
            first_line = http_data.split('\r\n')[0]

            if first_line.startswith('GET '):
                return f"HTTP GET {first_line[4:].split(' ')[0]}"
            elif first_line.startswith('POST '):
                return f"HTTP POST {first_line[5:].split(' ')[0]}"
            elif first_line.startswith('HTTP/'):
                status_code = first_line.split(' ')[1]
                return f"HTTP Response {status_code}"

        except Exception:
            pass
        return None

    def _parse_dns(self, data: bytes) -> Optional[str]:
        """解析DNS数据"""
        try:
            dns = dpkt.dns.DNS(data)
            if dns.qr == dpkt.dns.DNS_Q:
                if len(dns.qd) > 0:
                    return f"DNS Query: {dns.qd[0].name.decode('utf-8')}"
            else:
                if len(dns.an) > 0:
                    return f"DNS Response: {dns.an[0].name.decode('utf-8')}"
        except Exception:
            pass
        return None

    def _get_icmp_type_string(self, icmp_type: int, icmp_code: int) -> str:
        """获取ICMP类型描述"""
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        return icmp_types.get(icmp_type, f'ICMP Type {icmp_type}, Code {icmp_code}')

    def _get_process_name(self, src_ip: str, src_port: Optional[int],
                         dst_ip: str, dst_port: Optional[int]) -> Optional[str]:
        """获取对应的进程名称"""
        if not src_port or not dst_port:
            return None

        # 更新进程连接缓存
        self._update_process_connections()

        # 检查源和目标
        key = f"{src_ip}:{src_port}"
        if key in self.process_connections:
            return self.process_connections[key]

        key = f"{dst_ip}:{dst_port}"
        if key in self.process_connections:
            return self.process_connections[key]

        return None

    def _update_process_connections(self):
        """更新进程连接信息缓存"""
        try:
            # 每5秒更新一次
            current_time = time.time()
            if not hasattr(self, '_last_update_time') or current_time - self._last_update_time >= 5:
                self._last_update_time = current_time

                # 清空旧的缓存
                self.process_connections = {}

                # 获取所有网络连接
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        if conn.laddr and conn.pid:
                            process = psutil.Process(conn.pid)
                            # 添加本地地址映射
                            key = f"{conn.laddr.ip}:{conn.laddr.port}"
                            self.process_connections[key] = process.name()

                            # 如果有远程地址，也添加映射
                            if conn.raddr:
                                key = f"{conn.raddr.ip}:{conn.raddr.port}"
                                self.process_connections[key] = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            logger.debug(f"Failed to update process connections: {e}")

    def get_statistics(self) -> Dict:
        """获取网络统计信息"""
        return self.stats.get_summary()
