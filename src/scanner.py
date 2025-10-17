import nmap
import netifaces
import json
import socket
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.network_info = {}
        self.devices = []
        
    def get_local_network(self):
        """Определение локальной сети WiFi"""
        try:
            # Получаем шлюз по умолчанию
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            
            # Ищем WiFi интерфейс
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        # Ищем приватные IP
                        if ip.startswith('192.168.') or ip.startswith('10.') or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
                            netmask = addr_info.get('netmask', '255.255.255.0')
                            network = self._calculate_network(ip, netmask)
                            
                            self.network_info = {
                                'local_ip': ip,
                                'gateway': default_gateway,
                                'network': network,
                                'netmask': netmask,
                                'interface': interface
                            }
                            return self.network_info
            return None
        except Exception as e:
            print(f"❌ Ошибка определения сети: {e}")
            return None
    
    def _calculate_network(self, ip, netmask):
        """Вычисление сети по IP и маске"""
        ip_parts = [int(x) for x in ip.split('.')]
        mask_parts = [int(x) for x in netmask.split('.')]
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        return '.'.join(str(x) for x in network_parts) + '/24'
    
    def scan_network(self, network_range=None):
        """Сканирование сети с помощью nmap"""
        if not network_range:
            if not self.network_info:
                self.get_local_network()
            network_range = self.network_info.get('network', '192.168.1.0/24')
        
        print(f"🔍 Сканирование: {network_range}")
        
        try:
            # Стадия 1: Обнаружение устройств
            self.nm.scan(hosts=network_range, arguments='-sn')
            
            self.devices = []
            for host in self.nm.all_hosts():
                device_info = {
                    'ip': host,
                    'mac': 'Unknown',
                    'vendor': 'Unknown',
                    'hostname': 'Unknown',
                    'status': self.nm[host].state(),
                    'os': 'Unknown',
                    'ports': [],
                    'last_seen': datetime.now().isoformat()
                }
                
                # Получаем MAC и вендора
                if 'addresses' in self.nm[host]:
                    if 'mac' in self.nm[host]['addresses']:
                        device_info['mac'] = self.nm[host]['addresses']['mac']
                    if 'vendor' in self.nm[host] and device_info['mac'] in self.nm[host]['vendor']:
                        device_info['vendor'] = self.nm[host]['vendor'][device_info['mac']]
                
                # Hostname
                if 'hostnames' in self.nm[host] and self.nm[host]['hostnames']:
                    hostname = self.nm[host]['hostnames'][0]['name']
                    device_info['hostname'] = hostname if hostname else 'Unknown'
                
                self.devices.append(device_info)
            
            # Стадия 2: Детальное сканирование
            self._detailed_scan()
            return self.devices
            
        except Exception as e:
            print(f"❌ Ошибка сканирования: {e}")
            return []
    
    def _detailed_scan(self):
        """Детальное сканирование ОС и портов"""
        for device in self.devices:
            try:
                # Быстрое сканирование ОС
                self.nm.scan(hosts=device['ip'], arguments='-O --osscan-limit')
                if 'osmatch' in self.nm[device['ip']] and self.nm[device['ip']]['osmatch']:
                    device['os'] = self.nm[device['ip']]['osmatch'][0]['name']
                
                # Сканирование common портов
                self.nm.scan(hosts=device['ip'], arguments='-sS -T4 --top-ports 100')
                if 'tcp' in self.nm[device['ip']]:
                    for port, info in self.nm[device['ip']]['tcp'].items():
                        if info['state'] == 'open':
                            device['ports'].append({
                                'port': port,
                                'state': info['state'],
                                'service': info['name'],
                                'version': info.get('version', 'Unknown')
                            })
                            
            except Exception as e:
                print(f"⚠️ Ошибка сканирования {device['ip']}: {e}")
    
    def export_results(self, devices, filename):
        """Экспорт результатов в JSON"""
        data = {
            'scan_time': datetime.now().isoformat(),
            'network_info': self.network_info,
            'devices': devices
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
