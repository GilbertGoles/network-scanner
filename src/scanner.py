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
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info['addr']
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
        """Улучшенное сканирование сети"""
        if not network_range:
            if not self.network_info:
                self.get_local_network()
            network_range = self.network_info.get('network', '192.168.1.0/24')
        
        print(f"🔍 Сканирование: {network_range}")
        
        try:
            # ПЕРВАЯ СТАДИЯ: Только обнаружение устройств (быстро)
            print("🔍 Стадия 1: Обнаружение устройств...")
            self.nm.scan(hosts=network_range, arguments='-sn --min-rate 1000')
            
            self.devices = []
            for host in self.nm.all_hosts():
                device_info = self._create_device_info(host)
                self.devices.append(device_info)
            
            print(f"✅ Найдено устройств: {len(self.devices)}")
            
            # ВТОРАЯ СТАДИЯ: Детальное сканирование с приоритетом для шлюза
            print("🔍 Стадия 2: Детальное сканирование...")
            self._detailed_scan_with_priority()
            
            return self.devices
            
        except Exception as e:
            print(f"❌ Ошибка сканирования: {e}")
            return []

    def _create_device_info(self, host):
        """Создание базовой информации об устройстве"""
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
        
        # Получаем MAC адрес
        if 'addresses' in self.nm[host]:
            for addr_type, addr_value in self.nm[host]['addresses'].items():
                if addr_type == 'mac':
                    device_info['mac'] = addr_value
                    break
        
        # Получаем вендора
        if 'vendor' in self.nm[host] and device_info['mac'] in self.nm[host]['vendor']:
            device_info['vendor'] = self.nm[host]['vendor'][device_info['mac']]
        elif device_info['mac'] != 'Unknown':
            device_info['vendor'] = f"MAC: {device_info['mac']}"
        
        # Получаем hostname
        if 'hostnames' in self.nm[host] and self.nm[host]['hostnames']:
            hostname = self.nm[host]['hostnames'][0]['name']
            device_info['hostname'] = hostname if hostname else self._get_hostname_fallback(host)
        
        return device_info

    def _get_hostname_fallback(self, ip):
        """Резервный метод определения hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"

    def _detailed_scan_with_priority(self):
        """Детальное сканирование с приоритетом для важных устройств"""
        # Сначала сканируем шлюз и локальные устройства
        priority_devices = []
        normal_devices = []
        
        for device in self.devices:
            # Шлюз имеет высший приоритет
            if (device['ip'] == self.network_info.get('gateway') or 
                device['ip'] == self.network_info.get('local_ip') or
                device['hostname'] in ['_gateway', 'localhost', 'router'] or
                'gateway' in device['hostname'].lower()):
                priority_devices.append(device)
            else:
                normal_devices.append(device)
        
        print(f"🎯 Приоритетные устройства: {len(priority_devices)}")
        print(f"📱 Обычные устройства: {len(normal_devices)}")
        
        # Сканируем приоритетные устройства с более долгим таймаутом
        for device in priority_devices:
            try:
                print(f"🎯 Приоритетное сканирование: {device['ip']} ({device.get('hostname', 'Unknown')})")
                self.nm.scan(hosts=device['ip'], 
                            arguments='-sS -O -A --min-rate 500 --host-timeout 60s')
                self._update_device_info(device)
            except Exception as e:
                print(f"⚠️ Ошибка приоритетного сканирования {device['ip']}: {e}")
        
        # Сканируем обычные устройства с быстрым таймаутом
        for device in normal_devices:
            try:
                print(f"🔍 Сканирую {device['ip']}...")
                self.nm.scan(hosts=device['ip'], 
                            arguments='-sS -O --osscan-limit --max-retries 1 --host-timeout 20s')
                self._update_device_info(device)
            except Exception as e:
                print(f"⚠️ Ошибка сканирования {device['ip']}: {e}")

    def _update_device_info(self, device):
        """Обновление информации об устройстве после детального сканирования"""
        host = device['ip']
        
        try:
            # Обновляем ОС
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                best_os = self.nm[host]['osmatch'][0]
                accuracy = best_os.get('accuracy', '0')
                device['os'] = f"{best_os['name']} (accuracy: {accuracy}%)"
            
            # Обновляем hostname (если нашли лучше)
            if 'hostnames' in self.nm[host] and self.nm[host]['hostnames']:
                hostname = self.nm[host]['hostnames'][0]['name']
                if hostname and hostname != device['ip'] and hostname not in ['', 'localhost']:
                    device['hostname'] = hostname
            
            # Обновляем MAC и vendor если не нашли ранее
            if (device['mac'] == 'Unknown' or device['vendor'] == 'Unknown') and 'addresses' in self.nm[host]:
                for addr_type, addr_value in self.nm[host]['addresses'].items():
                    if addr_type == 'mac':
                        device['mac'] = addr_value
                        # Пытаемся получить вендора
                        if 'vendor' in self.nm[host] and addr_value in self.nm[host]['vendor']:
                            device['vendor'] = self.nm[host]['vendor'][addr_value]
                        break
            
            # Сканируем порты
            device['ports'] = []
            if 'tcp' in self.nm[host]:
                for port, info in self.nm[host]['tcp'].items():
                    if info['state'] == 'open':
                        device['ports'].append({
                            'port': port,
                            'state': info['state'],
                            'service': info['name'],
                            'version': info.get('version', 'Unknown')
                        })
            
            print(f"✅ Обновлено: {device['ip']} -> {device['hostname']} | {device['os']}")
            
        except Exception as e:
            print(f"⚠️ Ошибка обновления информации для {device['ip']}: {e}")

    def export_results(self, devices, filename):
        """Экспорт результатов в JSON"""
        data = {
            'scan_time': datetime.now().isoformat(),
            'network_info': self.network_info,
            'devices': devices
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def get_device_count(self):
        """Получить количество найденных устройств"""
        return len(self.devices)

    def get_network_summary(self):
        """Получить сводку по сети"""
        if not self.network_info:
            return "Сеть не определена"
        
        devices_by_os = {}
        for device in self.devices:
            os_name = device['os'].split(' (')[0]  # Берем только название ОС
            devices_by_os[os_name] = devices_by_os.get(os_name, 0) + 1
        
        detailed_devices = len([d for d in self.devices if d['os'] != 'Unknown'])
        
        summary = f"🌐 Сеть: {self.network_info['network']}\n"
        summary += f"📊 Всего устройств: {len(self.devices)}\n"
        summary += f"🔍 Детально просканировано: {detailed_devices}\n"
        summary += "⚙️ Распределение по ОС:\n"
        for os_name, count in devices_by_os.items():
            summary += f"  • {os_name}: {count}\n"
        
        return summary

    def get_device_details(self, ip_address):
        """Получить детальную информацию об устройстве по IP"""
        for device in self.devices:
            if device['ip'] == ip_address:
                details = f"📱 Устройство: {device['hostname']} ({device['ip']})\n"
                details += f"🔧 MAC: {device['mac']}\n"
                details += f"🏷️ Vendor: {device['vendor']}\n"
                details += f"💻 ОС: {device['os']}\n"
                details += f"📡 Статус: {device['status']}\n"
                
                if device['ports']:
                    details += f"🔓 Открытые порты ({len(device['ports'])}):\n"
                    for port in device['ports']:
                        details += f"  • {port['port']}/tcp - {port['service']} ({port['version']})\n"
                else:
                    details += "🔒 Открытых портов не обнаружено\n"
                
                return details
        return f"❌ Устройство с IP {ip_address} не найдено"
