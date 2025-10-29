import nmap
import netifaces
import socket
import threading
import concurrent.futures
import json
import time
from datetime import datetime
from typing import List, Dict, Any

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.network_info = {}
        self.devices = []
        self.scan_progress = {
            'current': 0,
            'total': 0,
            'stage': '',
            'active': False
        }
        
    def get_local_network(self) -> Dict[str, Any]:
        """Определение локальной сети с приоритетом WiFi"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            
            # Приоритет WiFi интерфейсам
            wifi_interfaces = ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0', 'wlp4s0']
            
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        if ip != '127.0.0.1' and not ip.startswith('169.254.'):
                            netmask = addr_info.get('netmask', '255.255.255.0')
                            network = self._calculate_network(ip, netmask)
                            
                            self.network_info = {
                                'local_ip': ip,
                                'gateway': default_gateway,
                                'network': network,
                                'netmask': netmask,
                                'interface': interface,
                                'is_wifi': interface in wifi_interfaces,
                                'scan_time': datetime.now().isoformat()
                            }
                            return self.network_info
            return None
        except Exception as e:
            print(f"❌ Ошибка определения сети: {e}")
            return None

    def scan_network(self, network_range: str = None) -> List[Dict[str, Any]]:
        """Основной метод сканирования сети"""
        start_time = time.time()
        self.scan_progress['active'] = True
        
        if not network_range:
            if not self.network_info:
                self.get_local_network()
            network_range = self.network_info.get('network', '192.168.1.0/24')
        
        print(f"🎯 Начинаем сканирование: {network_range}")
        self.devices = []
        
        try:
            # Стадия 1: Быстрое обнаружение устройств
            self.scan_progress['stage'] = 'discovery'
            devices_ips = self._fast_discovery(network_range)
            print(f"📡 Обнаружено IP-адресов: {len(devices_ips)}")
            
            # Стадия 2: Параллельное сканирование устройств
            self.scan_progress['stage'] = 'scanning'
            self.scan_progress['total'] = len(devices_ips)
            
            self.devices = self._parallel_device_scan(devices_ips)
            
            # Стадия 3: Анализ и классификация
            self.scan_progress['stage'] = 'analysis'
            self._analyze_network()
            
            scan_duration = time.time() - start_time
            print(f"✅ Сканирование завершено за {scan_duration:.2f} сек")
            print(f"📊 Найдено устройств: {len(self.devices)}")
            
            return self.devices
            
        except Exception as e:
            print(f"❌ Ошибка сканирования: {e}")
            return []
        finally:
            self.scan_progress['active'] = False

    def _fast_discovery(self, network_range: str) -> List[str]:
        """Быстрое обнаружение активных устройств"""
        devices = []
        
        # Метод 1: ARP Ping (самый быстрый)
        try:
            print("   🔍 ARP Ping сканирование...")
            self.nm.scan(hosts=network_range, arguments='-sn -PR --min-rate 1000 --max-retries 1 --host-timeout 5s')
            
            for host in self.nm.all_hosts():
                try:
                    if 'addresses' in self.nm[host]:
                        for addr_type, addr_value in self.nm[host]['addresses'].items():
                            if addr_type == 'mac' and addr_value != '00:00:00:00:00:00':
                                if host not in devices and not self._is_broadcast_ip(host):
                                    devices.append(host)
                                break
                except:
                    continue
                    
            print(f"   ✅ ARP: {len(devices)} устройств")
        except Exception as e:
            print(f"   ⚠️ ARP scan error: {e}")

        # Метод 2: TCP SYN Ping (для устройств без ARP)
        if len(devices) < 3:
            try:
                print("   🔍 TCP SYN сканирование...")
                self.nm.scan(hosts=network_range, arguments='-sn -PS22,80,443,3389 --min-rate 500 --max-retries 1 --host-timeout 3s')
                
                for host in self.nm.all_hosts():
                    if host not in devices and not self._is_broadcast_ip(host):
                        devices.append(host)
                        
                print(f"   ✅ TCP: {len(devices)} устройств")
            except Exception as e:
                print(f"   ⚠️ TCP scan error: {e}")

        return list(set(devices))  # Убираем дубликаты

    def _parallel_device_scan(self, devices_ips: List[str]) -> List[Dict[str, Any]]:
        """Параллельное сканирование устройств"""
        def scan_single_device(ip: str) -> Dict[str, Any]:
            try:
                self.scan_progress['current'] += 1
                device_info = self._create_device_info(ip)
                
                if self._is_valid_device(device_info):
                    # Сканирование портов
                    self._scan_device_ports(device_info)
                    # Сканирование сервисов
                    self._scan_device_services(device_info)
                    # Классификация
                    self._classify_device(device_info)
                    
                    print(f"   ✅ {ip} - {device_info['hostname']}")
                    return device_info
                    
            except Exception as e:
                print(f"   ❌ Ошибка сканирования {ip}: {e}")
            return None

        print(f"   🚀 Параллельное сканирование {len(devices_ips)} устройств...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(scan_single_device, devices_ips))
        
        return [device for device in results if device is not None]

    def _create_device_info(self, ip: str) -> Dict[str, Any]:
        """Создание базовой информации об устройстве"""
        device_info = {
            'ip': ip,
            'mac': 'Unknown',
            'vendor': 'Unknown',
            'hostname': 'Unknown',
            'status': 'up',
            'os': 'Unknown',
            'hardware': {
                'type': 'Unknown',
                'category': 'unknown',
                'vendor': 'Unknown',
                'confidence': '0%'
            },
            'ports': [],
            'services': [],
            'risk_score': 0,
            'last_seen': datetime.now().isoformat(),
            'response_time': 0
        }
        
        try:
            # Базовая информация из nmap
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                
                # MAC адрес
                if 'addresses' in host_info:
                    for addr_type, addr_value in host_info['addresses'].items():
                        if addr_type == 'mac':
                            device_info['mac'] = addr_value
                            break
                
                # Вендор
                if 'vendor' in host_info and device_info['mac'] in host_info['vendor']:
                    device_info['vendor'] = host_info['vendor'][device_info['mac']]
                
                # Hostname
                if 'hostnames' in host_info and host_info['hostnames']:
                    hostname = host_info['hostnames'][0]['name']
                    if hostname and hostname not in ['', 'localhost', ip]:
                        device_info['hostname'] = hostname
                
                # Резервный hostname
                if device_info['hostname'] == 'Unknown':
                    device_info['hostname'] = self._get_hostname_fallback(ip)
                    
        except Exception as e:
            print(f"      ⚠️ Device info error for {ip}: {e}")
        
        return device_info

    def _scan_device_ports(self, device_info: Dict[str, Any]):
        """Сканирование портов устройства"""
        try:
            ip = device_info['ip']
            device_type = device_info['hardware']['type'].lower()
            
            # Умный выбор портов в зависимости от типа устройства
            port_profile = self._get_port_profile(device_type)
            scan_args = f'-sS {port_profile} --min-rate 1000 --max-retries 1 --host-timeout 10s'
            
            self.nm.scan(hosts=ip, arguments=scan_args)
            
            # Обновляем информацию о портах
            device_info['ports'] = []
            if 'tcp' in self.nm[ip]:
                for port, info in self.nm[ip]['tcp'].items():
                    if info['state'] == 'open':
                        device_info['ports'].append({
                            'port': port,
                            'state': info['state'],
                            'service': info['name'],
                            'version': info.get('version', ''),
                            'product': info.get('product', '')
                        })
                        
        except Exception as e:
            print(f"      ⚠️ Port scan error for {device_info['ip']}: {e}")

    def _scan_device_services(self, device_info: Dict[str, Any]):
        """Сканирование сервисов и ОС"""
        try:
            ip = device_info['ip']
            
            if device_info['ports']:  # Только если есть открытые порты
                scan_args = '-sV --version-intensity 5 -O --osscan-limit --max-retries 1 --host-timeout 15s'
                self.nm.scan(hosts=ip, arguments=scan_args)
                
                # Обновляем информацию о сервисах
                device_info['services'] = []
                if 'tcp' in self.nm[ip]:
                    for port, info in self.nm[ip]['tcp'].items():
                        if info['state'] == 'open':
                            service_info = {
                                'port': port,
                                'name': info['name'],
                                'product': info.get('product', ''),
                                'version': info.get('version', ''),
                                'extrainfo': info.get('extrainfo', '')
                            }
                            device_info['services'].append(service_info)
                
                # Обновляем информацию об ОС
                if 'osmatch' in self.nm[ip] and self.nm[ip]['osmatch']:
                    best_os = self.nm[ip]['osmatch'][0]
                    accuracy = best_os.get('accuracy', '0')
                    device_info['os'] = f"{best_os['name']} ({accuracy}%)"
                    
        except Exception as e:
            print(f"      ⚠️ Service scan error for {device_info['ip']}: {e}")

    def _classify_device(self, device_info: Dict[str, Any]):
        """Классификация устройства"""
        hostname = device_info['hostname'].lower()
        vendor = device_info['vendor'].lower()
        mac = device_info['mac'].upper()
        services = [s['name'] for s in device_info.get('services', [])]
        
        # Классификация по MAC
        device_type = self._classify_by_mac(mac)
        if device_type == 'Unknown':
            # Классификация по hostname и vendor
            device_type = self._classify_by_name(hostname, vendor)
        
        device_info['hardware']['type'] = device_type
        device_info['hardware']['category'] = self._determine_category(device_type, hostname, services)
        device_info['risk_score'] = self._calculate_risk_score(device_info)

    def _classify_by_mac(self, mac: str) -> str:
        """Классификация по MAC адресу"""
        mac_oui = {
            'Apple': ['00:03:93', '00:05:02', '00:0A:27', '00:0A:95', '00:1B:63', '00:1C:B3'],
            'Samsung': ['00:12:47', '00:15:99', '00:16:32', '00:16:6B', '00:16:DB', '00:17:C9'],
            'Cisco': ['00:00:0C', '00:01:42', '00:01:43', '00:01:63', '00:01:64'],
            'TP-Link': ['00:1D:0F', '00:21:27', '00:23:CD', '00:26:4B'],
            'D-Link': ['00:05:5D', '00:0D:88', '00:0F:3D', '00:11:95', '00:13:46'],
            'Xiaomi': ['34:12:98', '64:CC:2E', '80:89:17', '8C:BE:BE'],
            'Huawei': ['00:18:82', '00:25:9E', '00:46:4B', '30:87:30', '54:89:98']
        }
        
        for vendor, prefixes in mac_oui.items():
            for prefix in prefixes:
                if mac.startswith(prefix):
                    return f"{vendor} Device"
        
        return 'Unknown'

    def _classify_by_name(self, hostname: str, vendor: str) -> str:
        """Классификация по имени и вендору"""
        router_keywords = ['router', 'gateway', 'asus', 'tplink', 'dlink', 'netgear', 'linksys']
        phone_keywords = ['android', 'iphone', 'samsung', 'xiaomi', 'huawei', 'oneplus']
        server_keywords = ['server', 'nas', 'storage', 'cloud']
        
        if any(keyword in hostname for keyword in router_keywords):
            return 'Router'
        elif any(keyword in vendor for keyword in router_keywords):
            return 'Router'
        elif any(keyword in hostname for keyword in phone_keywords):
            return 'Smartphone'
        elif any(keyword in vendor for keyword in phone_keywords):
            return 'Smartphone'
        elif any(keyword in hostname for keyword in server_keywords):
            return 'Server'
        
        return 'Network Device'

    def _determine_category(self, device_type: str, hostname: str, services: List[str]) -> str:
        """Определение категории устройства"""
        category_map = {
            'Router': 'network_infrastructure',
            'Cisco Device': 'network_infrastructure',
            'TP-Link Device': 'network_infrastructure',
            'D-Link Device': 'network_infrastructure',
            'Smartphone': 'mobile',
            'Apple Device': 'mobile',
            'Samsung Device': 'mobile',
            'Xiaomi Device': 'mobile',
            'Huawei Device': 'mobile',
            'Server': 'server'
        }
        
        # Дополнительная проверка по сервисам
        if 'http' in services or 'https' in services:
            if any(keyword in hostname for keyword in ['printer', 'print']):
                return 'printer'
            elif any(keyword in hostname for keyword in ['tv', 'smart']):
                return 'iot'
        
        return category_map.get(device_type, 'computer')

    def _calculate_risk_score(self, device_info: Dict[str, Any]) -> int:
        """Расчет оценки риска"""
        score = 0
        
        # Базовый риск по категории
        category_risk = {
            'network_infrastructure': 30,
            'server': 25,
            'printer': 10,
            'iot': 20,
            'mobile': 5,
            'computer': 15
        }
        score += category_risk.get(device_info['hardware']['category'], 10)
        
        # Риск по открытым портам
        risky_ports = {
            21: 10,   # FTP
            23: 15,   # Telnet
            135: 10,  # RPC
            139: 10,  # NetBIOS
            445: 20,  # SMB
            3389: 15  # RDP
        }
        
        for port in device_info.get('ports', []):
            if port['port'] in risky_ports:
                score += risky_ports[port['port']]
        
        # Дополнительный риск если нет MAC
        if device_info['mac'] == 'Unknown':
            score += 10
            
        return min(score, 100)

    def _get_port_profile(self, device_type: str) -> str:
        """Получить профиль портов для типа устройства"""
        profiles = {
            'router': '-p 22,23,80,443,8080,8443,161,199,1723,8291',
            'server': '-p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5985,5986',
            'printer': '-p 80,443,515,631,9100',
            'iot': '-p 22,23,80,443,1883,8883,5683,8080,8443',
            'mobile': '-p 62078,54987,54992,54995,8080',
            'computer': '-p 135,139,445,3389,5985,5986,5800,5900',
            'default': '--top-ports 50'
        }
        
        return profiles.get(device_type, profiles['default'])

    def _analyze_network(self):
        """Анализ всей сети"""
        print("   📊 Анализ сети...")
        
        for device in self.devices:
            # Дополнительный анализ каждого устройства
            self._analyze_device_risks(device)

    def _analyze_device_risks(self, device: Dict[str, Any]):
        """Анализ рисков устройства"""
        risks = []
        
        # Проверка опасных конфигураций
        if any(port['port'] == 23 for port in device.get('ports', [])):  # Telnet
            risks.append('Telnet service enabled - plain text authentication')
            
        if any(port['port'] == 21 for port in device.get('ports', [])):  # FTP
            risks.append('FTP service enabled - plain text credentials')
            
        if device['hardware']['type'] == 'Router' and any(port['port'] == 80 for port in device.get('ports', [])):
            risks.append('Router web interface on HTTP - consider using HTTPS')
        
        device['security_risks'] = risks
        if risks:
            device['risk_score'] += len(risks) * 5

    def _is_broadcast_ip(self, ip: str) -> bool:
        """Проверка является ли IP широковещательным"""
        return ip.endswith('.0') or ip.endswith('.255') or ip in ['255.255.255.255', '0.0.0.0']

    def _is_valid_device(self, device_info: Dict[str, Any]) -> bool:
        """Проверка валидности устройства"""
        ip = device_info['ip']
        
        if self._is_broadcast_ip(ip):
            return False
            
        if ip == '127.0.0.1':
            return False
            
        return True

    def _get_hostname_fallback(self, ip: str) -> str:
        """Резервное получение hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname
        except:
            pass
        return f"host-{ip.replace('.', '-')}"

    def _calculate_network(self, ip: str, netmask: str) -> str:
        """Вычисление сети"""
        ip_parts = [int(x) for x in ip.split('.')]
        mask_parts = [int(x) for x in netmask.split('.')]
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        return '.'.join(str(x) for x in network_parts) + '/24'

    def get_scan_progress(self) -> Dict[str, Any]:
        """Получить текущий прогресс сканирования"""
        return self.scan_progress.copy()

    def get_network_summary(self) -> str:
        """Получить сводку по сети"""
        if not self.network_info:
            return "Сеть не определена"
        
        devices_by_type = {}
        devices_by_category = {}
        total_risk = 0
        
        for device in self.devices:
            device_type = device['hardware']['type']
            category = device['hardware']['category']
            
            devices_by_type[device_type] = devices_by_type.get(device_type, 0) + 1
            devices_by_category[category] = devices_by_category.get(category, 0) + 1
            total_risk += device['risk_score']
        
        avg_risk = total_risk / len(self.devices) if self.devices else 0
        
        summary = f"🌐 СЕТЕВАЯ СВОДКА\n"
        summary += "=" * 50 + "\n"
        summary += f"📡 Сеть: {self.network_info['network']}\n"
        summary += f"🖥️  Локальный IP: {self.network_info['local_ip']}\n"
        summary += f"🚪 Шлюз: {self.network_info['gateway']}\n"
        summary += f"📊 Всего устройств: {len(self.devices)}\n"
        summary += f"⚠️  Средний риск: {avg_risk:.1f}/100\n\n"
        
        summary += "🛠️ ТИПЫ УСТРОЙСТВ:\n"
        for device_type, count in devices_by_type.items():
            summary += f"  • {device_type}: {count}\n"
        
        summary += "\n📂 КАТЕГОРИИ:\n"
        for category, count in devices_by_category.items():
            summary += f"  • {category}: {count}\n"
        
        return summary

    def export_results(self, filename: str):
        """Экспорт результатов"""
        data = {
            'scan_time': datetime.now().isoformat(),
            'network_info': self.network_info,
            'devices': self.devices
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
