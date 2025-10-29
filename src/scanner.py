import nmap
import netifaces
import json
import socket
from datetime import datetime
import threading
import time
import concurrent.futures
import subprocess
from typing import List, Dict, Any

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.network_info = {}
        self.devices = []
        self.scan_lock = threading.Lock()
        self.scan_stats = {
            'devices_found': 0,
            'ports_scanned': 0,
            'scan_duration': 0,
            'vulnerabilities_found': 0
        }
        
    def get_local_network(self):
        """Определение локальной сети WiFi с улучшенной логикой"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            
            # Ищем WiFi интерфейсы в первую очередь
            wifi_interfaces = ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0']
            
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        # Приоритет WiFi интерфейсам
                        if (interface in wifi_interfaces or 
                            ip.startswith('192.168.') or 
                            ip.startswith('10.') or 
                            (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)):
                            
                            netmask = addr_info.get('netmask', '255.255.255.0')
                            network = self._calculate_network(ip, netmask)
                            
                            self.network_info = {
                                'local_ip': ip,
                                'gateway': default_gateway,
                                'network': network,
                                'netmask': netmask,
                                'interface': interface,
                                'is_wifi': interface in wifi_interfaces
                            }
                            return self.network_info
            return None
        except Exception as e:
            print(f"❌ Ошибка определения сети: {e}")
            return None
    
    def scan_network(self, network_range=None):
        """Ультра-оптимизированное сканирование сети"""
        start_time = time.time()
        
        if not network_range:
            if not self.network_info:
                self.get_local_network()
            network_range = self.network_info.get('network', '192.168.1.0/24')
        
        print(f"🔍 Сканирование: {network_range}")
        
        try:
            # ОЧИЩАЕМ старые устройства
            self.devices = []
            
            # СТАДИЯ 1: Массовое обнаружение устройств
            print("🔍 Стадия 1: Массовое обнаружение устройств...")
            real_devices = self._mass_discovery_phase(network_range)
            
            # СТАДИЯ 2: Параллельное детальное сканирование
            print("🔍 Стадия 2: Параллельное детальное сканирование...")
            self._parallel_detailed_scan(real_devices)
            
            # СТАДИЯ 3: Анализ и классификация
            print("🔍 Стадия 3: Анализ и классификация...")
            self._analyze_and_classify_devices()
            
            # Обновляем статистику
            self.scan_stats['devices_found'] = len(self.devices)
            self.scan_stats['scan_duration'] = time.time() - start_time
            
            print(f"✅ Сканирование завершено за {self.scan_stats['scan_duration']:.2f} сек")
            print(f"📊 Найдено устройств: {len(self.devices)}")
            
            return self.devices
            
        except Exception as e:
            print(f"❌ Ошибка сканирования: {e}")
            return []

    def _mass_discovery_phase(self, network_range):
        """Фаза массового обнаружения устройств"""
        real_devices = []
        
        # Метод 1: ARP scan (самый быстрый и точный)
        print("   📡 ARP Ping scan...")
        try:
            self.nm.scan(hosts=network_range, arguments='-sn -PR --min-rate 1000 --max-retries 1 --host-timeout 10s')
            arp_hosts = self.nm.all_hosts()
            
            for host in arp_hosts:
                try:
                    if 'addresses' in self.nm[host]:
                        for addr_type, addr_value in self.nm[host]['addresses'].items():
                            if addr_type == 'mac' and addr_value != '00:00:00:00:00:00':
                                real_devices.append(host)
                                break
                except:
                    continue
                    
            print(f"   ✅ ARP scan: {len(real_devices)} устройств")
        except Exception as e:
            print(f"   ⚠️ ARP scan error: {e}")

        # Метод 2: TCP SYN Ping для устройств без ARP
        if len(real_devices) < 5:
            print("   📡 TCP SYN Ping scan...")
            try:
                self.nm.scan(hosts=network_range, arguments='-sn -PS22,80,443,3389 --min-rate 500 --max-retries 1')
                tcp_hosts = self.nm.all_hosts()
                
                for host in tcp_hosts:
                    if host not in real_devices and not host.endswith(('.0', '.255')):
                        real_devices.append(host)
                        
                print(f"   ✅ После TCP scan: {len(real_devices)} устройств")
            except Exception as e:
                print(f"   ⚠️ TCP scan error: {e}")

        # Убираем дубликаты и сортируем
        real_devices = list(set(real_devices))
        real_devices.sort()
        
        return real_devices

    def _parallel_detailed_scan(self, real_devices):
        """Параллельное детальное сканирование устройств"""
        def scan_device(device_ip):
            try:
                device_info = self._create_device_info(device_ip)
                
                if self._is_valid_device(device_info):
                    # Умное сканирование портов на основе типа устройства
                    self._smart_port_scan(device_info)
                    
                    # Детальное сканирование ОС и сервисов
                    self._detailed_service_scan(device_info)
                    
                    return device_info
                    
            except Exception as e:
                print(f"   ⚠️ Ошибка сканирования {device_ip}: {e}")
            return None

        # Параллельное сканирование (макс 5 потоков)
        print(f"   🚀 Параллельное сканирование {len(real_devices)} устройств...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(scan_device, real_devices))
        
        # Фильтруем None результаты
        self.devices = [device for device in results if device is not None]

    def _smart_port_scan(self, device_info):
        """Умное сканирование портов на основе типа устройства"""
        device_type = device_info['hardware'].get('type', 'unknown').lower()
        port_profiles = self._get_port_profile(device_type)
        
        try:
            scan_args = f'-sS --top-ports 50 --min-rate 1000 --max-retries 1 --host-timeout 15s'
            
            if port_profiles:
                scan_args = f'-sS -p {port_profiles} --min-rate 2000 --max-retries 1 --host-timeout 10s'
            
            self.nm.scan(hosts=device_info['ip'], arguments=scan_args)
            self._update_port_info(device_info)
            
        except Exception as e:
            print(f"      ⚠️ Port scan error for {device_info['ip']}: {e}")

    def _get_port_profile(self, device_type):
        """Возвращает профиль портов для типа устройства"""
        profiles = {
            'router': '22,23,80,443,8080,8443,161,199,1723,8291,2000',
            'server': '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,5985,5986,6379,27017,9200',
            'iot': '22,23,80,443,1883,8883,5683,8080,8443,9001',
            'computer': '135,139,445,3389,5985,5986,5800,5900',
            'phone': '62078,54987,54992,54995,8080,8433',
            'printer': '80,443,515,631,9100'
        }
        return profiles.get(device_type, '21,22,23,80,443,3389,8080,8443')

    def _detailed_service_scan(self, device_info):
        """Детальное сканирование сервисов и ОС"""
        try:
            # Сканирование версий сервисов
            self.nm.scan(hosts=device_info['ip'], 
                        arguments='-sV --version-intensity 7 --script banner,ssh2-enum-algos,ssl-cert -O --osscan-limit --max-retries 1 --host-timeout 20s')
            
            self._update_service_info(device_info)
            self._update_os_info(device_info)
            
        except Exception as e:
            print(f"      ⚠️ Service scan error for {device_info['ip']}: {e}")

    def _create_device_info(self, host):
        """Создание информации об устройстве с улучшенной классификацией"""
        device_info = {
            'ip': host,
            'mac': 'Unknown',
            'vendor': 'Unknown',
            'hostname': 'Unknown',
            'status': 'up',
            'os': 'Unknown',
            'hardware': {
                'type': 'Unknown',
                'architecture': 'Unknown',
                'vendor': 'Unknown',
                'model': 'Unknown',
                'confidence': '0%',
                'category': 'unknown'
            },
            'ports': [],
            'services': [],
            'vulnerabilities': [],
            'risk_score': 0,
            'last_seen': datetime.now().isoformat(),
            'scan_stage': 'detailed'
        }
        
        try:
            host_info = self.nm[host]
            
            # Базовая информация
            self._extract_basic_info(host_info, device_info)
            
            # Классификация устройства
            self._classify_device(device_info)
            
        except Exception as e:
            print(f"      ⚠️ Device info error for {host}: {e}")
        
        return device_info

    def _extract_basic_info(self, host_info, device_info):
        """Извлечение базовой информации об устройстве"""
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
            if hostname and hostname not in ['', 'localhost', device_info['ip']]:
                device_info['hostname'] = hostname
            else:
                device_info['hostname'] = self._get_hostname_fallback(device_info['ip'])

    def _classify_device(self, device_info):
        """Улучшенная классификация устройства"""
        hostname = device_info['hostname'].lower()
        vendor = device_info['vendor'].lower()
        mac = device_info['mac'].upper()
        
        # Определяем тип по MAC OUI
        device_type = self._classify_by_mac(mac, vendor, hostname)
        device_info['hardware']['type'] = device_type
        
        # Определяем категорию
        device_info['hardware']['category'] = self._determine_category(device_type, hostname, vendor)
        
        # Рассчитываем риск
        device_info['risk_score'] = self._calculate_risk_score(device_info)

    def _classify_by_mac(self, mac, vendor, hostname):
        """Классификация по MAC адресу"""
        # Apple devices
        if mac.startswith(('00:03:93', '00:05:02', '00:0A:27', '00:0A:95', '00:1B:63', '00:1C:B3', 
                          '00:1D:4F', '00:1E:52', '00:1E:C2', '00:1F:5B', '00:1F:F3', '00:21:E9',
                          '00:22:41', '00:23:12', '00:23:32', '00:23:6C', '00:23:DF', '00:24:36',
                          '00:25:00', '00:25:4B', '00:25:BC', '00:26:08', '00:26:4A', '00:26:B0')):
            return 'Apple Device'
        
        # Samsung
        elif mac.startswith(('00:12:47', '00:15:99', '00:16:32', '00:16:6B', '00:16:DB', '00:17:C9',
                           '00:18:AF', '00:1A:8A', '00:1B:98', '00:1C:43', '00:1D:25', '00:1D:F6')):
            return 'Samsung Device'
        
        # Cisco
        elif mac.startswith(('00:00:0C', '00:01:42', '00:01:43', '00:01:63', '00:01:64', '00:01:96',
                           '00:01:97', '00:01:C7', '00:01:C9')):
            return 'Cisco Router'
        
        # TP-Link
        elif mac.startswith(('00:1D:0F', '00:21:27', '00:23:CD', '00:26:4B')):
            return 'TP-Link Router'
        
        # По hostname и vendor
        elif any(word in hostname for word in ['router', 'gateway', 'asus', 'd-link', 'netgear']):
            return 'Router'
        elif any(word in vendor for word in ['cisco', 'ubiquiti', 'mikrotik']):
            return 'Router'
        elif any(word in hostname for word in ['android', 'iphone', 'samsung', 'xiaomi']):
            return 'Smartphone'
        elif any(word in vendor for word in ['apple', 'samsung', 'xiaomi']):
            return 'Smartphone'
        
        return 'Network Device'

    def _determine_category(self, device_type, hostname, vendor):
        """Определение категории устройства"""
        if device_type in ['Router', 'Cisco Router', 'TP-Link Router']:
            return 'network_infrastructure'
        elif device_type in ['Smartphone', 'Apple Device', 'Samsung Device']:
            return 'mobile'
        elif any(word in hostname for word in ['server', 'nas', 'storage']):
            return 'server'
        elif any(word in hostname for word in ['printer', 'print']):
            return 'printer'
        elif any(word in hostname for word in ['tv', 'smarttv', 'chromecast']):
            return 'iot'
        else:
            return 'computer'

    def _calculate_risk_score(self, device_info):
        """Расчет оценки риска для устройства"""
        score = 0
        
        # Повышаем риск для сетевого оборудования
        if device_info['hardware']['category'] == 'network_infrastructure':
            score += 30
        
        # Повышаем риск для устройств с открытыми портами
        if device_info['ports']:
            score += len(device_info['ports']) * 2
            
            # Высокорисковые порты
            risky_ports = [21, 23, 135, 139, 445, 3389]  # FTP, Telnet, SMB, RDP
            for port in device_info['ports']:
                if port['port'] in risky_ports:
                    score += 10
        
        # Повышаем риск для устройств без MAC (возможно скрытые)
        if device_info['mac'] == 'Unknown':
            score += 15
            
        return min(score, 100)

    def _update_port_info(self, device_info):
        """Обновление информации о портах"""
        try:
            host = device_info['ip']
            device_info['ports'] = []
            
            if 'tcp' in self.nm[host]:
                for port, info in self.nm[host]['tcp'].items():
                    if info['state'] == 'open':
                        device_info['ports'].append({
                            'port': port,
                            'state': info['state'],
                            'service': info['name'],
                            'version': info.get('version', 'Unknown'),
                            'product': info.get('product', 'Unknown')
                        })
                        
        except Exception as e:
            print(f"      ⚠️ Port update error: {e}")

    def _update_service_info(self, device_info):
        """Обновление информации о сервисах"""
        try:
            host = device_info['ip']
            device_info['services'] = []
            
            if 'tcp' in self.nm[host]:
                for port, info in self.nm[host]['tcp'].items():
                    if info['state'] == 'open':
                        service_info = {
                            'port': port,
                            'name': info['name'],
                            'product': info.get('product', ''),
                            'version': info.get('version', ''),
                            'extrainfo': info.get('extrainfo', '')
                        }
                        device_info['services'].append(service_info)
                        
        except Exception as e:
            print(f"      ⚠️ Service update error: {e}")

    def _update_os_info(self, device_info):
        """Обновление информации об ОС"""
        try:
            host = device_info['ip']
            host_info = self.nm[host]
            
            if 'osmatch' in host_info and host_info['osmatch']:
                best_os = host_info['osmatch'][0]
                accuracy = best_os.get('accuracy', '0')
                device_info['os'] = f"{best_os['name']} (accuracy: {accuracy}%)"
                
                # Обновляем информацию о железе
                if 'osclass' in best_os and best_os['osclass']:
                    os_class = best_os['osclass'][0]
                    device_info['hardware'].update({
                        'type': os_class.get('type', device_info['hardware']['type']),
                        'vendor': os_class.get('vendor', device_info['hardware']['vendor']),
                        'architecture': os_class.get('osfamily', device_info['hardware']['architecture']),
                        'confidence': f"{accuracy}%"
                    })
                    
        except Exception as e:
            print(f"      ⚠️ OS update error: {e}")

    def _analyze_and_classify_devices(self):
        """Анализ и классификация найденных устройств"""
        for device in self.devices:
            # Дополнительная классификация на основе собранных данных
            self._enhance_device_classification(device)
            
            # Анализ рисков
            self._analyze_device_risks(device)

    def _enhance_device_classification(self, device):
        """Улучшенная классификация на основе всех данных"""
        services = [s['name'] for s in device.get('services', [])]
        ports = [p['port'] for p in device.get('ports', [])]
        
        # Определяем по сервисам
        if any(s in services for s in ['http', 'https', 'www']):
            if any(p in ports for p in [80, 443, 8080, 8443]):
                device['hardware']['category'] = 'web_server'
                
        if 'ssh' in services:
            device['hardware']['category'] = 'server'
            
        if any(s in services for s in ['microsoft-ds', 'netbios-ssn']):
            device['hardware']['category'] = 'windows_device'

    def _analyze_device_risks(self, device):
        """Анализ рисков устройства"""
        risks = []
        
        # Проверяем опасные порты
        dangerous_ports = {
            21: 'FTP - Plain text credentials',
            23: 'Telnet - Plain text everything', 
            135: 'RPC - Multiple vulnerabilities',
            139: 'NetBIOS - Information disclosure',
            445: 'SMB - EternalBlue potential',
            3389: 'RDP - BlueKeep potential'
        }
        
        for port in device.get('ports', []):
            if port['port'] in dangerous_ports:
                risks.append({
                    'type': 'dangerous_port',
                    'port': port['port'],
                    'description': dangerous_ports[port['port']],
                    'risk_level': 'HIGH'
                })
        
        # Проверяем устаревшие сервисы
        outdated_services = ['telnet', 'ftp', 'rsh', 'rexec']
        for service in device.get('services', []):
            if service['name'] in outdated_services:
                risks.append({
                    'type': 'outdated_service',
                    'service': service['name'],
                    'description': f'Outdated and insecure service: {service["name"]}',
                    'risk_level': 'HIGH'
                })
        
        device['vulnerabilities'] = risks
        device['risk_score'] += len(risks) * 10

    def _is_valid_device(self, device_info):
        """Проверка валидности устройства"""
        ip = device_info['ip']
        
        # Отсеиваем широковещательные адреса
        if ip.endswith('.0') or ip.endswith('.255'):
            return False
            
        # Отсеиваем localhost
        if ip in ['127.0.0.1', 'localhost']:
            return False
            
        return True

    def _get_hostname_fallback(self, ip):
        """Резервный метод определения hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname
        except:
            pass
        return f"host-{ip.replace('.', '-')}"

    def _calculate_network(self, ip, netmask):
        """Вычисление сети по IP и маске"""
        ip_parts = [int(x) for x in ip.split('.')]
        mask_parts = [int(x) for x in netmask.split('.')]
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        return '.'.join(str(x) for x in network_parts) + '/24'

    def get_network_summary(self):
        """Получить расширенную сводку по сети"""
        if not self.network_info:
            return "Сеть не определена"
        
        devices_by_type = {}
        devices_by_category = {}
        total_risk = 0
        
        for device in self.devices:
            device_type = device['hardware'].get('type', 'Unknown')
            category = device['hardware'].get('category', 'unknown')
            
            devices_by_type[device_type] = devices_by_type.get(device_type, 0) + 1
            devices_by_category[category] = devices_by_category.get(category, 0) + 1
            total_risk += device['risk_score']
        
        avg_risk = total_risk / len(self.devices) if self.devices else 0
        
        summary = f"🌐 СЕТЕВАЯ СВОДКА\n"
        summary += "=" * 40 + "\n"
        summary += f"📡 Сеть: {self.network_info['network']}\n"
        summary += f"🖥️  Локальный IP: {self.network_info['local_ip']}\n"
        summary += f"🚪 Шлюз: {self.network_info['gateway']}\n"
        summary += f"📊 Всего устройств: {len(self.devices)}\n"
        summary += f"⚠️  Средний риск: {avg_risk:.1f}/100\n\n"
        
        summary += "🛠️ РАСПРЕДЕЛЕНИЕ ПО ТИПАМ:\n"
        for device_type, count in devices_by_type.items():
            summary += f"  • {device_type}: {count}\n"
        
        summary += "\n📂 РАСПРЕДЕЛЕНИЕ ПО КАТЕГОРИЯМ:\n"
        for category, count in devices_by_category.items():
            summary += f"  • {category}: {count}\n"
        
        # Топ рисковых устройств
        risky_devices = sorted(self.devices, key=lambda x: x['risk_score'], reverse=True)[:3]
        if risky_devices:
            summary += "\n🚨 ТОП РИСКОВЫХ УСТРОЙСТВ:\n"
            for device in risky_devices:
                summary += f"  • {device['ip']} - {device['hostname']} (риск: {device['risk_score']})\n"
        
        return summary

    def export_results(self, devices, filename):
        """Экспорт результатов в JSON"""
        data = {
            'scan_time': datetime.now().isoformat(),
            'network_info': self.network_info,
            'scan_stats': self.scan_stats,
            'devices': devices
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def get_scan_statistics(self):
        """Получить статистику сканирования"""
        return self.scan_stats
