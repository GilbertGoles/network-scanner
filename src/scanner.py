import nmap
import netifaces
import json
import socket
from datetime import datetime
import threading
import time

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.network_info = {}
        self.devices = []
        self.scan_lock = threading.Lock()
        
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
        """Точное сканирование сети - только реальные активные устройства"""
        if not network_range:
            if not self.network_info:
                self.get_local_network()
            network_range = self.network_info.get('network', '192.168.1.0/24')
        
        print(f"🔍 Сканирование: {network_range}")
        
        try:
            # ОЧИЩАЕМ старые устройства перед новым сканированием
            self.devices = []
            
            # ПЕРВАЯ СТАДИЯ: Точное обнаружение реальных устройств
            print("🔍 Стадия 1: Точное обнаружение реальных устройств...")
            
            real_devices = []
            
            # Метод 1: ARP scan - самый точный для локальной сети
            print("   📡 ARP scan (самый точный метод)...")
            try:
                self.nm.scan(hosts=network_range, arguments='-sn -PR --min-rate 1000 --max-retries 1')
                arp_hosts = self.nm.all_hosts()
                print(f"   📊 ARP scan raw: {len(arp_hosts)} хостов")
                
                # Фильтруем только устройства с MAC адресами
                for host in arp_hosts:
                    try:
                        if 'addresses' in self.nm[host]:
                            has_mac = False
                            for addr_type, addr_value in self.nm[host]['addresses'].items():
                                if addr_type == 'mac':
                                    # Проверяем что MAC валидный (не 00:00:00:00:00:00)
                                    if addr_value != '00:00:00:00:00:00' and len(addr_value) == 17:
                                        has_mac = True
                                        break
                            if has_mac:
                                real_devices.append(host)
                    except Exception as e:
                        continue
                
                print(f"   ✅ ARP scan filtered: {len(real_devices)} реальных устройств")
                
            except Exception as e:
                print(f"   ⚠️ ARP scan error: {e}")
            
            # Метод 2: Ping scan для устройств которые не отвечают на ARP
            if len(real_devices) < 3:  # Если нашлось мало устройств
                print("   📡 Ping scan (дополнительный метод)...")
                try:
                    self.nm.scan(hosts=network_range, arguments='-sn --min-rate 500 --max-retries 2')
                    ping_hosts = self.nm.all_hosts()
                    
                    # Добавляем только новые устройства
                    for host in ping_hosts:
                        if host not in real_devices:
                            # Проверяем что это не широковещательные адреса
                            if not host.endswith('.0') and not host.endswith('.255'):
                                real_devices.append(host)
                    
                    print(f"   ✅ После ping scan: {len(real_devices)} устройств")
                except Exception as e:
                    print(f"   ⚠️ Ping scan error: {e}")
            
            # Убираем дубликаты и сортируем
            real_devices = list(set(real_devices))
            real_devices.sort()
            
            print(f"🎯 Всего уникальных устройств: {len(real_devices)}")
            
            # СОЗДАЕМ информацию об устройствах
            for host in real_devices:
                device_info = self._create_device_info(host)
                
                # ДОПОЛНИТЕЛЬНАЯ ФИЛЬТРАЦИЯ: пропускаем сомнительные устройства
                if self._is_valid_device(device_info):
                    self.devices.append(device_info)
                    print(f"   ✅ {host} - {device_info['hostname']} ({device_info['mac']})")
                else:
                    print(f"   ❌ {host} - пропущено (сомнительное устройство)")
            
            # ВТОРАЯ СТАДИЯ: Детальное сканирование только реальных устройств
            if self.devices:
                print(f"🔍 Стадия 2: Детальное сканирование {len(self.devices)} реальных устройств...")
                self._smart_detailed_scan()
            else:
                print("❌ Реальные устройства не найдены")
            
            print(f"🎯 Итоговое количество реальных устройств: {len(self.devices)}")
            return self.devices
            
        except Exception as e:
            print(f"❌ Ошибка сканирования: {e}")
            return []

    def _is_valid_device(self, device_info):
        """Проверка что устройство реальное а не ложное"""
        ip = device_info['ip']
        
        # Пропускаем известные проблемные IP
        if ip.endswith('.0') or ip.endswith('.255') or ip.endswith('.1') and device_info['mac'] == 'Unknown':
            return False
        
        # Пропускаем если это широковещательный адрес
        if ip in ['255.255.255.255', '0.0.0.0']:
            return False
        
        # Если есть MAC - устройство реальное
        if device_info['mac'] != 'Unknown':
            return True
        
        # Если нет MAC, но есть вендор или hostname - тоже реальное
        if device_info['vendor'] != 'Unknown' or device_info['hostname'] != 'Unknown':
            return True
        
        # Для устройств без MAC проверяем ping
        try:
            # Быстрая проверка доступности
            socket.setdefaulttimeout(1)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 80))
            return True
        except:
            pass
        
        try:
            # Проверка через ICMP
            subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                         capture_output=True, timeout=2)
            return True
        except:
            return False

    def _smart_detailed_scan(self):
        """Умное детальное сканирование реальных устройств"""
        successful_scans = 0
        
        print(f"   🎯 Детальное сканирование {len(self.devices)} устройств")
        
        for i, device in enumerate(self.devices, 1):
            try:
                print(f"   🔍 [{i}/{len(self.devices)}] Сканирование: {device['ip']} ({device['hostname']})")
                
                # Для приоритетных устройств - глубокое сканирование
                if (device['ip'] == self.network_info.get('gateway') or 
                    device['ip'] == self.network_info.get('local_ip') or
                    device['hostname'] in ['_gateway', 'router']):
                    
                    print(f"      🎯 Приоритетное устройство - глубокое сканирование")
                    scan_args = '-sS -O -A --min-rate 500 --host-timeout 30s --max-retries 2'
                else:
                    print(f"      ⚡ Быстрое сканирование")
                    scan_args = '-sS -O --osscan-limit --max-retries 1 --host-timeout 15s'
                
                # Выполняем сканирование
                self.nm.scan(hosts=device['ip'], arguments=scan_args)
                
                # ОБНОВЛЯЕМ информацию устройства
                self._update_device_info(device)
                device['scan_stage'] = 'detailed'
                successful_scans += 1
                
                # Небольшая пауза между сканированиями
                if i < len(self.devices):
                    time.sleep(1)
                
            except Exception as e:
                print(f"      ⚠️ Ошибка сканирования {device['ip']}: {e}")
        
        print(f"✅ Успешно просканировано: {successful_scans}/{len(self.devices)} устройств")

    def _create_device_info(self, host):
        """Создание базовой информации об устройстве"""
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
                'confidence': '0%'
            },
            'ports': [],
            'last_seen': datetime.now().isoformat(),
            'scan_stage': 'basic'
        }
        
        try:
            # Получаем информацию из nmap
            host_info = self.nm[host]
            
            # Получаем MAC адрес
            if 'addresses' in host_info:
                for addr_type, addr_value in host_info['addresses'].items():
                    if addr_type == 'mac':
                        device_info['mac'] = addr_value
                        break
            
            # Получаем вендора
            if 'vendor' in host_info and device_info['mac'] in host_info['vendor']:
                device_info['vendor'] = host_info['vendor'][device_info['mac']]
                device_info['hardware'] = self._enhance_hardware_info_from_vendor(
                    device_info['vendor'], device_info['hardware']
                )
            elif device_info['mac'] != 'Unknown':
                device_info['vendor'] = f"MAC: {device_info['mac']}"
            
            # Получаем hostname
            if 'hostnames' in host_info and host_info['hostnames']:
                hostname = host_info['hostnames'][0]['name']
                if hostname and hostname not in ['', 'localhost', host]:
                    device_info['hostname'] = hostname
                else:
                    device_info['hostname'] = self._get_hostname_fallback(host)
            else:
                device_info['hostname'] = self._get_hostname_fallback(host)
            
            # Предварительная классификация железа
            device_info['hardware'] = self._classify_hardware_from_basic_info(device_info)
            
        except Exception as e:
            # Игнорируем ошибки для базовой информации
            pass
        
        return device_info

    def _get_hostname_fallback(self, ip):
        """Резервный метод определения hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname
        except:
            pass
        return "Unknown"

    def _update_device_info(self, device):
        """ОБНОВЛЯЕМ информацию устройства"""
        host = device['ip']
        
        try:
            host_info = self.nm[host]
            
            # Обновляем ОС если нашли
            if 'osmatch' in host_info and host_info['osmatch']:
                best_os = host_info['osmatch'][0]
                accuracy = best_os.get('accuracy', '0')
                device['os'] = f"{best_os['name']} (accuracy: {accuracy}%)"
                
                # Обновляем информацию о железе
                device['hardware'] = self._extract_hardware_info(best_os, device)
            
            # Обновляем hostname если нашли лучше
            if 'hostnames' in host_info and host_info['hostnames']:
                hostname = host_info['hostnames'][0]['name']
                if hostname and hostname != device['ip'] and hostname not in ['', 'localhost']:
                    device['hostname'] = hostname
            
            # Обновляем MAC и vendor если не нашли ранее
            if (device['mac'] == 'Unknown' or device['vendor'] == 'Unknown') and 'addresses' in host_info:
                for addr_type, addr_value in host_info['addresses'].items():
                    if addr_type == 'mac':
                        device['mac'] = addr_value
                        if 'vendor' in host_info and addr_value in host_info['vendor']:
                            device['vendor'] = host_info['vendor'][addr_value]
                            device['hardware'] = self._enhance_hardware_info_from_vendor(
                                device['vendor'], device['hardware']
                            )
                        break
            
            # Сканируем порты
            device['ports'] = []
            if 'tcp' in host_info:
                for port, info in host_info['tcp'].items():
                    if info['state'] == 'open':
                        device['ports'].append({
                            'port': port,
                            'state': info['state'],
                            'service': info['name'],
                            'version': info.get('version', 'Unknown'),
                            'product': info.get('product', 'Unknown')
                        })
            
            print(f"      ✅ Обновлено: {device['ip']} -> {device['hostname']} | {device['os']}")
            
        except Exception as e:
            print(f"      ⚠️ Ошибка обновления информации для {device['ip']}: {e}")

    def _extract_hardware_info(self, os_match, device):
        """Извлечение информации о железе из данных ОС"""
        hardware_info = device.get('hardware', {
            'type': 'Unknown',
            'architecture': 'Unknown',
            'vendor': 'Unknown',
            'model': 'Unknown',
            'confidence': '0%'
        })
        
        try:
            if 'osclass' in os_match and os_match['osclass']:
                os_class = os_match['osclass'][0]
                hardware_info['type'] = os_class.get('type', hardware_info['type'])
                hardware_info['vendor'] = os_class.get('vendor', hardware_info['vendor'])
                hardware_info['architecture'] = os_class.get('osfamily', hardware_info['architecture'])
                hardware_info['confidence'] = os_class.get('accuracy', '0') + '%'
            
            # Определяем тип устройства более точно
            hardware_info['type'] = self._classify_hardware_type(hardware_info, device)
            
        except Exception as e:
            pass
        
        return hardware_info

    def _classify_hardware_type(self, hardware_info, device):
        """Классификация типа железа"""
        vendor = hardware_info['vendor'].lower()
        hostname = device['hostname'].lower()
        os_info = device['os'].lower()
        
        if 'android' in os_info or 'android' in hostname:
            return 'Smartphone'
        elif 'apple' in vendor or 'iphone' in hostname or 'ipad' in hostname:
            return 'Apple Device'
        elif 'router' in hostname or 'gateway' in hostname:
            return 'Router'
        elif any(word in vendor for word in ['samsung', 'xiaomi', 'huawei']):
            return 'Mobile Device'
        
        return 'Network Device'

    def _enhance_hardware_info_from_vendor(self, vendor, existing_hardware):
        """Улучшение информации о железе на основе vendor"""
        if existing_hardware.get('vendor') == 'Unknown' and vendor != 'Unknown':
            existing_hardware['vendor'] = vendor
        
        vendor_lower = vendor.lower()
        
        if 'samsung' in vendor_lower:
            existing_hardware['model'] = 'Samsung Device'
        elif 'apple' in vendor_lower:
            existing_hardware['model'] = 'Apple Device'
        elif 'xiaomi' in vendor_lower:
            existing_hardware['model'] = 'Xiaomi Device'
        
        return existing_hardware

    def _classify_hardware_from_basic_info(self, device):
        """Предварительная классификация железа по базовой информации"""
        hardware_info = device.get('hardware', {
            'type': 'Unknown',
            'architecture': 'Unknown',
            'vendor': 'Unknown',
            'model': 'Unknown',
            'confidence': '0%'
        })
        
        hostname = device['hostname'].lower()
        vendor = device['vendor'].lower()
        
        if 'android' in hostname:
            hardware_info['type'] = 'Smartphone'
        elif 'iphone' in hostname or 'ipad' in hostname:
            hardware_info['type'] = 'Apple Mobile'
        elif 'router' in hostname or 'gateway' in hostname:
            hardware_info['type'] = 'Router'
        elif any(word in vendor for word in ['samsung', 'xiaomi', 'huawei']):
            hardware_info['type'] = 'Smartphone'
        
        return hardware_info

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
        
        devices_by_type = {}
        
        for device in self.devices:
            device_type = device['hardware'].get('type', 'Unknown')
            devices_by_type[device_type] = devices_by_type.get(device_type, 0) + 1
        
        summary = f"🌐 Сеть: {self.network_info['network']}\n"
        summary += f"📊 Всего реальных устройств: {len(self.devices)}\n\n"
        
        summary += "🛠️ Распределение по типам устройств:\n"
        for device_type, count in devices_by_type.items():
            summary += f"  • {device_type}: {count}\n"
        
        return summary

    def get_device_details(self, ip_address):
        """Получить детальную информацию об устройстве по IP"""
        for device in self.devices:
            if device['ip'] == ip_address:
                details = f"📱 Устройство: {device['hostname']} ({device['ip']})\n"
                details += f"🔧 MAC: {device['mac']}\n"
                details += f"🏷️ Vendor: {device['vendor']}\n"
                details += f"💻 ОС: {device['os']}\n"
                details += f"🔍 Стадия сканирования: {device.get('scan_stage', 'basic')}\n\n"
                
                hardware = device['hardware']
                details += "🛠️ ИНФОРМАЦИЯ О ЖЕЛЕЗЕ:\n"
                details += f"• Тип: {hardware.get('type', 'Unknown')}\n"
                details += f"• Производитель: {hardware.get('vendor', 'Unknown')}\n"
                details += f"• Модель: {hardware.get('model', 'Unknown')}\n\n"
                
                if device['ports']:
                    details += f"🔓 Открытые порты ({len(device['ports'])}):\n"
                    for port in device['ports']:
                        details += f"  • {port['port']}/tcp - {port['service']}\n"
                else:
                    details += "🔒 Открытых портов не обнаружено\n"
                
                return details
        return f"❌ Устройство с IP {ip_address} не найдено"
