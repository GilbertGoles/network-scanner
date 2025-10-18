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
        """Умное сканирование сети - только реальные устройства"""
        if not network_range:
            if not self.network_info:
                self.get_local_network()
            network_range = self.network_info.get('network', '192.168.1.0/24')
        
        print(f"🔍 Сканирование: {network_range}")
        
        try:
            # ОЧИЩАЕМ старые устройства перед новым сканированием
            self.devices = []
            
            # ПЕРВАЯ СТАДИЯ: Обнаружение реальных устройств
            print("🔍 Стадия 1: Обнаружение реальных устройств...")
            
            # Используем ARP scan - он находит только реальные устройства
            print("   📡 ARP scan (только реальные устройства)...")
            try:
                self.nm.scan(hosts=network_range, arguments='-sn -PR --min-rate 1000')
                arp_hosts = self.nm.all_hosts()
                print(f"   ✅ ARP scan found: {len(arp_hosts)} real devices")
                
                # Фильтруем только устройства с MAC адресами (реальные устройства)
                real_devices = []
                for host in arp_hosts:
                    try:
                        if 'addresses' in self.nm[host]:
                            for addr_type, addr_value in self.nm[host]['addresses'].items():
                                if addr_type == 'mac':
                                    real_devices.append(host)
                                    break
                    except:
                        continue
                
                print(f"   🔍 Real devices with MAC: {len(real_devices)}")
                
            except Exception as e:
                print(f"   ⚠️ ARP scan error: {e}")
                real_devices = []
            
            # Если ARP не нашел устройства, используем комбинированный подход
            if len(real_devices) < 5:  # Мало устройств найдено
                print("   📡 Комбинированное сканирование...")
                all_hosts = set()
                
                # Метод 2: Ping scan
                try:
                    self.nm.scan(hosts=network_range, arguments='-sn --min-rate 1000')
                    all_hosts.update(self.nm.all_hosts())
                except:
                    pass
                
                # Метод 3: No-ping scan
                try:
                    self.nm.scan(hosts=network_range, arguments='-sn -Pn --min-rate 500')
                    all_hosts.update(self.nm.all_hosts())
                except:
                    pass
                
                real_devices = list(all_hosts)
                print(f"   ✅ Combined scan found: {len(real_devices)} devices")
            
            # ОГРАНИЧИВАЕМ количество устройств для сканирования
            max_devices_to_scan = 20  # Максимум 20 устройств для детального сканирования
            if len(real_devices) > max_devices_to_scan:
                print(f"   ⚠️ Too many devices ({len(real_devices)}), limiting to {max_devices_to_scan}")
                # Приоритет: шлюз, локальный IP, затем случайные
                priority_hosts = []
                other_hosts = []
                
                for host in real_devices:
                    if (host == self.network_info.get('gateway') or 
                        host == self.network_info.get('local_ip')):
                        priority_hosts.append(host)
                    else:
                        other_hosts.append(host)
                
                # Сохраняем приоритетные + часть остальных
                real_devices = priority_hosts + other_hosts[:max_devices_to_scan - len(priority_hosts)]
            
            print(f"🎯 Будет просканировано: {len(real_devices)} устройств")
            
            # СОЗДАЕМ информацию об устройствах
            for host in real_devices:
                device_info = self._create_device_info(host)
                self.devices.append(device_info)
                print(f"   📍 {host} - {device_info['hostname']} ({device_info['mac']})")
            
            # ВТОРАЯ СТАДИЯ: Умное детальное сканирование
            if self.devices:
                print(f"🔍 Стадия 2: Детальное сканирование {len(self.devices)} устройств...")
                self._smart_detailed_scan()
            else:
                print("❌ Устройства не найдены")
            
            print(f"🎯 Итоговое количество устройств: {len(self.devices)}")
            return self.devices
            
        except Exception as e:
            print(f"❌ Ошибка сканирования: {e}")
            return []

    def _smart_detailed_scan(self):
        """Умное детальное сканирование - только важные устройства"""
        successful_scans = 0
        devices_to_scan = []
        
        # СОРТИРУЕМ устройства по приоритету
        for device in self.devices:
            priority = 0
            
            # Высший приоритет: шлюз и локальный IP
            if (device['ip'] == self.network_info.get('gateway') or 
                device['ip'] == self.network_info.get('local_ip')):
                priority = 100
            # Высокий приоритет: устройства с известными hostname
            elif device['hostname'] not in ['Unknown', 'localhost']:
                priority = 50
            # Средний приоритет: устройства с MAC адресами
            elif device['mac'] != 'Unknown':
                priority = 25
            # Низкий приоритет: остальные
            else:
                priority = 10
            
            devices_to_scan.append((priority, device))
        
        # Сортируем по приоритету (убывание)
        devices_to_scan.sort(key=lambda x: x[0], reverse=True)
        
        print(f"   🎯 Приоритетное сканирование {len(devices_to_scan)} устройств")
        
        for i, (priority, device) in enumerate(devices_to_scan, 1):
            try:
                print(f"   🔍 [{i}/{len(devices_to_scan)}] Сканирование: {device['ip']} ({device['hostname']}) - приоритет: {priority}")
                
                # Определяем глубину сканирования на основе приоритета
                if priority >= 50:  # Высокий приоритет
                    scan_args = '-sS -O -A --min-rate 500 --host-timeout 30s --max-retries 2'
                    print(f"      🎯 Глубокое сканирование")
                elif priority >= 25:  # Средний приоритет
                    scan_args = '-sS -O --osscan-limit --max-retries 1 --host-timeout 20s'
                    print(f"      🔍 Стандартное сканирование")
                else:  # Низкий приоритет
                    scan_args = '-sS --max-retries 1 --host-timeout 10s'
                    print(f"      ⚡ Быстрое сканирование")
                
                # Выполняем сканирование
                self.nm.scan(hosts=device['ip'], arguments=scan_args)
                
                # ОБНОВЛЯЕМ информацию устройства
                self._update_device_info(device)
                device['scan_stage'] = 'detailed'
                successful_scans += 1
                
                # Пауза между сканированиями
                if i < len(devices_to_scan):
                    time.sleep(2)  # 2 секунды паузы
                
            except Exception as e:
                print(f"      ⚠️ Ошибка сканирования {device['ip']}: {e}")
        
        print(f"✅ Успешно просканировано: {successful_scans}/{len(devices_to_scan)} устройств")

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
            print(f"⚠️ Ошибка создания информации для {host}: {e}")
        
        return device_info

    def _get_hostname_fallback(self, ip):
        """Резервный метод определения hostname"""
        try:
            # Пробуем разные методы получения hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if hostname and hostname != ip:
                    return hostname
            except:
                pass
            
            return "Unknown"
        except:
            return "Unknown"

    def _update_device_info(self, device):
        """ОБНОВЛЯЕМ информацию устройства, а не заменяем его"""
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
            
            # Парсим модель из названия ОС
            os_name = os_match.get('name', '')
            if hardware_info['model'] == 'Unknown':
                hardware_info['model'] = self._extract_model_from_os(os_name, hardware_info['vendor'])
            
        except Exception as e:
            print(f"⚠️ Ошибка извлечения информации о железе: {e}")
        
        return hardware_info

    def _classify_hardware_type(self, hardware_info, device):
        """Классификация типа железа"""
        vendor = hardware_info['vendor'].lower()
        device_type = hardware_info['type'].lower()
        hostname = device['hostname'].lower()
        os_info = device['os'].lower()
        
        # Мобильные устройства
        if any(word in vendor for word in ['samsung', 'xiaomi', 'huawei', 'oneplus', 'google', 'motorola', 'oppo', 'vivo']):
            if 'phone' in device_type or 'mobile' in device_type or 'android' in os_info:
                return 'Smartphone'
            return 'Mobile Device'
        
        # Apple устройства
        elif 'apple' in vendor:
            if 'iphone' in hostname or 'ios' in os_info:
                return 'iPhone'
            elif 'ipad' in hostname:
                return 'iPad'
            elif 'mac' in hostname or 'macos' in os_info:
                return 'Mac Computer'
            return 'Apple Device'
        
        # Сетевые устройства
        elif any(word in vendor for word in ['cisco', 'tp-link', 'd-link', 'asus', 'netgear', 'mikrotik', 'ubiquiti', 'tenda']):
            if 'router' in hostname or 'gateway' in hostname:
                return 'Router'
            elif 'switch' in hostname:
                return 'Network Switch'
            elif 'access point' in hostname or 'ap' in hostname:
                return 'Access Point'
            return 'Network Device'
        
        return hardware_info['type'] if hardware_info['type'] != 'Unknown' else 'General Purpose Device'

    def _extract_model_from_os(self, os_name, vendor):
        """Извлечение модели из названия ОС"""
        os_name_lower = os_name.lower()
        vendor_lower = vendor.lower()
        
        # Для Android устройств
        if 'android' in os_name_lower:
            if 'samsung' in vendor_lower:
                return 'Samsung Phone/Tablet'
            elif 'xiaomi' in vendor_lower:
                return 'Xiaomi Phone'
            elif 'huawei' in vendor_lower:
                return 'Huawei Phone'
            elif 'google' in vendor_lower:
                return 'Google Pixel'
            return 'Android Device'
        
        # Для iOS устройств
        elif 'ios' in os_name_lower or 'iphone' in os_name_lower:
            return 'iPhone/iPad'
        
        return 'Unknown'

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
        elif 'huawei' in vendor_lower:
            existing_hardware['model'] = 'Huawei Device'
        
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
        
        # Предварительная классификация по hostname
        if 'android' in hostname:
            hardware_info['type'] = 'Smartphone'
        elif 'iphone' in hostname or 'ipad' in hostname:
            hardware_info['type'] = 'Apple Mobile'
        elif 'router' in hostname or 'gateway' in hostname:
            hardware_info['type'] = 'Router'
        
        # Предварительная классификация по vendor
        if any(word in vendor for word in ['samsung', 'xiaomi', 'huawei']):
            hardware_info['type'] = 'Smartphone'
        elif 'apple' in vendor:
            hardware_info['type'] = 'Apple Device'
        
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
        devices_by_os = {}
        
        for device in self.devices:
            device_type = device['hardware'].get('type', 'Unknown')
            devices_by_type[device_type] = devices_by_type.get(device_type, 0) + 1
            
            os_name = device['os'].split(' (')[0]
            devices_by_os[os_name] = devices_by_os.get(os_name, 0) + 1
        
        detailed_devices = len([d for d in self.devices if d['os'] != 'Unknown'])
        
        summary = f"🌐 Сеть: {self.network_info['network']}\n"
        summary += f"📊 Всего устройств: {len(self.devices)}\n"
        summary += f"🔍 Детально просканировано: {detailed_devices}\n\n"
        
        summary += "🛠️ Распределение по типам устройств:\n"
        for device_type, count in devices_by_type.items():
            summary += f"  • {device_type}: {count}\n"
        
        summary += "\n💻 Распределение по ОС:\n"
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
                details += f"🔍 Стадия сканирования: {device.get('scan_stage', 'basic')}\n\n"
                
                hardware = device['hardware']
                details += "🛠️ ИНФОРМАЦИЯ О ЖЕЛЕЗЕ:\n"
                details += f"• Тип: {hardware.get('type', 'Unknown')}\n"
                details += f"• Архитектура: {hardware.get('architecture', 'Unknown')}\n"
                details += f"• Производитель: {hardware.get('vendor', 'Unknown')}\n"
                details += f"• Модель: {hardware.get('model', 'Unknown')}\n"
                details += f"• Достоверность: {hardware.get('confidence', '0%')}\n\n"
                
                if device['ports']:
                    details += f"🔓 Открытые порты ({len(device['ports'])}):\n"
                    for port in device['ports']:
                        details += f"  • {port['port']}/tcp - {port['service']} ({port['version']})\n"
                else:
                    details += "🔒 Открытых портов не обнаружено\n"
                
                details += f"\n⏰ Последнее обнаружение: {device['last_seen']}"
                
                return details
        return f"❌ Устройство с IP {ip_address} не найдено"
