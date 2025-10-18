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
        """Улучшенное сканирование сети - устройства не теряются!"""
        if not network_range:
            if not self.network_info:
                self.get_local_network()
            network_range = self.network_info.get('network', '192.168.1.0/24')
        
        print(f"🔍 Сканирование: {network_range}")
        
        try:
            # ОЧИЩАЕМ старые устройства перед новым сканированием
            self.devices = []
            
            # ПЕРВАЯ СТАДИЯ: Только обнаружение устройств (быстро)
            print("🔍 Стадия 1: Обнаружение всех устройств в сети...")
            self.nm.scan(hosts=network_range, arguments='-sn --min-rate 1000')
            
            # СОХРАНЯЕМ все найденные устройства
            all_hosts = list(self.nm.all_hosts())
            print(f"✅ Найдено устройств на первой стадии: {len(all_hosts)}")
            
            for host in all_hosts:
                device_info = self._create_device_info(host)
                self.devices.append(device_info)
                print(f"   📍 {host} - {device_info['hostname']} ({device_info['mac']})")
            
            # ВТОРАЯ СТАДИЯ: Детальное сканирование ВСЕХ устройств
            if self.devices:
                print(f"🔍 Стадия 2: Детальное сканирование {len(self.devices)} устройств...")
                self._detailed_scan_all_devices()
            else:
                print("❌ Устройства не найдены")
            
            print(f"🎯 Итоговое количество устройств: {len(self.devices)}")
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
            'hardware': {
                'type': 'Unknown',
                'architecture': 'Unknown', 
                'vendor': 'Unknown',
                'model': 'Unknown',
                'confidence': '0%'
            },
            'ports': [],
            'last_seen': datetime.now().isoformat(),
            'scan_stage': 'basic'  # Отслеживаем на какой стадии просканировано
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
            device_info['hardware'] = self._enhance_hardware_info_from_vendor(device_info['vendor'], device_info['hardware'])
        elif device_info['mac'] != 'Unknown':
            device_info['vendor'] = f"MAC: {device_info['mac']}"
        
        # Получаем hostname
        if 'hostnames' in self.nm[host] and self.nm[host]['hostnames']:
            hostname = self.nm[host]['hostnames'][0]['name']
            device_info['hostname'] = hostname if hostname else self._get_hostname_fallback(host)
        
        # Предварительная классификация железа
        device_info['hardware'] = self._classify_hardware_from_basic_info(device_info)
        
        return device_info

    def _get_hostname_fallback(self, ip):
        """Резервный метод определения hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"

    def _detailed_scan_all_devices(self):
        """Детальное сканирование ВСЕХ устройств без исключений"""
        successful_scans = 0
        
        for i, device in enumerate(self.devices, 1):
            try:
                print(f"🔍 [{i}/{len(self.devices)}] Детальное сканирование: {device['ip']}")
                
                # Для приоритетных устройств - более тщательное сканирование
                if (device['ip'] == self.network_info.get('gateway') or 
                    device['ip'] == self.network_info.get('local_ip')):
                    print(f"   🎯 Приоритетное устройство: {device['ip']}")
                    self.nm.scan(hosts=device['ip'], 
                                arguments='-sS -O -A --min-rate 500 --host-timeout 60s')
                else:
                    # Для обычных устройств - быстрый скан
                    self.nm.scan(hosts=device['ip'], 
                                arguments='-sS -O --osscan-limit --max-retries 1 --host-timeout 30s')
                
                # ОБНОВЛЯЕМ информацию устройства, а не заменяем его
                self._update_device_info(device)
                device['scan_stage'] = 'detailed'
                successful_scans += 1
                
            except Exception as e:
                print(f"⚠️ Ошибка сканирования {device['ip']}: {e}")
                # Устройство остается в списке даже если сканирование не удалось
        
        print(f"✅ Успешно просканировано: {successful_scans}/{len(self.devices)} устройств")

    def _update_device_info(self, device):
        """ОБНОВЛЯЕМ информацию устройства, а не заменяем его"""
        host = device['ip']
        
        try:
            # Обновляем ОС если нашли
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                best_os = self.nm[host]['osmatch'][0]
                accuracy = best_os.get('accuracy', '0')
                device['os'] = f"{best_os['name']} (accuracy: {accuracy}%)"
                
                # Обновляем информацию о железе
                device['hardware'] = self._extract_hardware_info(best_os, device)
            
            # Обновляем hostname если нашли лучше
            if 'hostnames' in self.nm[host] and self.nm[host]['hostnames']:
                hostname = self.nm[host]['hostnames'][0]['name']
                if hostname and hostname != device['ip'] and hostname not in ['', 'localhost']:
                    device['hostname'] = hostname
            
            # Обновляем MAC и vendor если не нашли ранее
            if (device['mac'] == 'Unknown' or device['vendor'] == 'Unknown') and 'addresses' in self.nm[host]:
                for addr_type, addr_value in self.nm[host]['addresses'].items():
                    if addr_type == 'mac':
                        device['mac'] = addr_value
                        if 'vendor' in self.nm[host] and addr_value in self.nm[host]['vendor']:
                            device['vendor'] = self.nm[host]['vendor'][addr_value]
                            device['hardware'] = self._enhance_hardware_info_from_vendor(device['vendor'], device['hardware'])
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
            
            print(f"   ✅ Обновлено: {device['ip']} -> {device['hostname']} | {device['os']}")
            
        except Exception as e:
            print(f"   ⚠️ Ошибка обновления информации для {device['ip']}: {e}")

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
        
        # Компьютеры
        elif any(word in vendor for word in ['dell', 'hp', 'lenovo', 'asus', 'acer', 'msi', 'gigabyte']):
            if 'laptop' in hostname or 'notebook' in hostname:
                return 'Laptop'
            elif 'server' in hostname:
                return 'Server'
            return 'Desktop Computer'
        
        # IoT устройства
        elif any(word in vendor for word in ['raspberry', 'arduino', 'espressif']):
            return 'IoT Device'
        
        # Игровые консоли
        elif any(word in hostname for word in ['playstation', 'xbox', 'nintendo']):
            return 'Gaming Console'
        
        # Smart TV
        elif any(word in hostname for word in ['tv', 'smarttv', 'androidtv']):
            return 'Smart TV'
        
        # Принтеры
        elif any(word in vendor for word in ['canon', 'hp', 'epson', 'brother']):
            return 'Printer'
        
        # Серверы
        elif any(word in hostname for word in ['server', 'nas', 'storage', 'cloud']):
            return 'Server'
        
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
        
        # Для Windows
        elif 'windows' in os_name_lower:
            return 'Windows PC'
        
        # Для Linux
        elif 'linux' in os_name_lower:
            return 'Linux Device'
        
        return 'Unknown'

    def _enhance_hardware_info_from_vendor(self, vendor, existing_hardware):
        """Улучшение информации о железе на основе vendor"""
        if existing_hardware.get('vendor') == 'Unknown' and vendor != 'Unknown':
            existing_hardware['vendor'] = vendor
        
        # Дополнительная логика для определения моделей по MAC vendor
        vendor_lower = vendor.lower()
        
        if 'samsung' in vendor_lower:
            existing_hardware['model'] = 'Samsung Device'
        elif 'apple' in vendor_lower:
            existing_hardware['model'] = 'Apple Device'
        elif 'xiaomi' in vendor_lower:
            existing_hardware['model'] = 'Xiaomi Device'
        elif 'huawei' in vendor_lower:
            existing_hardware['model'] = 'Huawei Device'
        elif 'google' in vendor_lower:
            existing_hardware['model'] = 'Google Device'
        elif 'dell' in vendor_lower:
            existing_hardware['model'] = 'Dell Computer'
        elif 'hp' in vendor_lower:
            existing_hardware['model'] = 'HP Computer'
        elif 'lenovo' in vendor_lower:
            existing_hardware['model'] = 'Lenovo Computer'
        elif 'asus' in vendor_lower:
            existing_hardware['model'] = 'ASUS Device'
        
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
        elif 'raspberry' in hostname:
            hardware_info['type'] = 'IoT Device'
            hardware_info['model'] = 'Raspberry Pi'
        
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
            # Группируем по типу железа
            device_type = device['hardware'].get('type', 'Unknown')
            devices_by_type[device_type] = devices_by_type.get(device_type, 0) + 1
            
            # Группируем по ОС
            os_name = device['os'].split(' (')[0]  # Берем только название ОС
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
                
                # Информация о железе
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
