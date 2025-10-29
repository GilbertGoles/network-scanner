import nmap
import socket
import netifaces
import threading
import time
import ipaddress
from typing import List, Dict, Any, Optional

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = {}
        self.scan_progress = {
            'current': 0,
            'total': 0,
            'stage': '',
            'active': False
        }
        self.current_scan_thread = None
        self.stop_scan_flag = False
        
    def get_local_network(self) -> str:
        """Определение локальной сети"""
        try:
            # Получаем сетевые интерфейсы
            interfaces = netifaces.interfaces()
            
            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        netmask = addr_info.get('netmask', '255.255.255.0')
                        
                        # Пропускаем localhost и docker сети
                        if ip.startswith('127.') or ip.startswith('172.17.'):
                            continue
                            
                        if ip != '127.0.0.1':
                            # Конвертируем в CIDR
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            return str(network)
            
            # Fallback
            return "192.168.1.0/24"
            
        except Exception as e:
            print(f"❌ Ошибка определения сети: {e}")
            return "192.168.1.0/24"
    
    def scan_network(self, target: str = None, ports: str = "1-1000", 
                    scan_type: str = "syn", timeout: int = 300) -> Dict[str, Any]:
        """Сканирование сети"""
        if self.scan_progress['active']:
            return {'error': 'Сканирование уже выполняется'}
        
        if not target:
            target = self.get_local_network()
        
        self.scan_progress.update({
            'current': 0,
            'total': 100,
            'stage': 'Подготовка сканирования',
            'active': True
        })
        
        self.stop_scan_flag = False
        self.scan_results = {}
        
        # Запускаем в отдельном потоке
        self.current_scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(target, ports, scan_type, timeout)
        )
        self.current_scan_thread.daemon = True
        self.current_scan_thread.start()
        
        return {'status': 'started', 'target': target}
    
    def _perform_scan(self, target: str, ports: str, scan_type: str, timeout: int):
        """Выполнение сканирования"""
        try:
            print(f"🎯 Начало сканирования: {target}, порты: {ports}")
            
            # Определяем аргументы nmap
            arguments = self._get_nmap_arguments(scan_type, timeout)
            
            self.scan_progress['stage'] = f'Сканирование {target}'
            
            # Выполняем сканирование
            scan_result = self.nm.scan(
                hosts=target, 
                ports=ports, 
                arguments=arguments,
                timeout=timeout
            )
            
            if self.stop_scan_flag:
                self.scan_progress.update({'active': False, 'stage': 'Отменено'})
                return
            
            # Обрабатываем результаты
            self._process_scan_results(scan_result)
            
            self.scan_progress.update({
                'current': 100,
                'stage': 'Сканирование завершено',
                'active': False
            })
            
            print(f"✅ Сканирование завершено. Найдено хостов: {len(self.scan_results)}")
            
        except Exception as e:
            print(f"❌ Ошибка сканирования: {e}")
            self.scan_progress.update({
                'stage': f'Ошибка: {str(e)}',
                'active': False
            })
    
    def _get_nmap_arguments(self, scan_type: str, timeout: int) -> str:
        """Генерация аргументов nmap"""
        base_args = f"-T4 --host-timeout {timeout}s"
        
        scan_args = {
            "syn": "-sS",
            "connect": "-sT", 
            "udp": "-sU",
            "aggressive": "-A",
            "quick": "-F",
            "comprehensive": "-sS -sV -sC -O"
        }
        
        return f"{base_args} {scan_args.get(scan_type, '-sS')}"
    
    def _process_scan_results(self, scan_result: Dict):
        """Обработка результатов сканирования"""
        try:
            scan_stats = scan_result.get('nmap', {}).get('scanstats', {})
            print(f"📊 Статистика сканирования: {scan_stats}")
            
            for host, host_data in scan_result.get('scan', {}).items():
                if self.stop_scan_flag:
                    break
                    
                host_info = {
                    'hostname': host_data.get('hostnames', [{}])[0].get('name', ''),
                    'state': host_data.get('status', {}).get('state', 'unknown'),
                    'ports': [],
                    'os': {},
                    'vendor': {},
                    'extra_info': {}
                }
                
                # Информация об ОС
                if 'osmatch' in host_data:
                    host_info['os'] = host_data['osmatch']
                
                # MAC адрес и вендор
                if 'addresses' in host_data:
                    host_info['mac'] = host_data['addresses'].get('mac', '')
                    if 'vendor' in host_data and host_info['mac']:
                        host_info['vendor'] = host_data['vendor'].get(host_info['mac'], '')
                
                # Портовая информация
                for port, port_data in host_data.get('tcp', {}).items():
                    service_info = {
                        'port': port,
                        'state': port_data.get('state', ''),
                        'service': port_data.get('name', ''),
                        'version': port_data.get('version', ''),
                        'product': port_data.get('product', ''),
                        'extra_info': port_data.get('extrainfo', ''),
                        'cpe': port_data.get('cpe', '')
                    }
                    host_info['ports'].append(service_info)
                
                # UDP порты
                for port, port_data in host_data.get('udp', {}).items():
                    service_info = {
                        'port': port,
                        'state': port_data.get('state', ''),
                        'service': port_data.get('name', ''),
                        'version': port_data.get('version', ''),
                        'product': port_data.get('product', ''),
                        'extra_info': port_data.get('extrainfo', ''),
                        'cpe': port_data.get('cpe', ''),
                        'protocol': 'udp'
                    }
                    host_info['ports'].append(service_info)
                
                self.scan_results[host] = host_info
            
        except Exception as e:
            print(f"❌ Ошибка обработки результатов: {e}")
    
    def stop_scan(self):
        """Остановка сканирования"""
        if self.scan_progress['active']:
            self.stop_scan_flag = True
            self.scan_progress['stage'] = 'Остановка...'
            print("⏹️ Остановка сканирования...")
    
    def get_scan_results(self) -> Dict[str, Any]:
        """Получение результатов сканирования"""
        return {
            'results': self.scan_results,
            'progress': self.scan_progress,
            'summary': self._generate_summary()
        }
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Генерация сводки сканирования"""
        total_hosts = len(self.scan_results)
        open_ports = 0
        services = {}
        os_types = {}
        
        for host, info in self.scan_results.items():
            # Подсчет открытых портов
            open_ports += len([p for p in info['ports'] if p.get('state') == 'open'])
            
            # Статистика сервисов
            for port in info['ports']:
                if port.get('state') == 'open':
                    service = port.get('service', 'unknown')
                    services[service] = services.get(service, 0) + 1
            
            # Статистика ОС
            if info.get('os'):
                for os_match in info['os']:
                    os_name = os_match.get('name', 'Unknown')
                    os_types[os_name] = os_types.get(os_name, 0) + 1
        
        return {
            'total_hosts': total_hosts,
            'open_ports': open_ports,
            'services': services,
            'os_distribution': os_types,
            'scan_timestamp': time.time()
        }
    
    def quick_scan(self, target: str = None) -> Dict[str, Any]:
        """Быстрое сканирование"""
        return self.scan_network(target, ports="21-23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080", scan_type="quick")
    
    def comprehensive_scan(self, target: str = None) -> Dict[str, Any]:
        """Полное сканирование"""
        return self.scan_network(target, ports="1-65535", scan_type="comprehensive")
    
    def service_scan(self, target: str, service_ports: List[int]) -> Dict[str, Any]:
        """Сканирование конкретных сервисов"""
        ports = ",".join(map(str, service_ports))
        return self.scan_network(target, ports=ports, scan_type="aggressive")
    
    def get_host_details(self, host: str) -> Dict[str, Any]:
        """Получение детальной информации о хосте"""
        return self.scan_results.get(host, {})
    
    def export_results(self, format_type: str = "json") -> str:
        """Экспорт результатов"""
        import json
        
        if format_type == "json":
            return json.dumps(self.scan_results, indent=2, ensure_ascii=False)
        else:
            return str(self.scan_results)


# Тестирование модуля
if __name__ == "__main__":
    def test_scanner():
        """Тестирование NetworkScanner"""
        print("🧪 Тестирование NetworkScanner...")
        
        scanner = NetworkScanner()
        
        # Тест определения сети
        print("\n🌐 Тест определения сети:")
        network = scanner.get_local_network()
        print(f"   Локальная сеть: {network}")
        
        # Тест быстрого сканирования
        print("\n🔍 Тест быстрого сканирования (localhost):")
        result = scanner.quick_scan("127.0.0.1")
        print(f"   Статус: {result.get('status')}")
        
        # Ожидаем завершения сканирования
        while scanner.scan_progress['active']:
            time.sleep(1)
            progress = scanner.scan_progress
            print(f"   Прогресс: {progress['current']}% - {progress['stage']}")
        
        # Получаем результаты
        results = scanner.get_scan_results()
        summary = results.get('summary', {})
        
        print(f"\n📊 Результаты сканирования:")
        print(f"   Хостов: {summary.get('total_hosts', 0)}")
        print(f"   Открытых портов: {summary.get('open_ports', 0)}")
        print(f"   Сервисов: {len(summary.get('services', {}))}")
        
        # Показываем найденные сервисы
        services = summary.get('services', {})
        if services:
            print("   🛠️ Обнаруженные сервисы:")
            for service, count in list(services.items())[:5]:
                print(f"     - {service}: {count}")
        
        print("\n✅ Тестирование завершено!")

    # Запуск тестов
    test_scanner()
