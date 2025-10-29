import matplotlib.pyplot as plt
import networkx as nx
from typing import Dict, Any, List
import time

class NetworkVisualizer:
    def __init__(self):
        self.fig = None
        self.ax = None
        self.graph = None
        
    def create_network_map(self, scan_results: Dict[str, Any]) -> plt.Figure:
        """Создание карты сети"""
        try:
            self.fig, self.ax = plt.subplots(figsize=(12, 8))
            self.graph = nx.Graph()
            
            hosts_data = scan_results.get('results', {})
            
            if not hosts_data:
                self._create_empty_plot()
                return self.fig
            
            # Добавляем узлы (хосты)
            for host, info in hosts_data.items():
                self._add_host_to_graph(host, info)
            
            # Создаем связи между хостами (упрощенно)
            self._create_network_connections(hosts_data)
            
            # Визуализируем граф
            self._visualize_network_graph()
            
            plt.title("Карта сети", fontsize=16, fontweight='bold')
            plt.tight_layout()
            
            return self.fig
            
        except Exception as e:
            print(f"❌ Ошибка создания карты сети: {e}")
            return self._create_error_plot(str(e))
    
    def _add_host_to_graph(self, host: str, host_info: Dict):
        """Добавление хоста в граф"""
        try:
            # Определяем тип устройства
            device_type = self._classify_device(host_info)
            node_color = self._get_device_color(device_type)
            node_size = self._get_device_size(device_type)
            
            # Добавляем узел
            self.graph.add_node(host, 
                              device_type=device_type,
                              hostname=host_info.get('hostname', ''),
                              os=host_info.get('os', []),
                              ports=len(host_info.get('ports', [])),
                              color=node_color,
                              size=node_size)
            
        except Exception as e:
            print(f"⚠️ Ошибка добавления хоста {host}: {e}")
    
    def _classify_device(self, host_info: Dict) -> str:
        """Классификация типа устройства"""
        open_ports = [p for p in host_info.get('ports', []) if p.get('state') == 'open']
        
        # Анализ портов для классификации
        port_services = [p.get('service', '').lower() for p in open_ports]
        
        # Веб-сервер
        if any(service in ['http', 'https', 'www'] for service in port_services):
            return 'web_server'
        
        # Файловый сервер
        if any(service in ['ftp', 'sftp', 'smb', 'nfs'] for service in port_services):
            return 'file_server'
        
        # Сервер баз данных
        if any(service in ['mysql', 'postgresql', 'mongodb', 'redis'] for service in port_services):
            return 'database'
        
        # Сетевые устройства
        if any(service in ['ssh', 'telnet'] for service in port_services) and len(open_ports) < 5:
            return 'network_device'
        
        # Рабочая станция
        if any(service in ['rdp', 'vnc'] for service in port_services):
            return 'workstation'
        
        return 'unknown'
    
    def _get_device_color(self, device_type: str) -> str:
        """Цвет для типа устройства"""
        colors = {
            'web_server': 'red',
            'file_server': 'blue', 
            'database': 'green',
            'network_device': 'orange',
            'workstation': 'purple',
            'unknown': 'gray'
        }
        return colors.get(device_type, 'gray')
    
    def _get_device_size(self, device_type: str) -> int:
        """Размер узла для типа устройства"""
        sizes = {
            'web_server': 800,
            'file_server': 700,
            'database': 600,
            'network_device': 500,
            'workstation': 400,
            'unknown': 300
        }
        return sizes.get(device_type, 300)
    
    def _create_network_connections(self, hosts_data: Dict):
        """Создание связей между хостами"""
        try:
            hosts = list(hosts_data.keys())
            
            # Упрощенная логика: связываем хосты с общими сервисами
            for i, host1 in enumerate(hosts):
                for host2 in hosts[i+1:]:
                    if self._should_connect(hosts_data[host1], hosts_data[host2]):
                        self.graph.add_edge(host1, host2, weight=1)
                        
        except Exception as e:
            print(f"⚠️ Ошибка создания связей: {e}")
    
    def _should_connect(self, host1_info: Dict, host2_info: Dict) -> bool:
        """Определение, нужно ли связывать хосты"""
        # Упрощенная логика связывания
        common_services = set()
        
        services1 = [p.get('service') for p in host1_info.get('ports', [])]
        services2 = [p.get('service') for p in host2_info.get('ports', [])]
        
        common_services = set(services1) & set(services2)
        return len(common_services) > 0
    
    def _visualize_network_graph(self):
        """Визуализация графа сети"""
        try:
            if len(self.graph.nodes) == 0:
                self._create_empty_plot()
                return
            
            # Позиционирование узлов
            pos = nx.spring_layout(self.graph, k=1, iterations=50)
            
            # Извлекаем атрибуты узлов
            node_colors = [self.graph.nodes[node]['color'] for node in self.graph.nodes()]
            node_sizes = [self.graph.nodes[node]['size'] for node in self.graph.nodes()]
            labels = {node: self._get_node_label(node) for node in self.graph.nodes()}
            
            # Рисуем граф
            nx.draw_networkx_nodes(self.graph, pos, 
                                 node_color=node_colors,
                                 node_size=node_sizes,
                                 alpha=0.8)
            
            nx.draw_networkx_edges(self.graph, pos, 
                                 alpha=0.5, 
                                 edge_color='gray',
                                 width=1)
            
            nx.draw_networkx_labels(self.graph, pos, labels, font_size=8)
            
            # Легенда
            self._add_legend()
            
        except Exception as e:
            print(f"❌ Ошибка визуализации графа: {e}")
    
    def _get_node_label(self, node: str) -> str:
        """Получение метки для узла"""
        node_data = self.graph.nodes[node]
        hostname = node_data.get('hostname', '')
        
        if hostname:
            # Сокращаем длинные hostname
            if len(hostname) > 15:
                hostname = hostname[:12] + '...'
            return f"{node}\n{hostname}"
        
        return node
    
    def _add_legend(self):
        """Добавление легенды"""
        device_types = ['web_server', 'file_server', 'database', 'network_device', 'workstation', 'unknown']
        colors = [self._get_device_color(t) for t in device_types]
        labels = ['Веб-сервер', 'Файловый сервер', 'База данных', 'Сетевое устройство', 'Рабочая станция', 'Неизвестно']
        
        legend_elements = []
        for color, label in zip(colors, labels):
            legend_elements.append(plt.Line2D([0], [0], marker='o', color='w', 
                                            markerfacecolor=color, markersize=8, label=label))
        
        self.ax.legend(handles=legend_elements, loc='upper right', fontsize=8)
    
    def _create_empty_plot(self):
        """Создание пустого графика"""
        self.ax.text(0.5, 0.5, 'Нет данных для визуализации', 
                    ha='center', va='center', transform=self.ax.transAxes, fontsize=12)
        self.ax.set_xlim(0, 1)
        self.ax.set_ylim(0, 1)
    
    def _create_error_plot(self, error_msg: str):
        """Создание графика с ошибкой"""
        self.fig, self.ax = plt.subplots(figsize=(10, 6))
        self.ax.text(0.5, 0.5, f'Ошибка визуализации:\n{error_msg}', 
                    ha='center', va='center', transform=self.ax.transAxes, fontsize=10)
        self.ax.set_xlim(0, 1)
        self.ax.set_ylim(0, 1)
        return self.fig
    
    def create_vulnerability_chart(self, vulnerability_results: Dict[str, Any]) -> plt.Figure:
        """Создание диаграммы уязвимостей"""
        try:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            summary = vulnerability_results.get('summary', {})
            vulnerabilities = vulnerability_results.get('vulnerabilities', [])
            
            if not vulnerabilities:
                ax1.text(0.5, 0.5, 'Нет данных об уязвимостях', 
                        ha='center', va='center', transform=ax1.transAxes)
                ax2.text(0.5, 0.5, 'Нет данных об уязвимостях', 
                        ha='center', va='center', transform=ax2.transAxes)
                return fig
            
            # Диаграмма распределения по severity
            severity_data = summary.get('severity_distribution', {})
            self._create_severity_chart(ax1, severity_data)
            
            # Диаграмма распределения по сервисам
            service_data = summary.get('service_distribution', {})
            self._create_service_chart(ax2, service_data)
            
            plt.tight_layout()
            return fig
            
        except Exception as e:
            print(f"❌ Ошибка создания диаграммы уязвимостей: {e}")
            return self._create_error_plot(str(e))
    
    def _create_severity_chart(self, ax, severity_data: Dict):
        """Создание диаграммы распределения по severity"""
        try:
            labels = []
            sizes = []
            colors = []
            
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
            color_map = {
                'CRITICAL': 'red',
                'HIGH': 'orange', 
                'MEDIUM': 'yellow',
                'LOW': 'green',
                'UNKNOWN': 'gray'
            }
            
            for severity in severity_order:
                if severity in severity_data and severity_data[severity] > 0:
                    labels.append(f"{severity}\n({severity_data[severity]})")
                    sizes.append(severity_data[severity])
                    colors.append(color_map.get(severity, 'gray'))
            
            if sizes:
                ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                ax.set_title('Распределение уязвимостей по критичности', fontweight='bold')
            else:
                ax.text(0.5, 0.5, 'Нет данных', ha='center', va='center', transform=ax.transAxes)
                
        except Exception as e:
            print(f"⚠️ Ошибка создания диаграммы severity: {e}")
    
    def _create_service_chart(self, ax, service_data: Dict):
        """Создание диаграммы распределения по сервисам"""
        try:
            if not service_data:
                ax.text(0.5, 0.5, 'Нет данных', ha='center', va='center', transform=ax.transAxes)
                return
            
            # Сортируем сервисы по количеству уязвимостей
            sorted_services = sorted(service_data.items(), key=lambda x: x[1], reverse=True)[:10]
            
            services = [s[0] if s[0] != 'unknown' else 'Неизвестно' for s in sorted_services]
            counts = [s[1] for s in sorted_services]
            
            bars = ax.bar(services, counts, color='skyblue', alpha=0.7)
            ax.set_title('Топ уязвимостей по сервисам', fontweight='bold')
            ax.set_ylabel('Количество уязвимостей')
            
            # Поворачиваем подписи
            plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
            
            # Добавляем значения на столбцы
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom')
                
        except Exception as e:
            print(f"⚠️ Ошибка создания диаграммы сервисов: {e}")
    
    def create_scan_progress_chart(self, scan_results: Dict[str, Any]) -> plt.Figure:
        """Создание диаграммы прогресса сканирования"""
        try:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
            
            summary = scan_results.get('summary', {})
            
            # Диаграмма распределения ОС
            os_data = summary.get('os_distribution', {})
            self._create_os_chart(ax1, os_data)
            
            # Диаграмма распределения сервисов
            service_data = summary.get('services', {})
            self._create_scan_service_chart(ax2, service_data)
            
            plt.tight_layout()
            return fig
            
        except Exception as e:
            print(f"❌ Ошибка создания диаграммы прогресса: {e}")
            return self._create_error_plot(str(e))
    
    def _create_os_chart(self, ax, os_data: Dict):
        """Создание диаграммы распределения ОС"""
        try:
            if not os_data:
                ax.text(0.5, 0.5, 'Нет данных об ОС', 
                       ha='center', va='center', transform=ax.transAxes)
                return
            
            # Берем топ-5 ОС
            sorted_os = sorted(os_data.items(), key=lambda x: x[1], reverse=True)[:5]
            
            os_names = [os[0] for os in sorted_os]
            counts = [os[1] for os in sorted_os]
            
            bars = ax.bar(os_names, counts, color='lightgreen', alpha=0.7)
            ax.set_title('Распределение операционных систем', fontweight='bold')
            ax.set_ylabel('Количество хостов')
            
            plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
            
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom')
                
        except Exception as e:
            print(f"⚠️ Ошибка создания диаграммы ОС: {e}")
    
    def _create_scan_service_chart(self, ax, service_data: Dict):
        """Создание диаграммы сервисов для сканирования"""
        try:
            if not service_data:
                ax.text(0.5, 0.5, 'Нет данных о сервисах', 
                       ha='center', va='center', transform=ax.transAxes)
                return
            
            # Топ-10 сервисов
            sorted_services = sorted(service_data.items(), key=lambda x: x[1], reverse=True)[:10]
            
            services = [s[0] for s in sorted_services]
            counts = [s[1] for s in sorted_services]
            
            bars = ax.bar(services, counts, color='lightcoral', alpha=0.7)
            ax.set_title('Распределение сетевых сервисов', fontweight='bold')
            ax.set_ylabel('Количество')
            
            plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
            
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom')
                
        except Exception as e:
            print(f"⚠️ Ошибка создания диаграммы сервисов: {e}")
    
    def save_plot(self, fig: plt.Figure, filename: str):
        """Сохранение графика в файл"""
        try:
            fig.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"💾 График сохранен: {filename}")
        except Exception as e:
            print(f"❌ Ошибка сохранения графика: {e}")


# Тестирование модуля
if __name__ == "__main__":
    def test_visualizer():
        """Тестирование NetworkVisualizer"""
        print("🧪 Тестирование NetworkVisualizer...")
        
        visualizer = NetworkVisualizer()
        
        # Тестовые данные
        test_scan_results = {
            'results': {
                '192.168.1.1': {
                    'hostname': 'router.local',
                    'state': 'up',
                    'ports': [
                        {'port': 80, 'state': 'open', 'service': 'http'},
                        {'port': 22, 'state': 'open', 'service': 'ssh'},
                        {'port': 53, 'state': 'open', 'service': 'domain'}
                    ],
                    'os': [{'name': 'Linux 3.2', 'accuracy': 95}]
                },
                '192.168.1.100': {
                    'hostname': 'webserver.local',
                    'state': 'up', 
                    'ports': [
                        {'port': 80, 'state': 'open', 'service': 'http'},
                        {'port': 443, 'state': 'open', 'service': 'https'},
                        {'port': 22, 'state': 'open', 'service': 'ssh'}
                    ],
                    'os': [{'name': 'Ubuntu Linux', 'accuracy': 90}]
                },
                '192.168.1.150': {
                    'hostname': 'fileserver.local',
                    'state': 'up',
                    'ports': [
                        {'port': 21, 'state': 'open', 'service': 'ftp'},
                        {'port': 445, 'state': 'open', 'service': 'microsoft-ds'},
                        {'port': 139, 'state': 'open', 'service': 'netbios-ssn'}
                    ],
                    'os': [{'name': 'Windows 10', 'accuracy': 85}]
                }
            },
            'summary': {
                'total_hosts': 3,
                'open_ports': 9,
                'services': {'http': 2, 'ssh': 2, 'https': 1, 'ftp': 1, 'microsoft-ds': 1, 'netbios-ssn': 1, 'domain': 1},
                'os_distribution': {'Linux': 2, 'Windows': 1}
            }
        }
        
        test_vuln_results = {
            'vulnerabilities': [
                {
                    'host': '192.168.1.1',
                    'service': 'http',
                    'vulnerability_id': 'CVE-2021-41773',
                    'severity': 'HIGH',
                    'cvss_score': 7.5
                },
                {
                    'host': '192.168.1.100', 
                    'service': 'ssh',
                    'vulnerability_id': 'CVE-2016-6515',
                    'severity': 'MEDIUM',
                    'cvss_score': 5.0
                },
                {
                    'host': '192.168.1.150',
                    'service': 'ftp',
                    'vulnerability_id': 'CVE-2011-2523', 
                    'severity': 'CRITICAL',
                    'cvss_score': 9.3
                }
            ],
            'summary': {
                'total_vulnerabilities': 3,
                'severity_distribution': {'CRITICAL': 1, 'HIGH': 1, 'MEDIUM': 1},
                'service_distribution': {'http': 1, 'ssh': 1, 'ftp': 1}
            }
        }
        
        print("\n🗺️ Тест создания карты сети...")
        network_fig = visualizer.create_network_map(test_scan_results)
        if network_fig:
            print("✅ Карта сети создана успешно")
        
        print("\n📊 Тест создания диаграммы уязвимостей...")
        vuln_fig = visualizer.create_vulnerability_chart(test_vuln_results)
        if vuln_fig:
            print("✅ Диаграмма уязвимостей создана успешно")
        
        print("\n📈 Тест создания диаграммы прогресса...")
        progress_fig = visualizer.create_scan_progress_chart(test_scan_results)
        if progress_fig:
            print("✅ Диаграмма прогресса создана успешно")
        
        # Сохранение тестовых графиков
        try:
            visualizer.save_plot(network_fig, "test_network_map.png")
            visualizer.save_plot(vuln_fig, "test_vulnerability_chart.png")
            visualizer.save_plot(progress_fig, "test_progress_chart.png")
        except Exception as e:
            print(f"⚠️ Ошибка сохранения графиков: {e}")
        
        print("\n✅ Тестирование завершено!")
        print("📁 Тестовые графики сохранены в текущей директории")

    # Запуск тестов
    test_visualizer()
