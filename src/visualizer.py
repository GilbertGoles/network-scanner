import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch
import numpy as np

class NetworkVisualizer:
    def __init__(self):
        self.fig = None
        self.ax = None
        self.colors = {
            'router': '#FF6B6B',
            'computer': '#4ECDC4', 
            'phone': '#45B7D1',
            'iot': '#96CEB4',
            'unknown': '#FECA57',
            'server': '#FF9FF3',
            'gateway': '#FF9FF3'
        }
    
    def create_network_map(self, devices, network_info):
        """Создание графовой карты сети в стиле Obsidian"""
        try:
            self.fig, self.ax = plt.subplots(figsize=(16, 12))
            self.ax.set_facecolor('#1E1E1E')
            self.fig.patch.set_facecolor('#1E1E1E')
            
            G = nx.Graph()
            positions = {}
            node_colors = []
            labels = {}
            node_sizes = []
            
            # Роутер/шлюз в центре
            gateway_ip = network_info.get('gateway', 'Unknown')
            local_ip = network_info.get('local_ip', 'Unknown')
            
            # Создаем центральный узел (роутер/шлюз)
            router_id = f"Router/Gateway\n{gateway_ip}"
            G.add_node(router_id)
            positions[router_id] = (0, 0)
            node_colors.append(self.colors['router'])
            labels[router_id] = router_id
            node_sizes.append(3500)  # Больший размер для роутера
            
            # Добавляем ВСЕ устройства, даже те что не прошли детальное сканирование
            connected_devices = 0
            total_devices = len(devices)
            
            for device in devices:
                # Создаем идентификатор устройства
                if device['hostname'] != 'Unknown':
                    device_id = f"{device['hostname']}\n{device['ip']}"
                else:
                    device_id = f"{device['ip']}"
                
                # Помечаем локальное устройство
                if device['ip'] == local_ip:
                    device_id = f"🖥️ {device_id}"
                
                G.add_node(device_id)
                
                # Распределяем по кругу или эллипсу для лучшего отображения
                if total_devices <= 8:
                    # Для малого количества устройств - равномерно по кругу
                    radius = 6
                    angle = (2 * np.pi * connected_devices) / max(total_devices, 1)
                    x = radius * np.cos(angle)
                    y = radius * np.sin(angle)
                else:
                    # Для большого количества - по эллипсу
                    radius_x = 8
                    radius_y = 5
                    angle = (2 * np.pi * connected_devices) / max(total_devices, 1)
                    x = radius_x * np.cos(angle)
                    y = radius_y * np.sin(angle)
                
                positions[device_id] = (x, y)
                
                # Определяем тип и цвет устройства
                device_type = self._classify_device(device)
                node_colors.append(self.colors.get(device_type, self.colors['unknown']))
                labels[device_id] = device_id
                
                # Размер узла зависит от типа устройства
                if device_type == 'router':
                    node_sizes.append(3000)
                elif device_type == 'server':
                    node_sizes.append(2800)
                elif device_type == 'computer':
                    node_sizes.append(2500)
                else:
                    node_sizes.append(2000)
                
                # Соединяем с роутером
                G.add_edge(router_id, device_id)
                connected_devices += 1
            
            # Визуализация графа
            all_nodes = list(G.nodes())
            all_positions = [positions[node] for node in all_nodes]
            
            # Рисуем узлы
            nx.draw_networkx_nodes(G, positions, 
                                 node_size=node_sizes,
                                 node_color=node_colors, 
                                 alpha=0.9,
                                 edgecolors='white', 
                                 linewidths=2,
                                 ax=self.ax)
            
            # Рисуем ребра
            nx.draw_networkx_edges(G, positions, 
                                 edge_color='#7F8C8D',
                                 alpha=0.6, 
                                 width=2, 
                                 style='dashed',
                                 ax=self.ax)
            
            # Рисуем подписи
            nx.draw_networkx_labels(G, positions, 
                                  labels, 
                                  font_size=8,
                                  font_weight='bold', 
                                  font_family='monospace',
                                  bbox=dict(boxstyle="round,pad=0.3", 
                                          facecolor="#2C3E50", 
                                          edgecolor='none', 
                                          alpha=0.8),
                                  ax=self.ax)
            
            # Легенда
            self._create_legend()
            
            # Статистика
            total_devices_count = len(devices)
            detailed_devices = len([d for d in devices if d['os'] != 'Unknown'])
            
            # Информационная панель
            info_text = f"🌐 Сеть: {network_info.get('network', 'Unknown')}\n"
            info_text += f"📊 Устройств: {total_devices_count}\n"
            info_text += f"🔍 Детально: {detailed_devices}\n"
            info_text += f"🚪 Шлюз: {gateway_ip}"
            
            # Добавляем информационную панель
            self.ax.text(0.02, 0.98, info_text, 
                        transform=self.ax.transAxes,
                        fontsize=10, 
                        color='white',
                        verticalalignment='top',
                        bbox=dict(boxstyle="round,pad=0.5", 
                                facecolor="#2C3E50", 
                                edgecolor='white', 
                                alpha=0.9))
            
            plt.title(f"🗂️ Карта сети",
                     color='white', fontsize=16, pad=20, fontweight='bold')
            plt.axis('off')
            plt.tight_layout()
            
            return self.fig
            
        except Exception as e:
            print(f"❌ Ошибка создания карты сети: {e}")
            # Создаем простую карту в случае ошибки
            return self._create_fallback_map(devices, network_info)
    
    def _classify_device(self, device):
        """Классификация устройства по характеристикам"""
        hostname = device['hostname'].lower()
        vendor = device['vendor'].lower()
        os_info = device['os'].lower()
        ip = device['ip']
        
        # Проверяем шлюз
        if (device['ip'] == self._get_gateway_ip() or 
            'gateway' in hostname or 
            '_gateway' in hostname):
            return 'gateway'
        
        # Проверяем роутер
        if any(word in hostname for word in ['router', 'gateway', 'asus', 'tp-link', 'd-link', 'netgear']):
            return 'router'
        elif any(word in vendor for word in ['cisco', 'ubiquiti', 'mikrotik']):
            return 'router'
        
        # Проверяем сервер
        if any(word in hostname for word in ['server', 'nas', 'storage', 'cloud']):
            return 'server'
        elif any(word in os_info for word in ['server', 'centos', 'ubuntu server', 'debian server']):
            return 'server'
        
        # Проверяем телефоны
        if any(word in hostname for word in ['android', 'iphone', 'mobile', 'samsung', 'xiaomi']):
            return 'phone'
        elif any(word in vendor for word in ['apple', 'samsung', 'xiaomi', 'huawei', 'oneplus']):
            return 'phone'
        
        # Проверяем компьютеры
        if any(word in os_info for word in ['windows', 'linux', 'mac os', 'ubuntu', 'debian', 'fedora']):
            return 'computer'
        elif any(word in hostname for word in ['pc', 'laptop', 'desktop', 'notebook']):
            return 'computer'
        
        # Проверяем IoT устройства
        if any(word in hostname for word in ['raspberry', 'pi', 'arduino', 'esp', 'iot', 'smart']):
            return 'iot'
        elif any(word in vendor for word in ['raspberry', 'arduino', 'espressif']):
            return 'iot'
        
        return 'unknown'
    
    def _get_gateway_ip(self):
        """Получение IP шлюза (заглушка, должна передаваться из scanner)"""
        return ""
    
    def _create_legend(self):
        """Создание легенды"""
        try:
            legend_elements = []
            legend_labels = []
            
            for device_type, color in self.colors.items():
                legend_elements.append(
                    patches.Patch(color=color, label=device_type.capitalize())
                )
                legend_labels.append(device_type.capitalize())
            
            self.ax.legend(handles=legend_elements, 
                          loc='upper right',
                          facecolor='#2C3E50', 
                          edgecolor='none',
                          labelcolor='white', 
                          fontsize=10,
                          title='Типы устройств',
                          title_fontproperties={'weight': 'bold'})
            
        except Exception as e:
            print(f"⚠️ Ошибка создания легенды: {e}")
    
    def _create_fallback_map(self, devices, network_info):
        """Создание резервной карты в случае ошибки"""
        try:
            self.fig, self.ax = plt.subplots(figsize=(12, 8))
            self.ax.set_facecolor('#1E1E1E')
            self.fig.patch.set_facecolor('#1E1E1E')
            
            # Простая текстовая карта
            info_text = "🗂️ Карта сети\n\n"
            info_text += f"🌐 Сеть: {network_info.get('network', 'Unknown')}\n"
            info_text += f"📊 Устройств: {len(devices)}\n\n"
            
            for i, device in enumerate(devices, 1):
                device_type = self._classify_device(device)
                color = self.colors.get(device_type, self.colors['unknown'])
                info_text += f"• {device['ip']} - {device['hostname']} ({device_type})\n"
            
            self.ax.text(0.5, 0.5, info_text, 
                        transform=self.ax.transAxes,
                        fontsize=12, 
                        color='white',
                        ha='center', 
                        va='center',
                        bbox=dict(boxstyle="round,pad=1", 
                                facecolor="#2C3E50", 
                                edgecolor='white'))
            
            plt.title("Карта сети (упрощенная версия)",
                     color='white', fontsize=14, pad=20)
            plt.axis('off')
            
            return self.fig
            
        except Exception as e:
            print(f"❌ Критическая ошибка создания карты: {e}")
            return None
    
    def save_map(self, filename="network_map.png"):
        """Сохранение карты в файл"""
        try:
            if self.fig:
                self.fig.savefig(filename, dpi=300, bbox_inches='tight', 
                               facecolor='#1E1E1E', edgecolor='none')
                print(f"✅ Карта сохранена как {filename}")
                return True
            else:
                print("❌ Нет активной карты для сохранения")
                return False
        except Exception as e:
            print(f"❌ Ошибка сохранения карты: {e}")
            return False
    
    def create_device_statistics(self, devices):
        """Создание статистики по устройствам"""
        stats = {
            'total': len(devices),
            'by_type': {},
            'by_os': {},
            'detailed_scan': 0
        }
        
        for device in devices:
            # Статистика по типам
            device_type = self._classify_device(device)
            stats['by_type'][device_type] = stats['by_type'].get(device_type, 0) + 1
            
            # Статистика по ОС
            os_name = device['os'].split(' (')[0]  # Берем только название ОС
            if os_name != 'Unknown':
                stats['by_os'][os_name] = stats['by_os'].get(os_name, 0) + 1
                stats['detailed_scan'] += 1
        
        return stats
    
    def print_statistics(self, devices):
        """Вывод статистики в консоль"""
        stats = self.create_device_statistics(devices)
        
        print("\n📊 СТАТИСТИКА СЕТИ")
        print("=" * 40)
        print(f"Всего устройств: {stats['total']}")
        print(f"Детально просканировано: {stats['detailed_scan']}")
        
        print("\n📱 По типам устройств:")
        for device_type, count in stats['by_type'].items():
            print(f"  • {device_type.capitalize()}: {count}")
        
        print("\n💻 По операционным системам:")
        for os_name, count in stats['by_os'].items():
            print(f"  • {os_name}: {count}")
        
        if not stats['by_os']:
            print("  • Информация об ОС недоступна")
