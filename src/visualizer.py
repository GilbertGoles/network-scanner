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
            'server': '#FF9FF3'
        }
    
    def create_network_map(self, devices, network_info):
        """Создание графовой карты сети в стиле Obsidian"""
        self.fig, self.ax = plt.subplots(figsize=(16, 12))
        self.ax.set_facecolor('#1E1E1E')
        self.fig.patch.set_facecolor('#1E1E1E')
        
        G = nx.Graph()
        positions = {}
        node_colors = []
        labels = {}
        
        # Роутер в центре
        router_id = f"Router\n{network_info.get('gateway', 'Unknown')}"
        G.add_node(router_id)
        positions[router_id] = (0, 0)
        node_colors.append(self.colors['router'])
        labels[router_id] = router_id
        
        # Распределяем устройства по кругу
        if devices:
            radius = 5
            angle_step = 2 * np.pi / len(devices)
            
            for i, device in enumerate(devices):
                device_id = f"{device['hostname']}\n{device['ip']}"
                G.add_node(device_id)
                
                angle = i * angle_step
                x = radius * np.cos(angle)
                y = radius * np.sin(angle)
                positions[device_id] = (x, y)
                
                # Классификация и цвет
                device_type = self._classify_device(device)
                node_colors.append(self.colors.get(device_type, self.colors['unknown']))
                labels[device_id] = device_id
                
                # Соединение с роутером
                G.add_edge(router_id, device_id)
        
        # Визуализация графа
        nx.draw_networkx_nodes(G, positions, node_size=3000,
                              node_color=node_colors, alpha=0.9,
                              edgecolors='white', linewidths=2)
        
        nx.draw_networkx_edges(G, positions, edge_color='#7F8C8D',
                              alpha=0.6, width=2, style='dashed')
        
        nx.draw_networkx_labels(G, positions, labels, font_size=8,
                               font_weight='bold', font_family='monospace',
                               bbox=dict(boxstyle="round,pad=0.3", facecolor="#2C3E50", 
                                       edgecolor='none', alpha=0.8))
        
        # Легенда
        self._create_legend()
        
        plt.title(f"🗂️ Карта сети: {network_info.get('network', 'Unknown')}",
                 color='white', fontsize=16, pad=20, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        
        return self.fig
    
    def _classify_device(self, device):
        """Классификация устройства по характеристикам"""
        hostname = device['hostname'].lower()
        vendor = device['vendor'].lower()
        os_info = device['os'].lower()
        
        if any(word in hostname for word in ['router', 'gateway', 'asus', 'tp-link']):
            return 'router'
        elif any(word in vendor for word in ['apple', 'samsung', 'xiaomi', 'huawei']):
            return 'phone'
        elif any(word in os_info for word in ['windows', 'linux', 'mac os', 'ubuntu']):
            return 'computer'
        elif any(word in hostname for word in ['raspberry', 'pi', 'arduino']):
            return 'iot'
        elif any(word in hostname for word in ['server', 'nas', 'storage']):
            return 'server'
        else:
            return 'unknown'
    
    def _create_legend(self):
        """Создание легенды"""
        legend_elements = []
        for device_type, color in self.colors.items():
            legend_elements.append(
                patches.Patch(color=color, label=device_type.capitalize())
            )
        
        self.ax.legend(handles=legend_elements, loc='upper left',
                      facecolor='#2C3E50', edgecolor='none',
                      labelcolor='white', fontsize=10)
