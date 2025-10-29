import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from typing import List, Dict, Any

class NetworkVisualizer:
    def __init__(self):
        self.colors = {
            'router': '#FF6B6B',
            'server': '#4ECDC4',
            'computer': '#45B7D1', 
            'phone': '#96CEB4',
            'printer': '#FECA57',
            'iot': '#FF9FF3',
            'unknown': '#BDC3C7'
        }
    
    def create_network_map(self, devices: List[Dict[str, Any]], network_info: Dict[str, Any]):
        """Создание карты сети"""
        try:
            fig, ax = plt.subplots(figsize=(14, 10))
            ax.set_facecolor('#1E1E1E')
            fig.patch.set_facecolor('#1E1E1E')
            
            G = nx.Graph()
            positions = {}
            node_colors = []
            node_sizes = []
            labels = {}
            
            # Центральный узел - шлюз
            gateway_ip = network_info.get('gateway', 'Unknown')
            gateway_id = f"Router\n{gateway_ip}"
            
            G.add_node(gateway_id)
            positions[gateway_id] = (0, 0)
            node_colors.append(self.colors['router'])
            node_sizes.append(3000)
            labels[gateway_id] = gateway_id
            
            # Добавляем устройства
            for i, device in enumerate(devices):
                device_type = device['hardware']['type'].lower()
                if 'router' in device_type:
                    device_color = self.colors['router']
                elif 'server' in device_type:
                    device_color = self.colors['server'] 
                elif 'phone' in device_type:
                    device_color = self.colors['phone']
                elif 'printer' in device_type:
                    device_color = self.colors['printer']
                elif 'iot' in device_type:
                    device_color = self.colors['iot']
                else:
                    device_color = self.colors['computer']
                
                device_id = f"{device['hostname']}\n{device['ip']}"
                G.add_node(device_id)
                
                # Распределение по кругу
                angle = 2 * np.pi * i / len(devices)
                radius = 8
                x = radius * np.cos(angle)
                y = radius * np.sin(angle)
                
                positions[device_id] = (x, y)
                node_colors.append(device_color)
                node_sizes.append(2000)
                labels[device_id] = device_id
                
                # Соединяем с шлюзом
                G.add_edge(gateway_id, device_id)
            
            # Визуализация
            nx.draw_networkx_nodes(G, positions, node_size=node_sizes, 
                                 node_color=node_colors, alpha=0.9,
                                 edgecolors='white', linewidths=2, ax=ax)
            
            nx.draw_networkx_edges(G, positions, edge_color='#7F8C8D',
                                 alpha=0.6, width=2, style='dashed', ax=ax)
            
            nx.draw_networkx_labels(G, positions, labels, font_size=8,
                                  font_weight='bold', font_family='monospace',
                                  bbox=dict(boxstyle="round,pad=0.3", facecolor="#2C3E50", 
                                          edgecolor='none', alpha=0.8), ax=ax)
            
            # Легенда
            self._create_legend(ax)
            
            # Информация
            info_text = f"Устройств: {len(devices)}\nСеть: {network_info.get('network', 'Unknown')}"
            ax.text(0.02, 0.98, info_text, transform=ax.transAxes, fontsize=10,
                   color='white', bbox=dict(boxstyle="round,pad=0.5", facecolor="#2C3E50"))
            
            plt.title("Карта сети", color='white', fontsize=16, pad=20)
            plt.axis('off')
            plt.tight_layout()
            
            return fig
            
        except Exception as e:
            print(f"❌ Ошибка создания карты: {e}")
            return self._create_simple_map(devices, network_info)
    
    def _create_legend(self, ax):
        """Создание легенды"""
        from matplotlib.patches import Patch
        
        legend_elements = [
            Patch(color=self.colors['router'], label='Роутеры'),
            Patch(color=self.colors['server'], label='Серверы'),
            Patch(color=self.colors['computer'], label='Компьютеры'),
            Patch(color=self.colors['phone'], label='Телефоны'),
            Patch(color=self.colors['printer'], label='Принтеры'),
            Patch(color=self.colors['iot'], label='IoT устройства'),
        ]
        
        ax.legend(handles=legend_elements, loc='upper right',
                 facecolor='#2C3E50', edgecolor='none',
                 labelcolor='white', fontsize=9)
    
    def _create_simple_map(self, devices: List[Dict[str, Any]], network_info: Dict[str, Any]):
        """Простая текстовая карта"""
        fig, ax = plt.subplots(figsize=(10, 8))
        ax.set_facecolor('#1E1E1E')
        fig.patch.set_facecolor('#1E1E1E')
        
        text_content = "🌐 КАРТА СЕТИ\n\n"
        text_content += f"Сеть: {network_info.get('network', 'Unknown')}\n"
        text_content += f"Устройств: {len(devices)}\n\n"
        
        for device in devices:
            text_content += f"• {device['ip']} - {device['hostname']}\n"
            text_content += f"  Тип: {device['hardware']['type']}\n"
            if device['ports']:
                ports = ', '.join([str(p['port']) for p in device['ports'][:3]])
                text_content += f"  Порты: {ports}\n"
            text_content += "\n"
        
        ax.text(0.5, 0.5, text_content, transform=ax.transAxes,
               fontsize=10, color='white', ha='center', va='center',
               bbox=dict(boxstyle="round,pad=1", facecolor="#2C3E50"))
        
        plt.axis('off')
        return fig
