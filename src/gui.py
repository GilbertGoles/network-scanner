import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
from datetime import datetime

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Network Scanner v1.0")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2C3E50')
        
        # Импорты здесь чтобы избежать циклических зависимостей
        from scanner import NetworkScanner
        from visualizer import NetworkVisualizer
        
        self.scanner = NetworkScanner()
        self.visualizer = NetworkVisualizer()
        
        self.setup_ui()
        self.scan_in_progress = False
        
    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        # Стили
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#2C3E50')
        style.configure('TLabel', background='#2C3E50', foreground='white', font=('Arial', 10))
        style.configure('TButton', background='#34495E', foreground='white', font=('Arial', 10))
        style.configure('Treeview', background='#34495E', fieldbackground='#34495E', foreground='white')
        
        # Главный контейнер
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Заголовок
        header_label = ttk.Label(main_frame, text="🌐 Network Scanner - Анализатор WiFi сетей", 
                                font=('Arial', 16, 'bold'))
        header_label.pack(pady=(0, 15))
        
        # Панель управления
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.scan_btn = ttk.Button(control_frame, text="🔄 Сканировать сеть", 
                                  command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.map_btn = ttk.Button(control_frame, text="🗂️ Показать карту", 
                                 command=self.show_map, state=tk.DISABLED)
        self.map_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_btn = ttk.Button(control_frame, text="💾 Экспорт JSON", 
                                    command=self.export_results, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT)
        
        # Информация о сети
        info_frame = ttk.LabelFrame(main_frame, text="📊 Информация о сети")
        info_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.info_text = scrolledtext.ScrolledText(info_frame, height=6, 
                                                  bg='#34495E', fg='white',
                                                  font=('Consolas', 9),
                                                  insertbackground='white')
        self.info_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Устройства
        devices_frame = ttk.LabelFrame(main_frame, text="📱 Обнаруженные устройства")
        devices_frame.pack(fill=tk.BOTH, expand=True)
        
        # Таблица устройств
        columns = ('IP', 'MAC', 'Hostname', 'Vendor', 'OS', 'Status', 'Ports')
        self.devices_tree = ttk.Treeview(devices_frame, columns=columns, show='headings', height=15)
        
        # Настройка колонок
        column_widths = {'IP': 120, 'MAC': 150, 'Hostname': 150, 'Vendor': 150, 'OS': 120, 'Status': 80, 'Ports': 100}
        for col in columns:
            self.devices_tree.heading(col, text=col)
            self.devices_tree.column(col, width=column_widths.get(col, 100))
        
        # Скроллбар для таблицы
        tree_scroll = ttk.Scrollbar(devices_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Статус бар
        self.status_var = tk.StringVar(value="Готов к сканированию...")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, style='TLabel')
        status_bar.pack(fill=tk.X, pady=(10, 0))
        
    def start_scan(self):
        """Запуск сканирования в отдельном потоке"""
        if not self.scan_in_progress:
            self.scan_in_progress = True
            self.scan_btn.config(state=tk.DISABLED)
            self.map_btn.config(state=tk.DISABLED)
            self.export_btn.config(state=tk.DISABLED)
            
            threading.Thread(target=self._scan_thread, daemon=True).start()
    
    def _scan_thread(self):
        """Поток сканирования"""
        try:
            self._update_status("🔍 Определение сети...")
            self._update_info("🔍 Определение сети...\n")
            
            network_info = self.scanner.get_local_network()
            if network_info:
                info_str = f"""🌐 Информация о сети:
• 🖥️  Локальный IP: {network_info['local_ip']}
• 🚪 Шлюз: {network_info['gateway']}
• 🌐 Сеть: {network_info['network']}
• 🔌 Интерфейс: {network_info['interface']}

"""
                self._update_info(info_str)
                self._update_status("🔍 Сканирование устройств...")
                self._update_info("🔍 Сканирование устройств...\n")
                
                devices = self.scanner.scan_network()
                self._display_devices(devices)
                
                result_str = f"✅ Сканирование завершено! Найдено устройств: {len(devices)}\n"
                self._update_info(result_str)
                self._update_status("Готово")
                
                # Активируем кнопки
                self.map_btn.config(state=tk.NORMAL)
                self.export_btn.config(state=tk.NORMAL)
                
            else:
                self._update_info("❌ Не удалось определить сеть\n")
                self._update_status("Ошибка")
                
        except Exception as e:
            self._update_info(f"❌ Ошибка сканирования: {str(e)}\n")
            self._update_status("Ошибка")
        finally:
            self.scan_in_progress = False
            self.scan_btn.config(state=tk.NORMAL)
    
    def _display_devices(self, devices):
        """Отображение устройств в таблице"""
        # Очистка таблицы
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        # Заполнение данными
        for device in devices:
            ports_str = ", ".join([str(p['port']) for p in device['ports'][:3]])
            if len(device['ports']) > 3:
                ports_str += f" ...(+{len(device['ports'])-3})"
                
            self.devices_tree.insert('', tk.END, values=(
                device['ip'],
                device['mac'],
                device['hostname'],
                device['vendor'],
                device['os'],
                device['status'],
                ports_str
            ))
    
    def show_map(self):
        """Показать карту сети"""
        if hasattr(self.scanner, 'devices') and self.scanner.devices:
            try:
                import matplotlib.pyplot as plt
                fig = self.visualizer.create_network_map(
                    self.scanner.devices, 
                    self.scanner.network_info
                )
                plt.show()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось создать карту: {str(e)}")
        else:
            messagebox.showwarning("Внимание", "Сначала выполните сканирование сети")
    
    def export_results(self):
        """Экспорт результатов"""
        if hasattr(self.scanner, 'devices') and self.scanner.devices:
            filename = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.scanner.export_results(self.scanner.devices, filename)
            messagebox.showinfo("Успех", f"Результаты экспортированы в {filename}")
    
    def _update_info(self, text):
        """Обновление информационного текста"""
        self.root.after(0, lambda: self.info_text.insert(tk.END, text))
    
    def _update_status(self, text):
        """Обновление статус бара"""
        self.root.after(0, lambda: self.status_var.set(text))
