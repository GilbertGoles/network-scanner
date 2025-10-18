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
        
        # Инициализация сканера уязвимостей (опционально)
        self.vuln_scanner = None
        try:
            from vulnerability_scanner import VulnerabilityScanner
            self.vuln_scanner = VulnerabilityScanner()
        except ImportError:
            print("⚠️ Сканер уязвимостей не доступен")
        
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
        style.configure('Treeview.Heading', background='#2C3E50', foreground='white')
        
        # Главный контейнер
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Заголовок
        header_label = ttk.Label(main_frame, text="🌐 Network Scanner - Анализатор WiFi сетей", 
                                font=('Arial', 16, 'bold'))
        header_label.pack(pady=(0, 15))
        
        # Панель управления
        self.control_frame = ttk.Frame(main_frame)
        self.control_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.scan_btn = ttk.Button(self.control_frame, text="🔄 Сканировать сеть", 
                                  command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.map_btn = ttk.Button(self.control_frame, text="🗂️ Показать карту", 
                                 command=self.show_map, state=tk.DISABLED)
        self.map_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_btn = ttk.Button(self.control_frame, text="💾 Экспорт JSON", 
                                    command=self.export_results, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Кнопка сканирования уязвимостей (если сканер доступен)
        if self.vuln_scanner:
            self.vuln_btn = ttk.Button(self.control_frame, text="🛡️ Сканировать уязвимости", 
                                      command=self.scan_vulnerabilities, state=tk.DISABLED)
            self.vuln_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Информация о сети
        info_frame = ttk.LabelFrame(main_frame, text="📊 Информация о сети")
        info_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.info_text = scrolledtext.ScrolledText(info_frame, height=6, 
                                                  bg='#34495E', fg='white',
                                                  font=('Consolas', 9),
                                                  insertbackground='white')
        self.info_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Создаем Notebook для вкладок
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Вкладка устройств
        devices_frame = ttk.Frame(self.notebook)
        self.notebook.add(devices_frame, text="📱 Устройства")
        
        # Таблица устройств
        columns = ('IP', 'MAC', 'Hostname', 'Vendor', 'OS', 'Hardware', 'Status', 'Ports')
        self.devices_tree = ttk.Treeview(devices_frame, columns=columns, show='headings', height=15)
        
        # Настройка колонок
        column_widths = {'IP': 120, 'MAC': 150, 'Hostname': 150, 'Vendor': 150, 'OS': 200, 'Hardware': 150, 'Status': 80, 'Ports': 100}
        for col in columns:
            self.devices_tree.heading(col, text=col)
            self.devices_tree.column(col, width=column_widths.get(col, 100))
        
        # Скроллбар для таблицы
        tree_scroll = ttk.Scrollbar(devices_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Контекстное меню для таблицы
        self.context_menu = tk.Menu(self.devices_tree, tearoff=0)
        self.context_menu.add_command(label="📋 Копировать IP", command=self.copy_ip)
        self.context_menu.add_command(label="🔍 Детали устройства", command=self.show_device_details)
        self.devices_tree.bind("<Button-3>", self.show_context_menu)
        
        # Вкладка уязвимостей (если сканер доступен)
        if self.vuln_scanner:
            self.vuln_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.vuln_frame, text="🛡️ Уязвимости")
            
            # Текстовая область для уязвимостей
            self.vuln_text = scrolledtext.ScrolledText(self.vuln_frame, 
                                                      bg='#34495E', fg='white',
                                                      font=('Consolas', 9),
                                                      insertbackground='white')
            self.vuln_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Статус бар
        self.status_var = tk.StringVar(value="Готов к сканированию...")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, style='TLabel')
        status_bar.pack(fill=tk.X, pady=(10, 0))
        
    def start_scan(self):
        """Запуск сканирования в отдельном потоке"""
        if not self.scan_in_progress:
            self.scan_in_progress = True
            self._disable_buttons()
            
            threading.Thread(target=self._scan_thread, daemon=True).start()
    
    def _disable_buttons(self):
        """Отключение кнопок во время сканирования"""
        self.scan_btn.config(state=tk.DISABLED)
        self.map_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)
        if self.vuln_scanner:
            self.vuln_btn.config(state=tk.DISABLED)
    
    def _enable_buttons(self):
        """Включение кнопок после сканирования"""
        self.scan_btn.config(state=tk.NORMAL)
        self.map_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL)
        if self.vuln_scanner and hasattr(self.scanner, 'devices') and self.scanner.devices:
            self.vuln_btn.config(state=tk.NORMAL)
    
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
                
                # Показываем сводку
                summary = self.scanner.get_network_summary()
                result_str = f"✅ Сканирование завершено!\n{summary}\n"
                self._update_info(result_str)
                self._update_status("Готово")
                
            else:
                self._update_info("❌ Не удалось определить сеть\n")
                self._update_status("Ошибка")
                
        except Exception as e:
            self._update_info(f"❌ Ошибка сканирования: {str(e)}\n")
            self._update_status("Ошибка")
        finally:
            self.scan_in_progress = False
            self._enable_buttons()
    
    def _display_devices(self, devices):
        """Отображение ВСЕХ устройств в таблице"""
        # Очистка таблицы
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        # Заполнение данными ВСЕХ устройств
        for device in devices:
            # Форматируем порты
            ports_str = "Нет открытых"
            if device['ports']:
                ports_str = ", ".join([str(p['port']) for p in device['ports'][:3]])
                if len(device['ports']) > 3:
                    ports_str += f" ...(+{len(device['ports'])-3})"
            
            # Помечаем устройства без детального сканирования
            hostname = device['hostname']
            os_info = device['os']
            hardware_info = "Unknown"
            
            if device['os'] == 'Unknown' and device['vendor'] == 'Unknown':
                hostname = f"⏳ {hostname}"  # Иконка ожидания
                os_info = "⏳ Сканирование..."
            else:
                # Отображаем информацию о железе
                if 'hardware' in device and device['hardware'].get('type') != 'Unknown':
                    hardware_info = f"{device['hardware'].get('type', 'Unknown')}"
            
            self.devices_tree.insert('', tk.END, values=(
                device['ip'],
                device['mac'],
                hostname,
                device['vendor'],
                os_info,
                hardware_info,
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
            try:
                self.scanner.export_results(self.scanner.devices, filename)
                messagebox.showinfo("Успех", f"Результаты экспортированы в {filename}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось экспортировать: {str(e)}")
        else:
            messagebox.showwarning("Внимание", "Сначала выполните сканирование сети")
    
    def scan_vulnerabilities(self):
        """Сканирование уязвимостей"""
        if not hasattr(self.scanner, 'devices') or not self.scanner.devices:
            messagebox.showwarning("Внимание", "Сначала выполните сканирование сети")
            return
        
        if not self.vuln_scanner:
            messagebox.showerror("Ошибка", "Сканер уязвимостей не доступен")
            return
        
        # Проверяем установлены ли скрипты
        missing = self.vuln_scanner.check_scripts_installed()
        if missing:
            messagebox.showwarning("Внимание", 
                                 f"Скрипты не установлены: {', '.join(missing)}\n\n"
                                 f"Установите:\n"
                                 f"sudo apt install nmap\n"
                                 f"sudo wget -O /usr/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse\n"
                                 f"sudo nmap --script-updatedb")
            return
        
        # Запускаем в отдельном потоке
        threading.Thread(target=self._vuln_scan_thread, daemon=True).start()
    
    def _vuln_scan_thread(self):
        """Поток сканирования уязвимостей"""
        try:
            self._update_status("🛡️ Сканирование уязвимостей...")
            if hasattr(self, 'vuln_text'):
                self.vuln_text.delete(1.0, tk.END)
                self.vuln_text.insert(tk.END, "🛡️ Начало сканирования уязвимостей...\n\n")
                self.vuln_text.see(tk.END)
            
            all_vulnerabilities = []
            total_devices = len(self.scanner.devices)
            
            for i, device in enumerate(self.scanner.devices, 1):
                if hasattr(self, 'vuln_text'):
                    progress = f"[{i}/{total_devices}]"
                    self.vuln_text.insert(tk.END, f"{progress} 🔍 Сканирую {device['ip']} ({device['hostname']})...\n")
                    self.vuln_text.see(tk.END)
                    self.vuln_text.update()
                
                # Получаем порты для сканирования
                ports = [p['port'] for p in device.get('ports', [])]
                vulnerabilities = self.vuln_scanner.scan_device_vulnerabilities(
                    device['ip'], ports if ports else None
                )
                
                all_vulnerabilities.extend(vulnerabilities)
                
                if hasattr(self, 'vuln_text') and vulnerabilities:
                    self.vuln_text.insert(tk.END, f"   ✅ Найдено уязвимостей: {len(vulnerabilities)}\n")
                else:
                    self.vuln_text.insert(tk.END, f"   ✅ Уязвимостей не обнаружено\n")
            
            # Генерируем отчет
            report = self.vuln_scanner.generate_vulnerability_report(all_vulnerabilities)
            if hasattr(self, 'vuln_text'):
                self.vuln_text.insert(tk.END, f"\n{'='*50}\n")
                self.vuln_text.insert(tk.END, report)
                self.vuln_text.see(tk.END)
            self._update_status("Сканирование уязвимостей завершено")
            
        except Exception as e:
            error_msg = f"❌ Ошибка сканирования уязвимостей: {str(e)}\n"
            if hasattr(self, 'vuln_text'):
                self.vuln_text.insert(tk.END, error_msg)
            self._update_status("Ошибка сканирования уязвимостей")
    
    def show_context_menu(self, event):
        """Показать контекстное меню для таблицы"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
    
    def copy_ip(self):
        """Копировать IP выделенного устройства"""
        selection = self.devices_tree.selection()
        if selection:
            item = self.devices_tree.item(selection[0])
            ip = item['values'][0]
            self._copy_to_clipboard(ip)
    
    def _copy_to_clipboard(self, text):
        """Копирование текста в буфер обмена"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._update_status(f"📋 Скопировано: {text}")
    
    def show_device_details(self):
        """Показать детальную информацию об устройстве"""
        selection = self.devices_tree.selection()
        if selection:
            item = self.devices_tree.item(selection[0])
            ip = item['values'][0]
            
            # Находим устройство в данных сканера
            device_info = None
            for device in self.scanner.devices:
                if device['ip'] == ip:
                    device_info = device
                    break
            
            if device_info:
                # Создаем детальную информацию
                details = f"🔍 ДЕТАЛЬНАЯ ИНФОРМАЦИЯ ОБ УСТРОЙСТВЕ\n"
                details += "=" * 50 + "\n\n"
                
                details += f"📱 ОСНОВНАЯ ИНФОРМАЦИЯ:\n"
                details += f"• IP адрес: {device_info['ip']}\n"
                details += f"• Hostname: {device_info['hostname']}\n"
                details += f"• MAC адрес: {device_info['mac']}\n"
                details += f"• Производитель: {device_info['vendor']}\n"
                details += f"• Операционная система: {device_info['os']}\n"
                details += f"• Статус: {device_info['status']}\n"
                details += f"• Последнее обнаружение: {device_info['last_seen']}\n\n"
                
                # Информация о железе
                hardware = device_info['hardware']
                details += f"🛠️ ИНФОРМАЦИЯ О ЖЕЛЕЗЕ:\n"
                details += f"• Тип устройства: {hardware.get('type', 'Unknown')}\n"
                details += f"• Архитектура: {hardware.get('architecture', 'Unknown')}\n"
                details += f"• Производитель: {hardware.get('vendor', 'Unknown')}\n"
                details += f"• Модель: {hardware.get('model', 'Unknown')}\n"
                details += f"• Уровень достоверности: {hardware.get('confidence', '0%')}\n\n"
                
                # Информация о портах
                if device_info['ports']:
                    details += f"🔓 ОТКРЫТЫЕ ПОРТЫ ({len(device_info['ports'])}):\n"
                    for port in device_info['ports']:
                        details += f"• Порт {port['port']}/tcp:\n"
                        details += f"  Сервис: {port['service']}\n"
                        details += f"  Версия: {port['version']}\n"
                        details += f"  Статус: {port['state']}\n\n"
                else:
                    details += "🔒 Открытых портов не обнаружено\n\n"
                
                # Сетевая информация
                if hasattr(self.scanner, 'network_info'):
                    net_info = self.scanner.network_info
                    details += f"🌐 СЕТЕВАЯ ИНФОРМАЦИЯ:\n"
                    details += f"• Локальная сеть: {net_info.get('network', 'Unknown')}\n"
                    details += f"• Шлюз по умолчанию: {net_info.get('gateway', 'Unknown')}\n"
                    details += f"• Интерфейс: {net_info.get('interface', 'Unknown')}\n"
                
            else:
                details = f"❌ Устройство с IP {ip} не найдено в данных сканирования"
            
            # Создаем окно с деталями
            details_window = tk.Toplevel(self.root)
            details_window.title(f"🔍 Детали устройства {ip}")
            details_window.geometry("700x600")
            details_window.configure(bg='#2C3E50')
            
            # Создаем фрейм для содержимого
            content_frame = ttk.Frame(details_window)
            content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Текстовая область с деталями
            details_text = scrolledtext.ScrolledText(content_frame, 
                                                   bg='#34495E', 
                                                   fg='white',
                                                   font=('Consolas', 10),
                                                   insertbackground='white',
                                                   wrap=tk.WORD)
            details_text.pack(fill=tk.BOTH, expand=True)
            details_text.insert(tk.END, details)
            details_text.config(state=tk.DISABLED)
            
            # Фрейм для кнопок
            button_frame = ttk.Frame(content_frame)
            button_frame.pack(fill=tk.X, pady=(10, 0))
            
            # Кнопка копирования IP
            copy_btn = ttk.Button(button_frame, text="📋 Копировать IP", 
                                 command=lambda: self._copy_to_clipboard(device_info['ip']))
            copy_btn.pack(side=tk.LEFT, padx=(0, 10))
            
            # Кнопка сканирования уязвимостей (если доступно)
            if self.vuln_scanner and device_info:
                vuln_btn = ttk.Button(button_frame, text="🛡️ Сканировать уязвимости", 
                                     command=lambda: self._scan_single_device_vulnerabilities(device_info))
                vuln_btn.pack(side=tk.LEFT, padx=(0, 10))
            
            # Кнопка закрытия
            close_btn = ttk.Button(button_frame, text="Закрыть", 
                                  command=details_window.destroy)
            close_btn.pack(side=tk.RIGHT)
    
    def _scan_single_device_vulnerabilities(self, device):
        """Сканирование уязвимостей для одного устройства"""
        if not self.vuln_scanner:
            messagebox.showerror("Ошибка", "Сканер уязвимостей не доступен")
            return
        
        # Проверяем установлены ли скрипты
        missing = self.vuln_scanner.check_scripts_installed()
        if missing:
            messagebox.showwarning("Внимание", 
                                 f"Скрипты не установлены: {', '.join(missing)}\n\n"
                                 f"Установите:\n"
                                 f"sudo apt install nmap\n"
                                 f"sudo wget -O /usr/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse\n"
                                 f"sudo nmap --script-updatedb")
            return
        
        # Запускаем в отдельном потоке
        threading.Thread(target=self._single_device_vuln_scan_thread, 
                        args=(device,), daemon=True).start()
    
    def _single_device_vuln_scan_thread(self, device):
        """Поток сканирования уязвимостей для одного устройства"""
        try:
            self._update_status(f"🛡️ Сканирование уязвимостей {device['ip']}...")
            
            # Получаем порты для сканирования
            ports = [p['port'] for p in device.get('ports', [])]
            vulnerabilities = self.vuln_scanner.scan_device_vulnerabilities(
                device['ip'], ports if ports else None
            )
            
            # Создаем отчет
            report = f"🛡️ ОТЧЕТ ПО УЯЗВИМОСТЯМ ДЛЯ {device['ip']}\n"
            report += "=" * 50 + "\n\n"
            report += f"📱 Устройство: {device['hostname']} ({device['ip']})\n"
            report += f"💻 ОС: {device['os']}\n"
            report += f"🛠️ Тип: {device['hardware'].get('type', 'Unknown')}\n\n"
            
            if vulnerabilities:
                report += f"⚠️ Найдено уязвимостей: {len(vulnerabilities)}\n\n"
                
                # Группируем по уровню риска
                by_risk = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
                for vuln in vulnerabilities:
                    by_risk[vuln['risk_level']].append(vuln)
                
                for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    vulns = by_risk[risk_level]
                    if vulns:
                        report += f"🔴 {risk_level} РИСК: {len(vulns)} уязвимостей\n"
                        report += "-" * 40 + "\n"
                        
                        for vuln in vulns:
                            report += f"🎯 Порт {vuln['port']} ({vuln.get('service', 'unknown')})\n"
                            report += f"   {vuln['description']}\n\n"
            else:
                report += "✅ Уязвимостей не обнаружено\n"
            
            # Показываем отчет в отдельном окне
            self.root.after(0, lambda: self._show_vuln_report(device['ip'], report))
            self._update_status(f"Сканирование уязвимостей {device['ip']} завершено")
            
        except Exception as e:
            error_msg = f"❌ Ошибка сканирования уязвимостей {device['ip']}: {str(e)}"
            self.root.after(0, lambda: messagebox.showerror("Ошибка", error_msg))
            self._update_status("Ошибка сканирования уязвимостей")
    
    def _show_vuln_report(self, device_ip, report):
        """Показать отчет по уязвимостям"""
        report_window = tk.Toplevel(self.root)
        report_window.title(f"🛡️ Уязвимости устройства {device_ip}")
        report_window.geometry("800x600")
        report_window.configure(bg='#2C3E50')
        
        # Текстовая область с отчетом
        report_text = scrolledtext.ScrolledText(report_window, 
                                              bg='#34495E', 
                                              fg='white',
                                              font=('Consolas', 10),
                                              insertbackground='white',
                                              wrap=tk.WORD)
        report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        report_text.insert(tk.END, report)
        report_text.config(state=tk.DISABLED)
        
        # Кнопка закрытия
        close_btn = ttk.Button(report_window, text="Закрыть", 
                              command=report_window.destroy)
        close_btn.pack(pady=10)
    
    def _update_info(self, text):
        """Обновление информационного текста"""
        self.root.after(0, lambda: self.info_text.insert(tk.END, text))
    
    def _update_status(self, text):
        """Обновление статус бара"""
        self.root.after(0, lambda: self.status_var.set(text))
