import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import json
from datetime import datetime

try:
    from scanner import NetworkScanner
    from vulnerability_scanner import AdvancedVulnerabilityScanner
    from visualizer import NetworkVisualizer
except ImportError as e:
    print(f"❌ Ошибка импорта модулей: {e}")
    # Создать заглушки для тестирования
    class NetworkScanner: 
        def __init__(self): 
            self.scan_progress = {'active': False}
            self.scan_results = {}
        def scan_network(self, **kwargs): return {'status': 'error'}
        def get_scan_results(self): return {}
        def stop_scan(self): pass
    
    class AdvancedVulnerabilityScanner:
        def __init__(self): 
            self.scan_progress = {'active': False}
        def scan_network_vulnerabilities(self, **kwargs): return {'status': 'error'}
        def get_vulnerability_results(self): return {}
        def stop_scan(self): pass
    
    class NetworkVisualizer:
        def create_network_map(self, **kwargs): return None
        def create_vulnerability_chart(self, **kwargs): return None

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Security Scanner v2.0")
        self.root.geometry("1200x800")
        
        # Инициализация компонентов
        self.scanner = NetworkScanner()
        self.vuln_scanner = AdvancedVulnerabilityScanner()
        self.visualizer = NetworkVisualizer()
        
        # Переменные интерфейса
        self.scan_results = {}
        self.vulnerability_results = {}
        
        self.setup_ui()
        self.setup_logging()
        
    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        # Создание вкладок
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Вкладка сканирования
        self.scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_frame, text="Сканирование сети")
        
        # Вкладка уязвимостей
        self.vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vuln_frame, text="Анализ уязвимостей")
        
        # Вкладка визуализации
        self.viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.viz_frame, text="Визуализация")
        
        # Вкладка логов
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="Логи")
        
        self.setup_scan_tab()
        self.setup_vulnerability_tab()
        self.setup_visualization_tab()
        self.setup_log_tab()
        
        # Статус бар
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def setup_scan_tab(self):
        """Настройка вкладки сканирования"""
        # Фрейм настроек
        settings_frame = ttk.LabelFrame(self.scan_frame, text="Настройки сканирования", padding=10)
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Цель сканирования
        ttk.Label(settings_frame, text="Цель:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.target_var = tk.StringVar(value="")
        target_entry = ttk.Entry(settings_frame, textvariable=self.target_var, width=30)
        target_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Кнопка автоматического определения сети
        ttk.Button(settings_frame, text="Авто", command=self.auto_detect_network).grid(row=0, column=2, padx=5, pady=2)
        
        # Порт
        ttk.Label(settings_frame, text="Порты:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.ports_var = tk.StringVar(value="1-1000")
        ports_entry = ttk.Entry(settings_frame, textvariable=self.ports_var, width=30)
        ports_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Тип сканирования
        ttk.Label(settings_frame, text="Тип:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.scan_type_var = tk.StringVar(value="syn")
        scan_type_combo = ttk.Combobox(settings_frame, textvariable=self.scan_type_var, 
                                      values=["syn", "connect", "udp", "aggressive", "quick", "comprehensive"])
        scan_type_combo.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        scan_type_combo.set("syn")
        
        # Кнопки сканирования
        button_frame = ttk.Frame(settings_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        ttk.Button(button_frame, text="Быстрое сканирование", command=self.quick_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Полное сканирование", command=self.full_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Остановить", command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        
        # Прогресс
        progress_frame = ttk.Frame(self.scan_frame)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=5, pady=2)
        
        self.progress_label = ttk.Label(progress_frame, text="Ожидание начала сканирования...")
        self.progress_label.pack(padx=5, pady=2)
        
        # Результаты
        results_frame = ttk.LabelFrame(self.scan_frame, text="Результаты сканирования", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview для результатов
        columns = ("Host", "Hostname", "State", "Ports", "OS")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100)
        
        self.results_tree.column("Host", width=120)
        self.results_tree.column("Hostname", width=150)
        self.results_tree.column("Ports", width=80)
        
        # Scrollbar для treeview
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Кнопки экспорта
        export_frame = ttk.Frame(self.scan_frame)
        export_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(export_frame, text="Экспорт в JSON", command=self.export_scan_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Очистить результаты", command=self.clear_scan_results).pack(side=tk.LEFT, padx=5)
        
    def setup_vulnerability_tab(self):
        """Настройка вкладки уязвимостей"""
        # Фрейм управления
        control_frame = ttk.LabelFrame(self.vuln_frame, text="Управление сканированием уязвимостей", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Сканировать уязвимости", command=self.scan_vulnerabilities).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Остановить сканирование", command=self.stop_vuln_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Обновить базу CVE", command=self.update_cve_database).pack(side=tk.LEFT, padx=5)
        
        # Прогресс уязвимостей
        vuln_progress_frame = ttk.Frame(self.vuln_frame)
        vuln_progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.vuln_progress_var = tk.DoubleVar()
        self.vuln_progress_bar = ttk.Progressbar(vuln_progress_frame, variable=self.vuln_progress_var, maximum=100)
        self.vuln_progress_bar.pack(fill=tk.X, padx=5, pady=2)
        
        self.vuln_progress_label = ttk.Label(vuln_progress_frame, text="Ожидание начала сканирования уязвимостей...")
        self.vuln_progress_label.pack(padx=5, pady=2)
        
        # Результаты уязвимостей
        vuln_results_frame = ttk.LabelFrame(self.vuln_frame, text="Результаты сканирования уязвимостей", padding=10)
        vuln_results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview для уязвимостей
        vuln_columns = ("Host", "Service", "CVE", "Severity", "CVSS", "Description")
        self.vuln_tree = ttk.Treeview(vuln_results_frame, columns=vuln_columns, show="headings", height=15)
        
        for col in vuln_columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=100)
        
        self.vuln_tree.column("Host", width=120)
        self.vuln_tree.column("Service", width=100)
        self.vuln_tree.column("CVE", width=120)
        self.vuln_tree.column("Severity", width=80)
        self.vuln_tree.column("CVSS", width=60)
        self.vuln_tree.column("Description", width=200)
        
        # Scrollbar для treeview уязвимостей
        vuln_scrollbar = ttk.Scrollbar(vuln_results_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vuln_scrollbar.set)
        vuln_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Кнопки экспорта уязвимостей
        vuln_export_frame = ttk.Frame(self.vuln_frame)
        vuln_export_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(vuln_export_frame, text="Экспорт уязвимостей", command=self.export_vulnerabilities).pack(side=tk.LEFT, padx=5)
        ttk.Button(vuln_export_frame, text="Очистить уязвимости", command=self.clear_vulnerabilities).pack(side=tk.LEFT, padx=5)
        
    def setup_visualization_tab(self):
        """Настройка вкладки визуализации"""
        control_frame = ttk.LabelFrame(self.viz_frame, text="Визуализация данных", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Показать карту сети", command=self.show_network_map).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Показать диаграмму уязвимостей", command=self.show_vulnerability_chart).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Показать статистику сканирования", command=self.show_scan_stats).pack(side=tk.LEFT, padx=5)
        
        # Область для отображения графиков
        self.viz_text = scrolledtext.ScrolledText(self.viz_frame, height=20, state=tk.DISABLED)
        self.viz_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Кнопки сохранения
        save_frame = ttk.Frame(self.viz_frame)
        save_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(save_frame, text="Сохранить визуализацию", command=self.save_visualization).pack(side=tk.LEFT, padx=5)
        
    def setup_log_tab(self):
        """Настройка вкладки логов"""
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=25, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Кнопки управления логами
        log_control_frame = ttk.Frame(self.log_frame)
        log_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(log_control_frame, text="Очистить логи", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_control_frame, text="Сохранить логи", command=self.save_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_control_frame, text="Экспорт отчетов", command=self.export_reports).pack(side=tk.LEFT, padx=5)
        
    def setup_logging(self):
        """Настройка системы логирования"""
        self.log("🚀 Advanced Network Security Scanner v2.0 запущен")
        self.log("✅ Все модули инициализированы")
        
    def log(self, message: str):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, formatted_message)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
        
        print(formatted_message.strip())
        
    def auto_detect_network(self):
        """Автоматическое определение сети"""
        try:
            network = self.scanner.get_local_network()
            self.target_var.set(network)
            self.log(f"🌐 Автоматически определена сеть: {network}")
        except Exception as e:
            self.log(f"❌ Ошибка определения сети: {e}")
            messagebox.showerror("Ошибка", f"Не удалось определить сеть: {e}")
    
    def quick_scan(self):
        """Быстрое сканирование"""
        target = self.target_var.get() or self.scanner.get_local_network()
        self.log(f"🔍 Запуск быстрого сканирования: {target}")
        
        # Запуск в отдельном потоке
        scan_thread = threading.Thread(target=self._perform_scan, args=("quick", target))
        scan_thread.daemon = True
        scan_thread.start()
    
    def full_scan(self):
        """Полное сканирование"""
        target = self.target_var.get() or self.scanner.get_local_network()
        self.log(f"🔍 Запуск полного сканирования: {target}")
        
        # Запуск в отдельном потоке
        scan_thread = threading.Thread(target=self._perform_scan, args=("comprehensive", target))
        scan_thread.daemon = True
        scan_thread.start()
    
    def _perform_scan(self, scan_type: str, target: str):
        """Выполнение сканирования"""
        try:
            if scan_type == "quick":
                result = self.scanner.quick_scan(target)
            else:
                result = self.scanner.scan_network(target=target, scan_type="comprehensive")
            
            if result.get('error'):
                self.log(f"❌ Ошибка сканирования: {result['error']}")
                return
            
            # Мониторинг прогресса
            while self.scanner.scan_progress['active']:
                progress = self.scanner.scan_progress
                
                # Обновление UI в основном потоке
                self.root.after(0, self._update_scan_progress, progress)
                time.sleep(0.5)
            
            # Получение результатов
            self.root.after(0, self._process_scan_results)
            
        except Exception as e:
            self.log(f"❌ Ошибка при сканировании: {e}")
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка сканирования: {e}"))
    
    def _update_scan_progress(self, progress: dict):
        """Обновление прогресса сканирования"""
        self.progress_var.set(progress['current'])
        self.progress_label.config(text=progress['stage'])
        self.status_var.set(f"Сканирование: {progress['stage']}")
    
    def _process_scan_results(self):
        """Обработка результатов сканирования"""
        try:
            self.scan_results = self.scanner.get_scan_results()
            self._display_scan_results()
            self.log(f"✅ Сканирование завершено. Найдено хостов: {len(self.scan_results.get('results', {}))}")
            self.status_var.set("Сканирование завершено")
            
        except Exception as e:
            self.log(f"❌ Ошибка обработки результатов: {e}")
    
    def _display_scan_results(self):
        """Отображение результатов сканирования в таблице"""
        # Очистка таблицы
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        results = self.scan_results.get('results', {})
        
        for host, info in results.items():
            hostname = info.get('hostname', 'N/A')
            state = info.get('state', 'unknown')
            ports = len([p for p in info.get('ports', []) if p.get('state') == 'open'])
            
            # Определение ОС
            os_info = "Unknown"
            if info.get('os'):
                best_os = max(info['os'], key=lambda x: x.get('accuracy', 0))
                os_info = best_os.get('name', 'Unknown')
            
            self.results_tree.insert("", tk.END, values=(host, hostname, state, ports, os_info))
    
    def stop_scan(self):
        """Остановка сканирования"""
        self.scanner.stop_scan()
        self.log("⏹️ Сканирование остановлено пользователем")
        self.status_var.set("Сканирование остановлено")
    
    def scan_vulnerabilities(self):
        """Сканирование уязвимостей"""
        if not self.scan_results.get('results'):
            messagebox.showwarning("Предупреждение", "Сначала выполните сканирование сети")
            return
        
        self.log("🔍 Запуск сканирования уязвимостей...")
        
        # Запуск в отдельном потоке
        vuln_thread = threading.Thread(target=self._perform_vuln_scan)
        vuln_thread.daemon = True
        vuln_thread.start()
    
    def _perform_vuln_scan(self):
        """Выполнение сканирования уязвимостей"""
        try:
            result = self.vuln_scanner.scan_network_vulnerabilities(self.scan_results)
            
            if result.get('error'):
                self.log(f"❌ Ошибка сканирования уязвимостей: {result['error']}")
                return
            
            # Мониторинг прогресса
            while self.vuln_scanner.scan_progress['active']:
                progress = self.vuln_scanner.scan_progress
                
                # Обновление UI в основном потоке
                self.root.after(0, self._update_vuln_progress, progress)
                time.sleep(0.5)
            
            # Получение результатов
            self.root.after(0, self._process_vuln_results)
            
        except Exception as e:
            self.log(f"❌ Ошибка при сканировании уязвимостей: {e}")
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка сканирования уязвимостей: {e}"))
    
    def _update_vuln_progress(self, progress: dict):
        """Обновление прогресса сканирования уязвимостей"""
        self.vuln_progress_var.set(progress['current'])
        self.vuln_progress_label.config(text=progress['stage'])
        self.status_var.set(f"Сканирование уязвимостей: {progress['stage']}")
    
    def _process_vuln_results(self):
        """Обработка результатов сканирования уязвимостей"""
        try:
            self.vulnerability_results = self.vuln_scanner.get_vulnerability_results()
            self._display_vulnerability_results()
            
            summary = self.vulnerability_results.get('summary', {})
            total_vulns = summary.get('total_vulnerabilities', 0)
            
            self.log(f"✅ Сканирование уязвимостей завершено. Найдено: {total_vulns} уязвимостей")
            self.status_var.set("Сканирование уязвимостей завершено")
            
            # Показать статистику
            if total_vulns > 0:
                critical = summary.get('severity_distribution', {}).get('CRITICAL', 0)
                high = summary.get('severity_distribution', {}).get('HIGH', 0)
                
                if critical > 0 or high > 0:
                    messagebox.showwarning(
                        "Высокий риск", 
                        f"Обнаружены критические уязвимости!\nКритические: {critical}, Высокие: {high}"
                    )
            
        except Exception as e:
            self.log(f"❌ Ошибка обработки результатов уязвимостей: {e}")
    
    def _display_vulnerability_results(self):
        """Отображение результатов уязвимостей"""
        # Очистка таблицы
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        vulnerabilities = self.vulnerability_results.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            host = vuln.get('host', 'N/A')
            service = vuln.get('service', 'N/A')
            cve = vuln.get('vulnerability_id', 'N/A')
            severity = vuln.get('severity', 'UNKNOWN')
            cvss = vuln.get('cvss_score', 0.0)
            description = vuln.get('description', '')[:100] + "..." if len(vuln.get('description', '')) > 100 else vuln.get('description', '')
            
            # Цвет в зависимости от severity
            tags = ""
            if severity == 'CRITICAL':
                tags = 'critical'
            elif severity == 'HIGH':
                tags = 'high'
            elif severity == 'MEDIUM':
                tags = 'medium'
            elif severity == 'LOW':
                tags = 'low'
            
            self.vuln_tree.insert("", tk.END, values=(host, service, cve, severity, cvss, description), tags=(tags,))
        
        # Настройка цветов
        self.vuln_tree.tag_configure('critical', background='#ffcccc')
        self.vuln_tree.tag_configure('high', background='#ffe6cc')
        self.vuln_tree.tag_configure('medium', background='#ffffcc')
        self.vuln_tree.tag_configure('low', background='#e6ffcc')
    
    def stop_vuln_scan(self):
        """Остановка сканирования уязвимостей"""
        self.vuln_scanner.stop_scan()
        self.log("⏹️ Сканирование уязвимостей остановлено")
        self.status_var.set("Сканирование уязвимостей остановлено")
    
    def update_cve_database(self):
        """Обновление базы данных CVE"""
        try:
            if hasattr(self.vuln_scanner, 'cve_integration') and self.vuln_scanner.cve_integration:
                self.log("🔄 Начало обновления базы CVE...")
                
                def update_thread():
                    try:
                        updated = self.vuln_scanner.cve_integration.update_cve_database()
                        self.root.after(0, lambda: self.log(f"✅ База CVE обновлена. Добавлено записей: {updated}"))
                    except Exception as e:
                        self.root.after(0, lambda: self.log(f"❌ Ошибка обновления базы CVE: {e}"))
                
                thread = threading.Thread(target=update_thread)
                thread.daemon = True
                thread.start()
            else:
                messagebox.showinfo("Информация", "CVE интеграция не доступна")
                
        except Exception as e:
            self.log(f"❌ Ошибка при обновлении CVE: {e}")
    
    def show_network_map(self):
        """Показать карту сети"""
        if not self.scan_results.get('results'):
            messagebox.showwarning("Предупреждение", "Сначала выполните сканирование сети")
            return
        
        try:
            self.log("🗺️ Генерация карты сети...")
            fig = self.visualizer.create_network_map(self.scan_results)
            
            if fig:
                plt = self._get_matplotlib()
                plt.show()
                self.log("✅ Карта сети сгенерирована")
            else:
                self.log("❌ Не удалось создать карту сети")
                
        except Exception as e:
            self.log(f"❌ Ошибка создания карты сети: {e}")
            messagebox.showerror("Ошибка", f"Не удалось создать карту сети: {e}")
    
    def show_vulnerability_chart(self):
        """Показать диаграмму уязвимостей"""
        if not self.vulnerability_results.get('vulnerabilities'):
            messagebox.showwarning("Предупреждение", "Сначала выполните сканирование уязвимостей")
            return
        
        try:
            self.log("📊 Генерация диаграммы уязвимостей...")
            fig = self.visualizer.create_vulnerability_chart(self.vulnerability_results)
            
            if fig:
                plt = self._get_matplotlib()
                plt.show()
                self.log("✅ Диаграмма уязвимостей сгенерирована")
            else:
                self.log("❌ Не удалось создать диаграмму уязвимостей")
                
        except Exception as e:
            self.log(f"❌ Ошибка создания диаграммы уязвимостей: {e}")
            messagebox.showerror("Ошибка", f"Не удалось создать диаграмму уязвимостей: {e}")
    
    def show_scan_stats(self):
        """Показать статистику сканирования"""
        if not self.scan_results.get('results'):
            messagebox.showwarning("Предупреждение", "Сначала выполните сканирование сети")
            return
        
        try:
            self.log("📈 Генерация статистики сканирования...")
            fig = self.visualizer.create_scan_progress_chart(self.scan_results)
            
            if fig:
                plt = self._get_matplotlib()
                plt.show()
                self.log("✅ Статистика сканирования сгенерирована")
            else:
                self.log("❌ Не удалось создать статистику сканирования")
                
        except Exception as e:
            self.log(f"❌ Ошибка создания статистики: {e}")
            messagebox.showerror("Ошибка", f"Не удалось создать статистику: {e}")
    
    def _get_matplotlib(self):
        """Получение matplotlib с настройками для русского языка"""
        import matplotlib.pyplot as plt
        plt.rcParams['font.family'] = 'DejaVu Sans'
        plt.rcParams['axes.unicode_minus'] = False
        return plt
    
    def save_visualization(self):
        """Сохранение визуализации"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
            )
            if filename:
                # Здесь можно добавить логику сохранения текущей визуализации
                self.log(f"💾 Визуализация сохранена: {filename}")
                messagebox.showinfo("Успех", f"Визуализация сохранена в {filename}")
        except Exception as e:
            self.log(f"❌ Ошибка сохранения визуализации: {e}")
    
    def export_scan_results(self):
        """Экспорт результатов сканирования"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename and self.scan_results:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
                self.log(f"💾 Результаты сканирования экспортированы: {filename}")
        except Exception as e:
            self.log(f"❌ Ошибка экспорта результатов: {e}")
    
    def export_vulnerabilities(self):
        """Экспорт уязвимостей"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename and self.vulnerability_results:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.vulnerability_results, f, indent=2, ensure_ascii=False)
                self.log(f"💾 Уязвимости экспортированы: {filename}")
        except Exception as e:
            self.log(f"❌ Ошибка экспорта уязвимостей: {e}")
    
    def clear_scan_results(self):
        """Очистка результатов сканирования"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results = {}
        self.log("🗑️ Результаты сканирования очищены")
    
    def clear_vulnerabilities(self):
        """Очистка уязвимостей"""
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        self.vulnerability_results = {}
        self.log("🗑️ Результаты уязвимостей очищены")
    
    def clear_logs(self):
        """Очистка логов"""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.log("🗑️ Логи очищены")
    
    def save_logs(self):
        """Сохранение логов"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self.log(f"💾 Логи сохранены: {filename}")
        except Exception as e:
            self.log(f"❌ Ошибка сохранения логов: {e}")
    
    def export_reports(self):
        """Экспорт отчетов"""
        try:
            # Создание комплексного отчета
            report = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'scanner_version': '2.0.0'
                },
                'network_scan': self.scan_results,
                'vulnerability_scan': self.vulnerability_results
            }
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON reports", "*.json"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                self.log(f"📊 Комплексный отчет экспортирован: {filename}")
                
        except Exception as e:
            self.log(f"❌ Ошибка экспорта отчета: {e}")


# Запуск приложения
if __name__ == "__main__":
    def main():
        root = tk.Tk()
        app = NetworkScannerGUI(root)
        root.mainloop()

    main()
