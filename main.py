#!/usr/bin/env python3
"""
Главный файл запуска Network Scanner
Автор: [BotPany]
Версия: 1.0.0
"""

import tkinter as tk
import argparse
import sys
import os

# Добавляем путь к src в PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from gui import NetworkScannerGUI
from scanner import NetworkScanner
from visualizer import NetworkVisualizer

def main():
    """Основная функция запуска"""
    parser = argparse.ArgumentParser(description='Network Scanner - Анализатор WiFi сетей')
    parser.add_argument('--gui', action='store_true', help='Запуск с GUI интерфейсом')
    parser.add_argument('--scan', type=str, help='Сканировать указанную сеть (например: 192.168.1.0/24)')
    parser.add_argument('--export', type=str, help='Экспорт результатов в файл')
    
    args = parser.parse_args()
    
    if args.gui or not any(vars(args).values()):
        # Запуск GUI версии
        root = tk.Tk()
        app = NetworkScannerGUI(root)
        root.mainloop()
    elif args.scan:
        # Консольная версия
        scanner = NetworkScanner()
        print(f"🔍 Сканирование сети: {args.scan}")
        devices = scanner.scan_network(args.scan)
        
        print(f"✅ Найдено устройств: {len(devices)}")
        for device in devices:
            print(f"\n📱 {device['hostname']} ({device['ip']})")
            print(f"   MAC: {device['mac']}")
            print(f"   Производитель: {device['vendor']}")
            print(f"   ОС: {device['os']}")
            
        if args.export:
            scanner.export_results(devices, args.export)
            print(f"💾 Результаты экспортированы в: {args.export}")

if __name__ == "__main__":
    main()
