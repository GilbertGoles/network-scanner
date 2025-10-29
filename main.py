#!/usr/bin/env python3
"""
Advanced Network Security Scanner v2.0
Автор: [BotPany]
"""

import tkinter as tk
from tkinter import messagebox
import sys
import os
import subprocess

def check_dependencies():
    """Проверка и установка зависимостей"""
    try:
        import requests
        import nmap
        import matplotlib
        import networkx
        import netifaces
        return True
    except ImportError as e:
        print(f"❌ Отсутствуют зависимости: {e}")
        response = messagebox.askyesno(
            "Установка зависимостей", 
            "Необходимые библиотеки не установлены. Установить автоматически?"
        )
        if response:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
                messagebox.showinfo("Успех", "Зависимости установлены! Перезапустите приложение.")
                return True
            except Exception as install_error:
                messagebox.showerror("Ошибка", f"Не удалось установить зависимости: {install_error}")
        return False

def main():
    """Главная функция запуска"""
    if not check_dependencies():
        return
    
    try:
        # Добавляем путь к src
        src_path = os.path.join(os.path.dirname(__file__), 'src')
        if src_path not in sys.path:
            sys.path.append(src_path)
            
        from gui import NetworkScannerGUI
        
        root = tk.Tk()
        app = NetworkScannerGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"❌ Ошибка запуска: {e}")
        messagebox.showerror("Ошибка", f"Не удалось запустить приложение: {e}")

if __name__ == "__main__":
    main()
