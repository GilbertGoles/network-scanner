#!/usr/bin/env python3
"""
Advanced Network Security Scanner v2.0
Автор: [BotPany]
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# Добавляем путь к src
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from gui import NetworkScannerGUI

def main():
    """Главная функция запуска"""
    try:
        root = tk.Tk()
        app = NetworkScannerGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"❌ Ошибка запуска: {e}")
        messagebox.showerror("Ошибка", f"Не удалось запустить приложение: {e}")

if __name__ == "__main__":
    main()
