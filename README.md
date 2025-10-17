# 🌐 Network Scanner

Профессиональный сканер WiFi сетей с визуализацией в стиле Obsidian.

## 🚀 Возможности

- 🔍 Автоматическое обнаружение WiFi сети
- 📱 Определение всех подключенных устройств
- 🖥️ Анализ операционных систем и открытых портов
- 🗂️ Визуализация сети в виде графа (стиль Obsidian)
- 💾 Экспорт результатов в JSON
- 🎯 GUI интерфейс и консольный режим


## 📦 Установка

```bash
# Клонирование репозитория
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner

# Установка зависимостей
pip install -r requirements.txt
```
## 🎮 Использование

## bash

python main.py --gui

## console

```bash
# Сканирование автоматически определенной сети
python main.py --scan auto

# Сканирование конкретной сети
python main.py --scan 192.168.1.0/24 --export results.json
```
