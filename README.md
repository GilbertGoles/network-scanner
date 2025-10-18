# 🌐 Network Scanner

Быстрый сканер WiFi сетей с визуализацией в стиле Obsidian.

![Скрин1](images/Screenshot_2025-10-18_09_18_16.png)
![Скрин2](images/Screenshot_2025-10-18_09_18_30.png)

## 🚀 Возможности

- 🔍 Автоматическое обнаружение WiFi сети
- 📱 Определение всех подключенных устройств
- 🖥️ Анализ операционных систем, открытых портов и железа
- 🗂️ Визуализация сети в виде графа (стиль Obsidian)
- 💾 Экспорт результатов в JSON
- 🎯 GUI интерфейс и консольный режим
- 🔪 Поиск актуальных уязвимостей


## 📦 Установка 

```bash
# Клонирование репозитория
git clone https://github.com/GilbertGoles/network-scanner.git
cd network-scanner

# Установка зависимостей
pip install -r requirements.txt
```

## 📦 Установка в виртуальном окружении (Kali)

```bash
# Переходим в папку проекта
cd ~/network-scanner

# Создаем виртуальное окружение
python3 -m venv venv

# Активируем виртуальное окружение
source venv/bin/activate

# Теперь устанавливаем зависимости
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
