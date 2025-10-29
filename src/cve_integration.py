import requests
import json
import sqlite3
import os
from datetime import datetime, timedelta
import time
import threading
from typing import List, Dict, Any

class CVEIntegration:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.local_db = "cve_database.db"
        self.cache_dir = "cache"
        self._init_environment()
        self._init_local_database()
    
    def _init_environment(self):
        """Инициализация окружения"""
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
    
    def _init_local_database(self):
        """Инициализация локальной базы CVE"""
        try:
            conn = sqlite3.connect(self.local_db)
            cursor = conn.cursor()
            
            # Таблица CVE записей
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cve_entries (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_score REAL,
                    cvss_severity TEXT,
                    published_date TEXT,
                    last_modified TEXT,
                    cpe_match TEXT,
                    raw_data TEXT,
                    last_updated TEXT
                )
            ''')
            
            # Таблица CPE соответствий
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cpe_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    cpe_string TEXT,
                    version_start_including TEXT,
                    version_end_excluding TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cve_entries (cve_id)
                )
            ''')
            
            # Таблица обновлений
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS update_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    update_type TEXT,
                    timestamp TEXT,
                    records_processed INTEGER,
                    status TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            print("✅ Локальная база CVE инициализирована")
            
        except Exception as e:
            print(f"❌ Ошибка инициализации базы CVE: {e}")
    
    def search_cve_by_cpe(self, cpe_string: str) -> List[Dict[str, Any]]:
        """Поиск CVE по CPE строке"""
        print(f"🔍 Поиск CVE для: {cpe_string}")
        
        # Сначала ищем в локальной базе
        local_results = self._search_local_cve_by_cpe(cpe_string)
        if local_results:
            print(f"✅ Найдено в локальной базе: {len(local_results)} CVE")
            return local_results
        
        # Если нет в локальной базе, ищем в NVD
        print("🌐 Запрос к NVD API...")
        return self._search_nvd_cve_by_cpe(cpe_string)
    
    def _search_local_cve_by_cpe(self, cpe_string: str) -> List[Dict[str, Any]]:
        """Поиск в локальной базе данных"""
        try:
            conn = sqlite3.connect(self.local_db)
            cursor = conn.cursor()
            
            # Упрощаем CPE для поиска
            simplified_cpe = self._simplify_cpe(cpe_string)
            vendor = self._get_vendor_from_cpe(cpe_string)
            
            cursor.execute('''
                SELECT ce.cve_id, ce.description, ce.cvss_score, ce.cvss_severity
                FROM cve_entries ce
                JOIN cpe_matches cm ON ce.cve_id = cm.cve_id
                WHERE cm.cpe_string LIKE ? OR cm.cpe_string LIKE ? OR cm.cpe_string LIKE ?
                ORDER BY ce.cvss_score DESC
                LIMIT 15
            ''', (
                f'%{simplified_cpe}%',
                f'%{vendor}%',
                f'%{cpe_string}%'
            ))
            
            results = cursor.fetchall()
            conn.close()
            
            return [{
                'cve_id': row[0],
                'description': row[1],
                'cvss_score': row[2],
                'severity': row[3],
                'source': 'local_db'
            } for row in results]
            
        except Exception as e:
            print(f"❌ Ошибка поиска в локальной базе CVE: {e}")
            return []
    
    def _search_nvd_cve_by_cpe(self, cpe_string: str) -> List[Dict[str, Any]]:
        """Поиск в NVD API"""
        try:
            # Форматируем CPE для NVD API
            formatted_cpe = self._format_cpe_for_nvd(cpe_string)
            
            params = {
                'cpeName': formatted_cpe,
                'resultsPerPage': 20,
                'startIndex': 0
            }
            
            print(f"🌐 Запрос к NVD API: {formatted_cpe}")
            response = requests.get(self.nvd_api_url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                cves = self._parse_nvd_response(data)
                
                # Сохраняем в локальную базу
                if cves:
                    self._save_cves_to_local_db(cves, cpe_string)
                    print(f"💾 Сохранено в локальную базу: {len(cves)} CVE")
                
                return cves
            else:
                print(f"❌ Ошибка NVD API: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"❌ Ошибка запроса к NVD API: {e}")
            return []
    
    def _parse_nvd_response(self, data: Dict) -> List[Dict[str, Any]]:
        """Парсинг ответа NVD API"""
        cves = []
        
        for vulnerability in data.get('vulnerabilities', []):
            cve_data = vulnerability.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            if not cve_id:
                continue
            
            # Описание
            descriptions = cve_data.get('descriptions', [])
            description = next((desc['value'] for desc in descriptions if desc['lang'] == 'en'), 'No description available')
            
            # CVSS метрики
            metrics = cve_data.get('metrics', {})
            cvss_score = 0.0
            cvss_severity = 'UNKNOWN'
            
            # Пробуем разные версии CVSS
            for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if metrics.get(cvss_version):
                    cvss_data = metrics[cvss_version][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    if cvss_score > 0:
                        break
            
            # Информация о CPE
            cpe_match = self._extract_cpe_matches(cve_data)
            
            cves.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': cvss_severity,
                'published_date': cve_data.get('published', ''),
                'last_modified': cve_data.get('lastModified', ''),
                'cpe_match': json.dumps(cpe_match),
                'raw_data': json.dumps(cve_data),
                'source': 'nvd_api'
            })
        
        return cves
    
    def _extract_cpe_matches(self, cve_data: Dict) -> List[str]:
        """Извлечение CPE соответствий из данных CVE"""
        cpe_matches = []
        
        try:
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches.extend(node.get('cpeMatch', []))
        except Exception as e:
            print(f"⚠️ Ошибка извлечения CPE: {e}")
        
        return cpe_matches
    
    def _simplify_cpe(self, cpe_string: str) -> str:
        """Упрощение CPE строки для поиска"""
        try:
            # cpe:2.3:a:apache:http_server:2.4.49 -> apache:http_server
            parts = cpe_string.split(':')
            if len(parts) >= 5:
                return f"{parts[3]}:{parts[4]}"
        except:
            pass
        return cpe_string
    
    def _get_vendor_from_cpe(self, cpe_string: str) -> str:
        """Извлечение вендора из CPE"""
        try:
            parts = cpe_string.split(':')
            return parts[3] if len(parts) > 3 else ""
        except:
            return ""
    
    def _format_cpe_for_nvd(self, cpe_string: str) -> str:
        """Форматирование CPE для NVD API"""
        return cpe_string
    
    def _save_cves_to_local_db(self, cves: List[Dict], cpe_string: str):
        """Сохранение CVE в локальную базу"""
        try:
            conn = sqlite3.connect(self.local_db)
            cursor = conn.cursor()
            
            for cve in cves:
                # Вставляем или обновляем CVE
                cursor.execute('''
                    INSERT OR REPLACE INTO cve_entries 
                    (cve_id, description, cvss_score, cvss_severity, published_date, last_modified, cpe_match, raw_data, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve['cve_id'], cve['description'], cve['cvss_score'],
                    cve['severity'], cve['published_date'], cve['last_modified'],
                    cve['cpe_match'], cve['raw_data'], datetime.now().isoformat()
                ))
                
                # Добавляем CPE соответствие
                cursor.execute('''
                    INSERT OR IGNORE INTO cpe_matches (cve_id, cpe_string)
                    VALUES (?, ?)
                ''', (cve['cve_id'], cpe_string))
            
            # Логируем обновление
            cursor.execute('''
                INSERT INTO update_log (update_type, timestamp, records_processed, status)
                VALUES (?, ?, ?, ?)
            ''', ('cve_update', datetime.now().isoformat(), len(cves), 'success'))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"❌ Ошибка сохранения CVE в базу: {e}")
    
    def update_cve_database(self):
        """Обновление локальной базы CVE"""
        try:
            print("🔄 Начало обновления базы CVE...")
            
            # Здесь можно добавить логику массового обновления
            # Например, обновление для популярных продуктов
            
            popular_products = [
                "cpe:2.3:a:apache:http_server:*",
                "cpe:2.3:a:openssh:openssh:*", 
                "cpe:2.3:a:mysql:mysql:*",
                "cpe:2.3:a:postgresql:postgresql:*",
                "cpe:2.3:a:microsoft:iis:*"
            ]
            
            total_updated = 0
            for product in popular_products:
                cves = self._search_nvd_cve_by_cpe(product)
                total_updated += len(cves)
                time.sleep(1)  # Пауза между запросами
            
            print(f"✅ Обновление завершено. Обработано: {total_updated} CVE")
            return total_updated
            
        except Exception as e:
            print(f"❌ Ошибка обновления базы CVE: {e}")
            return 0
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Получение статистики базы данных"""
        try:
            conn = sqlite3.connect(self.local_db)
            cursor = conn.cursor()
            
            # Количество CVE
            cursor.execute('SELECT COUNT(*) FROM cve_entries')
            cve_count = cursor.fetchone()[0]
            
            # Количество CPE соответствий
            cursor.execute('SELECT COUNT(*) FROM cpe_matches')
            cpe_count = cursor.fetchone()[0]
            
            # Последнее обновление
            cursor.execute('SELECT timestamp FROM update_log ORDER BY id DESC LIMIT 1')
            last_update = cursor.fetchone()
            last_update = last_update[0] if last_update else "Никогда"
            
            conn.close()
            
            return {
                'cve_count': cve_count,
                'cpe_count': cpe_count,
                'last_update': last_update,
                'database_file': self.local_db
            }
            
        except Exception as e:
            print(f"❌ Ошибка получения статистики: {e}")
            return {}
