import requests
import json
import time
from typing import List, Dict, Any

class VulnersIntegration:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://vulners.com/api/v3"
        self.local_cache = {}
        self.request_delay = 1  # Задержка между запросами
    
    def search_vulnerabilities(self, software_name: str, version: str = None) -> List[Dict[str, Any]]:
        """Поиск уязвимостей через Vulners API"""
        cache_key = f"{software_name}_{version if version else 'no_version'}"
        
        # Проверяем кэш
        if cache_key in self.local_cache:
            return self.local_cache[cache_key]
        
        try:
            # Формируем поисковый запрос
            query = self._build_search_query(software_name, version)
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'NetworkSecurityScanner/2.0'
            }
            
            if self.api_key:
                headers['X-Vulners-Api-Key'] = self.api_key
            
            payload = {
                "query": query,
                "size": 15,
                "sort": "published",
                "order": "desc"
            }
            
            print(f"🌐 Запрос к Vulners API: {query}")
            response = requests.post(
                f"{self.base_url}/search/lucene/",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                results = self._parse_vulners_response(response.json())
                self.local_cache[cache_key] = results
                
                # Задержка для соблюдения лимитов API
                time.sleep(self.request_delay)
                
                return results
            else:
                print(f"❌ Ошибка Vulners API: {response.status_code}")
                if response.status_code == 429:
                    print("⚠️ Превышен лимит запросов. Увеличиваем задержку...")
                    self.request_delay = 5
                
                return []
                
        except Exception as e:
            print(f"❌ Ошибка запроса к Vulners API: {e}")
            return []
    
    def _build_search_query(self, software_name: str, version: str = None) -> str:
        """Построение поискового запроса"""
        # Экранируем специальные символы
        software_name = software_name.replace('"', '\\"')
        
        if version:
            version = version.replace('"', '\\"')
            return f'"{software_name}" {version}'
        
        return f'"{software_name}"'
    
    def _parse_vulners_response(self, data: Dict) -> List[Dict[str, Any]]:
        """Парсинг ответа Vulners"""
        vulnerabilities = []
        
        try:
            hits = data.get('data', {}).get('search', [])
            
            for hit in hits:
                vuln_id = hit.get('_id', '')
                source = hit.get('_source', {})
                
                # Базовая информация
                title = source.get('title', '')
                description = source.get('description', '')
                
                # CVSS оценка
                cvss_info = source.get('cvss', {})
                cvss_score = cvss_info.get('score', 0.0)
                
                # Список CVE
                cvelist = source.get('cvelist', [])
                
                vulnerability = {
                    'id': vuln_id,
                    'title': title,
                    'description': description[:500] + '...' if len(description) > 500 else description,
                    'cvss_score': cvss_score,
                    'severity': self._calculate_severity(cvss_score),
                    'published': source.get('published', ''),
                    'type': source.get('type', ''),
                    'bulletinFamily': source.get('bulletinFamily', ''),
                    'href': source.get('href', ''),
                    'cvelist': cvelist,
                    'source': 'vulners'
                }
                
                vulnerabilities.append(vulnerability)
            
            print(f"✅ Vulners: найдено {len(vulnerabilities)} уязвимостей")
            
        except Exception as e:
            print(f"❌ Ошибка парсинга ответа Vulners: {e}")
        
        return vulnerabilities
    
    def _calculate_severity(self, cvss_score: float) -> str:
        """Определение уровня серьезности по CVSS"""
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0:
            return 'LOW'
        else:
            return 'UNKNOWN'
    
    def get_software_vulnerabilities(self, software_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Поиск уязвимостей для программного обеспечения"""
        vulnerabilities = []
        
        # Пробуем разные комбинации для поиска
        search_attempts = []
        
        if software_data.get('product'):
            search_attempts.append(software_data['product'])
        
        if software_data.get('service_name'):
            search_attempts.append(software_data['service_name'])
        
        if software_data.get('version'):
            # Поиск с версией
            for term in search_attempts:
                vulns = self.search_vulnerabilities(term, software_data['version'])
                vulnerabilities.extend(vulns)
        
        # Поиск без версии (более общий)
        for term in search_attempts:
            vulns = self.search_vulnerabilities(term)
            vulnerabilities.extend(vulns)
        
        # Убираем дубликаты
        seen_ids = set()
        unique_vulnerabilities = []
        
        for vuln in vulnerabilities:
            if vuln['id'] not in seen_ids:
                seen_ids.add(vuln['id'])
                unique_vulnerabilities.append(vuln)
        
        return unique_vulnerabilities
    
    def clear_cache(self):
        """Очистка кэша"""
        self.local_cache.clear()
        print("✅ Кэш Vulners очищен")
