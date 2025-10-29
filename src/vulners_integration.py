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
        
        # Тестовые данные для fallback
        self.test_vulnerabilities = {
            'apache': [
                {
                    'id': 'CVE-2021-41773',
                    'title': 'Apache Path Traversal',
                    'description': 'Path traversal vulnerability in Apache HTTP Server 2.4.49',
                    'cvss_score': 7.5,
                    'severity': 'HIGH',
                    'published': '2021-10-05',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
                    'cvelist': ['CVE-2021-41773'],
                    'source': 'vulners_fallback'
                },
                {
                    'id': 'CVE-2021-42013',
                    'title': 'Apache Path Traversal RCE',
                    'description': 'Path traversal and remote code execution in Apache HTTP Server 2.4.50',
                    'cvss_score': 9.8,
                    'severity': 'CRITICAL',
                    'published': '2021-10-07',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013',
                    'cvelist': ['CVE-2021-42013'],
                    'source': 'vulners_fallback'
                }
            ],
            'openssh': [
                {
                    'id': 'CVE-2016-6515',
                    'title': 'OpenSSH Denial of Service',
                    'description': 'Buffer overflow in OpenSSH before 7.3',
                    'cvss_score': 7.5,
                    'severity': 'HIGH',
                    'published': '2016-08-07',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2016-6515',
                    'cvelist': ['CVE-2016-6515'],
                    'source': 'vulners_fallback'
                },
                {
                    'id': 'CVE-2017-15906',
                    'title': 'OpenSSH Memory Corruption',
                    'description': 'Memory corruption in OpenSSH before 7.6',
                    'cvss_score': 8.1,
                    'severity': 'HIGH',
                    'published': '2017-10-26',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2017-15906',
                    'cvelist': ['CVE-2017-15906'],
                    'source': 'vulners_fallback'
                }
            ],
            'android': [
                {
                    'id': 'CVE-2023-35674',
                    'title': 'Android Framework Privilege Escalation',
                    'description': 'Privilege escalation vulnerability in Android Framework',
                    'cvss_score': 8.8,
                    'severity': 'HIGH',
                    'published': '2023-12-06',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2023-35674',
                    'cvelist': ['CVE-2023-35674'],
                    'source': 'vulners_fallback'
                }
            ],
            'windows': [
                {
                    'id': 'CVE-2019-0708',
                    'title': 'BlueKeep RDP Vulnerability',
                    'description': 'Remote Desktop Services Remote Code Execution Vulnerability',
                    'cvss_score': 9.8,
                    'severity': 'CRITICAL',
                    'published': '2019-05-14',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708',
                    'cvelist': ['CVE-2019-0708'],
                    'source': 'vulners_fallback'
                }
            ],
            'microsoft': [
                {
                    'id': 'CVE-2017-0143',
                    'title': 'EternalBlue SMB Vulnerability',
                    'description': 'Windows SMBv1 Remote Code Execution Vulnerability',
                    'cvss_score': 9.3,
                    'severity': 'CRITICAL',
                    'published': '2017-03-14',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2017-0143',
                    'cvelist': ['CVE-2017-0143'],
                    'source': 'vulners_fallback'
                }
            ],
            'nginx': [
                {
                    'id': 'CVE-2021-23017',
                    'title': 'NGINX DNS Resolver Vulnerability',
                    'description': 'DNS resolver vulnerability in NGINX before 1.20.1',
                    'cvss_score': 7.5,
                    'severity': 'HIGH',
                    'published': '2021-05-25',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017',
                    'cvelist': ['CVE-2021-23017'],
                    'source': 'vulners_fallback'
                }
            ],
            'vsftpd': [
                {
                    'id': 'CVE-2011-2523',
                    'title': 'VSFTPD Backdoor Vulnerability',
                    'description': 'Backdoor command execution in VSFTPD 2.3.4',
                    'cvss_score': 9.3,
                    'severity': 'CRITICAL',
                    'published': '2011-07-05',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2011-2523',
                    'cvelist': ['CVE-2011-2523'],
                    'source': 'vulners_fallback'
                }
            ]
        }
        
        print("✅ VulnersIntegration инициализирован")
        if api_key:
            print("🔑 API ключ Vulners.com установлен")
        else:
            print("⚠️ API ключ Vulners.com не установлен, используется публичный доступ")
    
    def search_vulnerabilities(self, software_name: str, version: str = None) -> List[Dict[str, Any]]:
        """Поиск уязвимостей через Vulners API с fallback на тестовые данные"""
        cache_key = f"{software_name}_{version if version else 'no_version'}"
        
        # Проверяем кэш
        if cache_key in self.local_cache:
            print(f"📦 Используем кэшированные данные для: {software_name}")
            return self.local_cache[cache_key]
        
        # Пытаемся получить данные из API
        api_results = self._search_vulners_api(software_name, version)
        if api_results:
            self.local_cache[cache_key] = api_results
            return api_results
        
        # Если API не доступен, используем тестовые данные
        print(f"🌐 Vulners API недоступен, используем тестовые данные для: {software_name}")
        fallback_results = self._get_fallback_vulnerabilities(software_name, version)
        self.local_cache[cache_key] = fallback_results
        return fallback_results
    
    def _search_vulners_api(self, software_name: str, version: str = None) -> List[Dict[str, Any]]:
        """Поиск уязвимостей через Vulners API"""
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
                
                # Задержка для соблюдения лимитов API
                time.sleep(self.request_delay)
                
                if results:
                    print(f"✅ Vulners API: найдено {len(results)} уязвимостей для {software_name}")
                else:
                    print(f"ℹ️ Vulners API: уязвимостей не найдено для {software_name}")
                
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
                    'source': 'vulners_api'
                }
                
                vulnerabilities.append(vulnerability)
            
        except Exception as e:
            print(f"❌ Ошибка парсинга ответа Vulners: {e}")
        
        return vulnerabilities
    
    def _get_fallback_vulnerabilities(self, software_name: str, version: str = None) -> List[Dict[str, Any]]:
        """Получение тестовых уязвимостей при недоступности API"""
        software_lower = software_name.lower()
        
        # Ищем точное совпадение
        for key, vulnerabilities in self.test_vulnerabilities.items():
            if key in software_lower:
                print(f"📋 Используем тестовые данные для: {key}")
                
                # Фильтруем по версии если указана
                if version:
                    filtered_vulns = []
                    for vuln in vulnerabilities:
                        # Проверяем совпадение версии в описании
                        if version in vuln.get('description', ''):
                            filtered_vulns.append(vuln)
                    
                    if filtered_vulns:
                        return filtered_vulns
                
                return vulnerabilities
        
        # Если точного совпадения нет, ищем частичное
        for key, vulnerabilities in self.test_vulnerabilities.items():
            if any(word in software_lower for word in key.split()):
                print(f"📋 Используем тестовые данные по ключу: {key}")
                return vulnerabilities
        
        # Общие уязвимости для любого ПО
        print(f"📋 Используем общие тестовые данные")
        return [
            {
                'id': 'CVE-2021-44228',
                'title': 'Log4Shell Remote Code Execution',
                'description': 'Apache Log4j2 remote code execution vulnerability',
                'cvss_score': 10.0,
                'severity': 'CRITICAL',
                'published': '2021-12-09',
                'type': 'cve',
                'bulletinFamily': 'NVD',
                'href': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
                'cvelist': ['CVE-2021-44228'],
                'source': 'vulners_fallback'
            }
        ]
    
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
        search_terms = []
        
        if software_data.get('product'):
            search_terms.append(software_data['product'])
        
        if software_data.get('service_name'):
            search_terms.append(software_data['service_name'])
        
        # Добавляем ключевые слова из описания
        if software_data.get('version'):
            search_terms.append(software_data['version'])
        
        # Убираем дубликаты и пустые строки
        search_terms = list(set([term for term in search_terms if term]))
        
        print(f"🔍 Поиск уязвимостей для: {', '.join(search_terms)}")
        
        # Поиск с версией
        if software_data.get('version'):
            for term in search_terms:
                vulns = self.search_vulnerabilities(term, software_data['version'])
                vulnerabilities.extend(vulns)
        
        # Поиск без версии (более общий)
        for term in search_terms:
            vulns = self.search_vulnerabilities(term)
            vulnerabilities.extend(vulns)
        
        # Убираем дубликаты по ID
        seen_ids = set()
        unique_vulnerabilities = []
        
        for vuln in vulnerabilities:
            if vuln['id'] not in seen_ids:
                seen_ids.add(vuln['id'])
                unique_vulnerabilities.append(vuln)
        
        print(f"✅ Найдено уникальных уязвимостей: {len(unique_vulnerabilities)}")
        
        return unique_vulnerabilities
    
    def clear_cache(self):
        """Очистка кэша"""
        cache_size = len(self.local_cache)
        self.local_cache.clear()
        print(f"🧹 Кэш Vulners очищен. Удалено записей: {cache_size}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Получение статистики кэша"""
        return {
            'cache_entries': len(self.local_cache),
            'test_vulnerabilities_count': sum(len(vulns) for vulns in self.test_vulnerabilities.values()),
            'request_delay': self.request_delay,
            'api_configured': bool(self.api_key)
        }
    
    def search_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Поиск информации по конкретному CVE"""
        # Сначала проверяем тестовые данные
        for vulnerabilities in self.test_vulnerabilities.values():
            for vuln in vulnerabilities:
                if vuln['id'] == cve_id:
                    return [vuln]
        
        # Пытаемся найти через API
        try:
            query = f'"{cve_id}"'
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'NetworkSecurityScanner/2.0'
            }
            
            if self.api_key:
                headers['X-Vulners-Api-Key'] = self.api_key
            
            payload = {
                "query": query,
                "size": 5,
                "sort": "published",
                "order": "desc"
            }
            
            response = requests.post(
                f"{self.base_url}/search/lucene/",
                headers=headers,
                json=payload,
                timeout=20
            )
            
            if response.status_code == 200:
                return self._parse_vulners_response(response.json())
            else:
                print(f"❌ Ошибка поиска CVE {cve_id}: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Ошибка поиска CVE {cve_id}: {e}")
        
        return []


# Тестирование модуля
if __name__ == "__main__":
    def test_vulners_integration():
        """Тестирование VulnersIntegration"""
        print("🧪 Тестирование VulnersIntegration...")
        
        # Тест без API ключа
        vulners = VulnersIntegration()
        
        print("\n🔍 Тест поиска уязвимостей:")
        test_software = [
            "Apache HTTP Server",
            "OpenSSH",
            "Android",
            "Unknown Software"
        ]
        
        for software in test_software:
            print(f"\n📋 Поиск для: {software}")
            results = vulners.search_vulnerabilities(software, "2.4.49")
            print(f"   Найдено: {len(results)} уязвимостей")
            for vuln in results[:2]:  # Показываем первые 2
                print(f"   - {vuln['id']}: {vuln['severity']} ({vuln['cvss_score']})")
        
        print("\n🔍 Тест поиска по данным ПО:")
        software_data = {
            'product': 'Apache',
            'service_name': 'http',
            'version': '2.4.49'
        }
        results = vulners.get_software_vulnerabilities(software_data)
        print(f"   Найдено: {len(results)} уязвимостей")
        
        print("\n🔍 Тест поиска по CVE:")
        cve_results = vulners.search_by_cve("CVE-2021-41773")
        print(f"   Найдено: {len(cve_results)} записей")
        
        print("\n📊 Статистика кэша:")
        stats = vulners.get_cache_stats()
        for key, value in stats.items():
            print(f"   {key}: {value}")
        
        print("\n🧹 Очистка кэша:")
        vulners.clear_cache()
        
        print("\n✅ Тестирование завершено!")
    
    # Запуск тестов
    test_vulners_integration()
