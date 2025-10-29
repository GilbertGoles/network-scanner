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
                    'description': 'Backdoor command execution in VSFTPD version 2.3.4',
                    'cvss_score': 9.3,
                    'severity': 'CRITICAL',
                    'published': '2011-07-05',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2011-2523',
                    'cvelist': ['CVE-2011-2523'],
                    'source': 'vulners_fallback'
                }
            ],
            'proftpd': [
                {
                    'id': 'CVE-2015-3456',
                    'title': 'ProFTPD Mod_copy Vulnerability',
                    'description': 'Remote code execution in ProFTPD with mod_copy',
                    'cvss_score': 9.8,
                    'severity': 'CRITICAL',
                    'published': '2015-05-13',
                    'type': 'cve',
                    'bulletinFamily': 'NVD',
                    'href': 'https://nvd.nist.gov/vuln/detail/CVE-2015-3456',
                    'cvelist': ['CVE-2015-3456'],
                    'source': 'vulners_fallback'
                }
            ]
        }
        
        print("✅ VulnersIntegration инициализирован")
    
    def search_vulnerabilities(self, software_name: str, version: str = None) -> List[Dict[str, Any]]:
        """Поиск уязвимостей для программного обеспечения"""
        print(f"🔍 Vulners: поиск уязвимостей для {software_name} {version if version else ''}")
        
        # Проверяем кэш
        cache_key = f"{software_name}_{version}" if version else software_name
        if cache_key in self.local_cache:
            print(f"✅ Найдено в кэше: {len(self.local_cache[cache_key])} уязвимостей")
            return self.local_cache[cache_key]
        
        # Пробуем API Vulners
        api_results = self._search_vulners_api(software_name, version)
        if api_results:
            self.local_cache[cache_key] = api_results
            return api_results
        
        # Fallback на тестовые данные
        fallback_results = self._get_fallback_vulnerabilities(software_name, version)
        if fallback_results:
            self.local_cache[cache_key] = fallback_results
            return fallback_results
        
        print(f"⚠️ Уязвимости не найдены для {software_name}")
        return []
    
    def _search_vulners_api(self, software_name: str, version: str = None) -> List[Dict[str, Any]]:
        """Поиск через Vulners API"""
        try:
            # Формируем поисковый запрос
            search_query = software_name.lower()
            if version:
                search_query += f" {version}"
            
            print(f"🌐 Запрос к Vulners API: {search_query}")
            
            # Эмуляция API запроса (в реальности нужен API ключ)
            time.sleep(self.request_delay)
            
            # В реальном приложении здесь будет:
            # headers = {'User-Agent': 'NetworkScanner/2.0'}
            # params = {'apiKey': self.api_key, 'query': search_query}
            # response = requests.get(f"{self.base_url}/search/lucene", headers=headers, params=params)
            
            # Для демонстрации возвращаем пустой список
            # В реальном приложении нужно раскомментировать код выше и добавить обработку ответа
            
            return []
            
        except Exception as e:
            print(f"❌ Ошибка Vulners API: {e}")
            return []
    
    def _get_fallback_vulnerabilities(self, software_name: str, version: str = None) -> List[Dict[str, Any]]:
        """Получение тестовых уязвимостей"""
        software_lower = software_name.lower()
        
        # Поиск по ключевым словам
        for keyword, vulnerabilities in self.test_vulnerabilities.items():
            if keyword in software_lower:
                print(f"✅ Найдено тестовых уязвимостей: {len(vulnerabilities)}")
                return vulnerabilities
        
        # Общие уязвимости для неизвестного ПО
        general_vulns = [
            {
                'id': 'CVE-2021-44228',
                'title': 'Log4Shell Remote Code Execution',
                'description': 'Apache Log4j2 Remote Code Execution Vulnerability',
                'cvss_score': 10.0,
                'severity': 'CRITICAL',
                'published': '2021-12-09',
                'type': 'cve',
                'bulletinFamily': 'NVD',
                'href': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
                'cvelist': ['CVE-2021-44228'],
                'source': 'vulners_fallback'
            },
            {
                'id': 'CVE-2022-22965',
                'title': 'Spring4Shell Remote Code Execution',
                'description': 'Spring Framework Remote Code Execution via Data Binding',
                'cvss_score': 9.8,
                'severity': 'CRITICAL',
                'published': '2022-03-31',
                'type': 'cve',
                'bulletinFamily': 'NVD',
                'href': 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965',
                'cvelist': ['CVE-2022-22965'],
                'source': 'vulners_fallback'
            }
        ]
        
        print(f"✅ Используем общие тестовые уязвимости: {len(general_vulns)}")
        return general_vulns
    
    def get_software_suggestions(self, banner: str) -> List[str]:
        """Получение предположений о ПО на основе баннера"""
        suggestions = []
        banner_lower = banner.lower()
        
        # Определение ПО по баннеру
        software_patterns = {
            'apache': ['apache', 'httpd'],
            'nginx': ['nginx'],
            'iis': ['microsoft-iis', 'iis'],
            'openssh': ['openssh', 'ssh-2.0'],
            'vsftpd': ['vsftpd'],
            'proftpd': ['proftpd'],
            'mysql': ['mysql'],
            'postgresql': ['postgresql'],
            'tomcat': ['apache-tomcat', 'tomcat'],
            'wordpress': ['wordpress'],
            'joomla': ['joomla'],
            'drupal': ['drupal']
        }
        
        for software, patterns in software_patterns.items():
            for pattern in patterns:
                if pattern in banner_lower:
                    suggestions.append(software)
                    break
        
        return suggestions if suggestions else ['unknown']
    
    def get_vulnerability_stats(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Статистика по уязвимостям"""
        stats = {
            'total': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0,
            'max_cvss': 0.0,
            'average_cvss': 0.0
        }
        
        total_score = 0.0
        scored_vulns = 0
        
        for vuln in vulnerabilities:
            score = vuln.get('cvss_score', 0)
            severity = vuln.get('severity', 'UNKNOWN').upper()
            
            # Подсчет по severity
            if severity == 'CRITICAL':
                stats['critical'] += 1
            elif severity == 'HIGH':
                stats['high'] += 1
            elif severity == 'MEDIUM':
                stats['medium'] += 1
            elif severity == 'LOW':
                stats['low'] += 1
            else:
                stats['unknown'] += 1
            
            # Статистика CVSS
            if score > 0:
                stats['max_cvss'] = max(stats['max_cvss'], score)
                total_score += score
                scored_vulns += 1
        
        # Средний CVSS
        if scored_vulns > 0:
            stats['average_cvss'] = round(total_score / scored_vulns, 1)
        
        return stats
    
    def filter_vulnerabilities(self, vulnerabilities: List[Dict], 
                             min_severity: str = None, 
                             min_cvss: float = None) -> List[Dict]:
        """Фильтрация уязвимостей по severity и CVSS"""
        filtered = vulnerabilities
        
        if min_severity:
            severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
            min_level = severity_order.get(min_severity.upper(), 0)
            
            filtered = [v for v in filtered 
                       if severity_order.get(v.get('severity', '').upper(), 0) >= min_level]
        
        if min_cvss is not None:
            filtered = [v for v in filtered 
                       if v.get('cvss_score', 0) >= min_cvss]
        
        return filtered
    
    def get_exploit_info(self, vulnerability_id: str) -> Dict[str, Any]:
        """Получение информации об эксплойтах для уязвимости"""
        # Тестовые данные об эксплойтах
        exploit_db = {
            'CVE-2021-41773': {
                'exploits': [
                    {
                        'title': 'Apache 2.4.49 Path Traversal Exploit',
                        'type': 'remote',
                        'platform': 'linux',
                        'port': 80,
                        'difficulty': 'easy',
                        'reliability': 'high',
                        'source': 'exploit_db'
                    }
                ],
                'metasploit_modules': [
                    'auxiliary/scanner/http/apache_normalize_path'
                ]
            },
            'CVE-2019-0708': {
                'exploits': [
                    {
                        'title': 'BlueKeep RDP Exploit',
                        'type': 'remote',
                        'platform': 'windows',
                        'port': 3389,
                        'difficulty': 'hard',
                        'reliability': 'medium',
                        'source': 'exploit_db'
                    }
                ],
                'metasploit_modules': [
                    'exploit/windows/rdp/cve_2019_0708_bluekeep_rce'
                ]
            },
            'CVE-2017-0143': {
                'exploits': [
                    {
                        'title': 'EternalBlue SMB Exploit',
                        'type': 'remote',
                        'platform': 'windows',
                        'port': 445,
                        'difficulty': 'medium',
                        'reliability': 'high',
                        'source': 'exploit_db'
                    }
                ],
                'metasploit_modules': [
                    'exploit/windows/smb/ms17_010_eternalblue'
                ]
            }
        }
        
        return exploit_db.get(vulnerability_id, {
            'exploits': [],
            'metasploit_modules': []
        })
    
    def clear_cache(self):
        """Очистка кэша"""
        self.local_cache.clear()
        print("✅ Кэш Vulners очищен")


# Тестирование модуля
if __name__ == "__main__":
    def test_vulners_integration():
        """Тестирование VulnersIntegration"""
        print("🧪 Тестирование VulnersIntegration...")
        
        vulners = VulnersIntegration()
        
        # Тест поиска уязвимостей
        test_software = [
            ("Apache HTTP Server", "2.4.49"),
            ("OpenSSH", "7.4"),
            ("VSFTPD", "2.3.4"),
            ("Unknown Software", "1.0")
        ]
        
        for software, version in test_software:
            print(f"\n🔍 Тест для {software} {version}:")
            vulnerabilities = vulners.search_vulnerabilities(software, version)
            
            if vulnerabilities:
                stats = vulners.get_vulnerability_stats(vulnerabilities)
                print(f"   📊 Статистика: {stats['total']} уязвимостей")
                print(f"   🎯 Критические: {stats['critical']}, Высокие: {stats['high']}")
                print(f"   📈 Max CVSS: {stats['max_cvss']}, Средний: {stats['average_cvss']}")
                
                # Показываем топ-3 уязвимости
                for i, vuln in enumerate(vulnerabilities[:3]):
                    print(f"   {i+1}. {vuln['id']}: {vuln['severity']} ({vuln['cvss_score']}) - {vuln['title']}")
            else:
                print("   ⚠️ Уязвимости не найдены")
        
        # Тест фильтрации
        print("\n🎛️ Тест фильтрации:")
        all_vulns = vulners.search_vulnerabilities("apache")
        filtered = vulners.filter_vulnerabilities(all_vulns, min_severity="HIGH", min_cvss=7.0)
        print(f"   Всего: {len(all_vulns)}, После фильтра: {len(filtered)}")
        
        # Тест эксплойтов
        print("\n💥 Тест информации об эксплойтах:")
        test_cves = ['CVE-2021-41773', 'CVE-2019-0708', 'CVE-2017-0143']
        for cve in test_cves:
            exploit_info = vulners.get_exploit_info(cve)
            print(f"   {cve}: {len(exploit_info['exploits'])} эксплойтов, {len(exploit_info['metasploit_modules'])} модулей Metasploit")
        
        print("\n✅ Тестирование завершено!")

    # Запуск тестов
    test_vulners_integration()
