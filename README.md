# Capstone-Topics-On-Security

## 파일에 포함된 주요 내용:
*   **70가지 보안 프로젝트**: 초급부터 고급까지의 실습 로드맵
*   **GitHub 프로젝트 카테고리별 분류**: DFIR(포렌식), Offensive(공격), Defensive(방어/SIEM), AI 보안 등
*   **최신 보안 위협 (2025)**: 금융 보안 SW 취약점, AI 기반 랜섬웨어 등 최신 리포트 링크
*   **보안 도구 및 명령어**: SIEM 도구 목록, 멀웨어 분석 샌드박스, 리눅스 로그 처리 및 Nmap 명령어 요약
*   **학습 리소스**: CTF 플랫폼, 보안 검색 엔진 및 교육 채널 정보

### 1. 디지털 포렌식 및 침해 사고 대응 (DFIR)
*   **LAP (Linux Artifact Parser):** [https://github.com/linuxartifactparser/LAP](https://github.com/linuxartifactparser/LAP)
    *   Velociraptor, GRR 등으로 수집된 리눅스 아티팩트를 분석하는 GUI 도구.
*   **LEAF (Linux Evidence Acquisition Framework):** [https://github.com/alex-cart/LEAF](https://github.com/alex-cart/LEAF)
    *   Linux EXT4 시스템에서 증거 및 아티팩트를 수집하는 프레임워크.
*   **WELA (Windows Event Log Analyzer):** [https://github.com/Yamato-Security/WELA](https://github.com/Yamato-Security/WELA)
    *   윈도우 이벤트 로그를 분석하는 도구.
*   **Windows Forensics Projects for Beginners:** [https://github.com/0xrajneesh/Windows-Forensics-Projects-for-Beginners](https://github.com/0xrajneesh/Windows-Forensics-Projects-for-Beginners)
    *   초보자를 위한 실습 위주의 윈도우 포렌식 프로젝트 모음.
*   **DFIR LABS:** [https://github.com/Azr43lKn1ght/DFIR-LABS](https://github.com/Azr43lKn1ght/DFIR-LABS)
    *   포렌식, 침해 사고 대응, 멀웨어 분석, 위협 헌팅 관련 챌린지 모음.
*   **Offensive Security Forensics Portfolio:** [https://github.com/thieveshkar/Offensive-Security-Forensics-Portfolio](https://github.com/thieveshkar/Offensive-Security-Forensics-Portfolio)
    *   MFA 구현, Volatility 메모리 포렌식, Splunk 위협 헌팅 등 고급 보안 스킬 포트폴리오.
*   **Awesome Forensics:** [https://github.com/cugu/awesome-forensics](https://github.com/cugu/awesome-forensics)
    *   포렌식 관련 도구 및 리소스 큐레이션 목록.
*   **The Sleuth Kit & Autopsy:** [https://github.com/sleuthkit](https://github.com/sleuthkit) (디스크 이미지 분석 및 디지털 증거 복구용 도구)
*   **Volatility:** [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) (RAM 내 디지털 흔적 수집용 분석 체계)

---

### 2. 취약점 점검 및 모의해킹 (Offensive Security)
*   **SpiderSuite:** [https://github.com/spidersuite/SpiderSuite](https://github.com/spidersuite/SpiderSuite)
    *   보안 전문가를 위한 멀티 기능 웹 크롤러 및 분석 도구.
*   **Medusa:** [https://github.com/jmk-foofus/medusa](https://github.com/jmk-foofus/medusa)
    *   SSH, FTP, HTTP 등 다양한 서비스를 지원하는 병렬 로그인 무차별 대입(Brute-forcer) 도구.
*   **MS-RPC-Fuzzer:** [https://github.com/warpnet/MS-RPC-Fuzzer](https://github.com/warpnet/MS-RPC-Fuzzer)
    *   MS-RPC 구현체의 취약점을 찾기 위한 자동화된 퍼징 도구.
*   **Shellcode-IDE:** [https://github.com/CX330Blake/Shellcode-IDE](https://github.com/CX330Blake/Shellcode-IDE)
    *   쉘코드 개발 및 분석을 편리하게 돕는 IDE 환경.
*   **Awesome Korean Products Hacking:** [https://github.com/kaist-hacking/awesome-korean-products-hacking](https://github.com/kaist-hacking/awesome-korean-products-hacking)
    *   한국 내 주요 소프트웨어 및 제품에 대한 해킹/취약점 연구 모음.
*   **SQLMap:** [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) (자동화된 SQL 인젝션 취약점 탐지 및 공격 도구)
*   **Metasploit Framework:** [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) (침투 테스트 및 익스플로잇 개발용 표준 프레임워크)
*   **OWASP ZAP:** [https://github.com/zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) (웹 애플리케이션 취약점 스캔 및 분석 오픈소스 도구)

---

### 3. 멀웨어 분석 및 샌드박스 (Malware Analysis)
*   **CAPEv2:** [https://github.com/kevoreilly/CAPEv2](https://github.com/kevoreilly/CAPEv2) (자동화된 악성코드 분석 및 구성 정보 추출 샌드박스)
*   **Cuckoo Sandbox:** [https://github.com/cuckoosandbox/cuckoo](https://github.com/cuckoosandbox/cuckoo) (오픈소스 기반 자동화 악성코드 동적 분석 시스템)
*   **DRAKVUF:** [https://github.com/tklengyel/drakvuf](https://github.com/tklengyel/drakvuf) (하이퍼바이저 기반 에이전트리스 악성코드 동적 분석 도구)
*   **Viper:** [https://github.com/viper-framework/viper](https://github.com/viper-framework/viper) (악성코드 샘플 체계적 관리 및 정적 분석 프레임워크)
*   **Viper Monkey:** [https://github.com/decalage2/ViperMonkey](https://github.com/decalage2/ViperMonkey) (VBA 매크로 분석)
*   **Manalyzer:** [https://github.com/justice-it/manalyzer](https://github.com/justice-it/manalyzer) (윈도우 PE 파일 실행 코드 및 구조 분석 도구)

---

### 4. Static Source Code Analysis (SAST)
* **[CodeQL](https://github.com/github/codeql)**: 시맨틱 분석 기반 취약점 탐지 엔진
* **[Semgrep](https://github.com/semgrep/semgrep)**: 규칙 기반 다중언어 정적 분석기
* **[CodeSonar](https://www.codesecure.com/products/codesonar)**: 데이터흐름 분석 기반 상용 SAST
* **[Joern](https://github.com/joernio/joern)**: 코드 속성 그래프 기반 분석 플랫폼
* **[PMD](https://github.com/pmd/pmd)**: 코드 품질·결함 탐지 정적 분석
  
---

### 5. Binary Analysis
* **[Ghidra](https://github.com/NationalSecurityAgency/ghidra)**: 리버스 엔지니어링·바이너리 분석 도구

---

### 6. 방어 보안 및 SIEM (Defensive / SIEM)
*   **Wazuh:** [https://github.com/wazuh/wazuh](https://github.com/wazuh/wazuh)
    *   오픈소스 XDR 및 SIEM 플랫폼.
*   **MozDef (Mozilla Defense Platform):** [https://github.com/mozilla/MozDef](https://github.com/mozilla/MozDef)
    *   마이크로서비스 기반의 SIEM 솔루션.
*   **MISP (Malware Information Sharing Platform):** [https://github.com/MISP/MISP](https://github.com/MISP/MISP)
    *   위협 인텔리전스 공유 및 분석 플랫폼.
*   **Snort:** [https://github.com/snort3/snort3](https://github.com/snort3/snort3) (실시간 패킷 분석 기반 네트워크 침입 탐지 시스템)
*   **Suricata:** [https://github.com/OISF/suricata](https://github.com/OISF/suricata) (고성능 패킷 분석 및 침입 방지 시스템 IPS)

### 7. Phishing Analysis
* **[ThePhish](https://github.com/emalderson/ThePhish)**: 피싱 메일 자동 분석·대응 플랫폼
* **[PhishTool](https://github.com/criggs6/PhishTool)**: 피싱 이메일 아티팩트 추출·분석

---

### 8. Ransomware Detection
* **[PE-Sieve](https://github.com/hasherezade/pe-sieve)**: 프로세스 메모리 스캔·페이로드 탐지
* **[RansomWatch](https://github.com/joshhighet/ransomwatch)**: 랜섬웨어 유출 사이트 모니터링
* **[Honeybits](https://github.com/0x4D31/honeybits)**: 허니파일로 암호화 행위 조기탐지
* **[CryptoKill](https://github.com/v-p-b/CryptoKill)**: 암호화 징후 시 프로세스 강제종료
* **[Loki](https://github.com/Neo23x0/Loki)**: IOC 기반 랜섬웨어·악성코드 스캐너
* **[RansomCheck](https://github.com/Tylous/RansomCheck)**: 파일 랜섬웨어 감염 여부 확인

---

### 9. AI 및 자동화 (AI & Automation)
*   **NMAP-AI:** [https://github.com/yashab-cyber/nmap-ai](https://github.com/yashab-cyber/nmap-ai)
    *   AI 기반 네트워크 스캐닝 자동화 및 지능형 스크립트 생성 플랫폼.
*   **chandra:** [https://github.com/datalab-to/chandra](https://github.com/datalab-to/chandra)
    *   복잡한 문서(필기, 표, 수식 등) 분석을 위한 OCR 모델.
*   **XBOW Validation Benchmarks:** [https://github.com/xbow-engineering/validation-benchmarks/](https://github.com/xbow-engineering/validation-benchmarks/)
    *   AI 보안 성능 검증을 위한 벤치마크 데이터셋.

---

### 10. 기타 스크립트 및 도구 모음
*   **PowerShell Security Scripts:** [https://github.com/Am0rphous/PowerShell](https://github.com/Am0rphous/PowerShell)
    *   보안 관리, Blue/Red Team을 위한 다양한 PowerShell 스크립트 모음.
*   **GoPhish:** [https://github.com/gophish/gophish](https://github.com/gophish/gophish) (오픈소스 피싱 시뮬레이션 및 캠페인 관리 프레임워크)
*   **Lynis:** [https://github.com/CISOfy/lynis](https://github.com/CISOfy/lynis) (시스템 보안 취약점 진단 및 감사 도구)
*   **CyberChef:** [https://github.com/gchq/CyberChef](https://github.com/gchq/CyberChef) (데이터 인코딩, 디코딩 및 변환을 위한 웹 도구)

* 
