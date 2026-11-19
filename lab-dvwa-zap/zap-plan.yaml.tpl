# Plan de OWASP ZAP Automation Framework para DVWA (sesion autenticada por cookie).
env:
  contexts:
    - name: dvwa
      urls: ["http://dvwa/"]
      includePaths:
        - "http://dvwa/vulnerabilities/sqli/.*"
        - "http://dvwa/vulnerabilities/xss_r/.*"
        - "http://dvwa/vulnerabilities/xss_d/.*"
        - "http://dvwa/vulnerabilities/authbypass/.*"
        - "http://dvwa/vulnerabilities/exec/.*"
        - "http://dvwa/vulnerabilities/fi/.*"
        - "http://dvwa/index.php"
      excludePaths:                      # no cerrar sesion ni borrar la BD
        - ".*logout.*"
        - ".*setup.*"
        - ".*security.php.*"
        - ".*csrf.*"
  parameters:
    failOnError: true
    progressToStdout: true
jobs:
  - type: replacer
    rules:
      - description: cookie de sesion DVWA
        matchType: req_header
        matchString: Cookie
        replacementString: "__COOKIE__"
  - type: spider
    parameters: {context: dvwa, url: "http://dvwa/vulnerabilities/sqli/", maxDuration: 2}
  - type: requestor
    requests:
      - {url: "http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"}
      - {url: "http://dvwa/vulnerabilities/xss_r/?name=prueba"}
      - {url: "http://dvwa/vulnerabilities/authbypass/get_user_data.php"}
      - {url: "http://dvwa/vulnerabilities/exec/"}
      - {url: "http://dvwa/vulnerabilities/fi/?page=include.php"}
  - type: passiveScan-wait
    parameters: {maxDuration: 2}
  - type: activeScan
    parameters: {context: dvwa, maxScanDurationInMins: 12, threadPerHost: 4}
  - type: report
    parameters: {template: traditional-html, reportDir: /zap/wrk/reportes, reportFile: zap-dvwa.html, reportTitle: "OWASP ZAP - DVWA (Act4)"}
  - type: report
    parameters: {template: traditional-json, reportDir: /zap/wrk/reportes, reportFile: zap-dvwa.json}
  - type: report
    parameters: {template: traditional-md, reportDir: /zap/wrk/reportes, reportFile: zap-dvwa.md}
