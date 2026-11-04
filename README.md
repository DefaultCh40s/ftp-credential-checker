# ftp-credential-checker
Verificador paralelo de credenciais FTP em Python. Testa listas HOST:USER:PASS, coleta banner/PWD/arquivos dos logins válidos, opcionalmente testa HTTP/HTTPS com fallback HEAD→GET e detecta WebRoot provável. Separa log de processo do arquivo de válidos, com threads, porta e timeout configuráveis.
