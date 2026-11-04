# FTP Credential Checker

Ferramenta em Python para **verificação paralela de credenciais FTP** no formato `HOST:USER:PASS`. Para cada login bem-sucedido, coleta informações do servidor (banner de boas-vindas, diretório atual e primeiros arquivos listados), opcionalmente testa HTTP/HTTPS e detecta **WebRoot provável** — útil para identificar servidores FTP que fazem upload direto no document root de um servidor web.

Projetada para **auditorias de segurança autorizadas**, testes de ambientes controlados e validação de listas de credenciais.

> ⚠️ **Aviso**: Este projeto é destinado exclusivamente a **pesquisa de segurança** e **testes autorizados**. O uso contra servidores sem autorização explícita é ilegal. O autor não se responsabiliza por qualquer uso indevido.

---

## ✨ Funcionalidades

### Verificação FTP
- ⚡ **Verificação paralela** com `ThreadPoolExecutor` (threads configuráveis)
- 🔑 **Autenticação FTP real** via `ftplib` (não apenas teste de conectividade)
- 📋 **Coleta de informações** em logins válidos:
  - Banner de boas-vindas (`getwelcome()`)
  - Diretório atual (`pwd()`)
  - Primeiros 5 arquivos listados (`nlst()`)
- 🔒 **Sem fd leak**: socket FTP sempre fechado via `try/finally`, mesmo em erro

### Checagem web e detecção de WebRoot
- 🌐 **`--check-web`**: após login válido, testa `host:80` (HTTP) e `host:443` (HTTPS)
- 🔁 **Fallback automático**: se o servidor rejeitar `HEAD` (405/501), refaz com `GET` + `Range: bytes=0-0`
- 🎯 **Detecção de WebRoot provável**: correlaciona o `pwd()` do FTP com caminhos comuns de document root (`public_html`, `www`, `htdocs`, `html`, `webroot`, `var/www`, `/web`)
- ♻️ **SSL context reutilizado**: criado uma vez, compartilhado entre todos os hosts

### Logs e saída
- 📝 **`--log`**: arquivo de log de processo separado do arquivo de válidos (`-o`), com timestamp e nível de cada evento
- 📊 **Resumo enriquecido**: entradas na lista, testados, válidos, inválidos, ignorados, tempos total/médio e **top 5 motivos de falha**
- 📈 **Barra de progresso** em tempo real (linha única)
- 🧮 **Contagem de linhas inválidas**: formato errado é contabilizado em `skipped` e logado com o número da linha original
- 🔒 **Escrita thread-safe**: locks separados para estatísticas e para o arquivo de válidos

### Gerais
- 🎨 **Saída colorida** no terminal (verde = válido, vermelho = falha)
- 📁 **Duas formas de entrada** — arquivo (`-f`) ou stdin (`--stdin`)
- 💾 **Exportação de credenciais válidas** para arquivo (`-o`)
- 🔇 **Modo silencioso** (`-q`) para suprimir output no terminal (o log continua gravando)
- 🛡 **Validação de argumentos** — `--threads`, `--timeout` e `--port` checados antes de qualquer tentativa
- 🛡 **Tratamento granular de erros** — credenciais inválidas, timeout, conexão recusada, erros de rede

---

## 📦 Requisitos

Nenhuma dependência externa. Usa apenas a biblioteca padrão do Python 3.8+:

- `ftplib`, `socket`, `ssl`, `http.client`
- `argparse`, `logging`, `threading`, `time`
- `concurrent.futures`, `dataclasses`, `collections`

---

## 🚀 Uso

### Sintaxe geral

```bash
python3 ftp_checker.py \
  -f ARQUIVO \              # entrada por arquivo (obrigatório se não usar --stdin)
  --stdin \                 # entrada por pipe/stdin (obrigatório se não usar -f)
  -t THREADS \              # threads paralelas (padrão: 10)
  -p PORTA \                # porta FTP (padrão: 21)
  --timeout SEGUNDOS \      # timeout de conexão/operação (padrão: 10)
  -o SAIDA \                # arquivo de válidos (padrão: não salva)
  --log LOG \               # arquivo de log de processo (padrão: ftp_checker.log)
  --check-web \             # testa HTTP/HTTPS + WebRoot provável (padrão: off)
  -q                        # modo silencioso: suprime falhas no terminal (padrão: off)
