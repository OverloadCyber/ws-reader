# ws-reader

Leitor de WebSocket dinamico (ws:// / wss://) - Delfia.

- `ws-reader.html` - cliente para navegador (sem dependencias)
- `ws-reader.ps1` - cliente para PowerShell 5.1+ / 7+
- `mitm-ws-log.py` - addon do mitmproxy p/ capturar HTTP + WebSocket do navegador
  (requests/responses com corpo JSON, handshake e frames com Socket.IO decodificado).
  Use quando nao souber qual cookie/auth/inscricao o navegador manda - mostra tudo.

## PowerShell
```powershell
.\ws-reader.ps1 -Url wss://echo.websocket.org
```

## Navegador
Abra `ws-reader.html` e cole a URL wss://. Campos: subprotocolo e
"mensagens ao conectar" (replica as inscrições do navegador, ex: `42["subscribe","sala-x"]`).

## Lendo com os dados da request
Pegue a conexão no DevTools (Network → WS) e replique o handshake:

- **Headers de auth** (`Cookie`, `Authorization`, `Origin`) → use o `.ps1` com `-Header`,
  pois a API WebSocket do navegador não permite setar headers. Ex:
  ```powershell
  .\ws-reader.ps1 -Url "wss://api.exemplo.com/ws" -Header "Cookie: session=abc" -Header "Origin: https://app.exemplo.com"
  ```
- **No navegador**: cookies só vão se a página for do mesmo domínio do WS; para token use
  `?token=…` na URL ou o subprotocolo.

## Capturando tudo com o mitmproxy (quando não se sabe o auth)

Em vez de caçar o frame no DevTools, deixe um proxy interceptar o navegador:

1. Instale o mitmproxy (https://mitmproxy.org/downloads ou `pip install mitmproxy`).
2. Rode o proxy só p/ o host de interesse (sem ruído de outros sites):
   ```powershell
   mitmdump --listen-port 8881 --allow-hosts "cx\.netscout\.com" --set termlog_verbosity=warn -s mitm-ws-log.py
   ```
   - `--allow-hosts` faz interceptar APENAS esse host; o resto passa direto.
   - `--set termlog_verbosity=warn` silencia as linhas de connect/disconnect do mitmproxy.
3. Aponte o navegador (ou o Windows) para o proxy `127.0.0.1:8881`.
4. Instale o certificado do mitmproxy (necessário p/ `https`/`wss`):
   ```powershell
   certutil -addstore -f "ROOT" "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
   ```
   (ou abra `http://mitm.it` no navegador e instale manualmente). Reabra o navegador.
5. Acesse o site — o terminal mostra requests/responses HTTP (com corpo JSON) e os
   frames WebSocket com Socket.IO decodificado (CONNECT/EVENT/ACK). Dali você copia o
   auth e os dados para usar no `ws-reader.ps1`.

### Deixar o Claude Code analisar a captura

Grave tudo num arquivo com `--set capfile=captura.log`:
```powershell
mitmdump --listen-port 8881 --allow-hosts "cx\.netscout\.com" --set termlog_verbosity=warn --set capfile=captura.log -s mitm-ws-log.py
```
Depois rode o Claude Code (CLI) na mesma pasta e peça, por exemplo:
"analise o captura.log e me diga qual é o payload de auth do socket.io e o que cada
evento significa". Ele lê o arquivo direto — não precisa de API nem de chave.
