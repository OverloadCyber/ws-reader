# ws-reader

Leitor de WebSocket dinamico (ws:// / wss://) - Delfia.

- `ws-reader.html` - cliente para navegador (sem dependencias)
- `ws-reader.ps1` - cliente para PowerShell 5.1+ / 7+
- `mitm-ws-log.py` - addon do mitmproxy p/ capturar TODO o WebSocket do navegador
  (handshake + frames, com Socket.IO decodificado). Use quando nao souber qual
  cookie/auth/inscricao o navegador manda - o proxy mostra tudo automaticamente.

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
2. Rode o proxy com o addon na porta 8881:
   ```powershell
   mitmdump --listen-port 8881 -s mitm-ws-log.py --set wshost=cx.netscout.com
   ```
3. Aponte o navegador (ou o Windows) para o proxy `127.0.0.1:8881`.
4. Abra `http://mitm.it` no navegador e instale o certificado (necessário p/ `wss://`).
5. Acesse o site normalmente — o terminal mostra o handshake (Cookie/Origin) e cada
   frame, com Socket.IO decodificado (CONNECT/EVENT/ACK). Dali você copia o auth e os
   eventos para usar no `ws-reader.ps1`.
