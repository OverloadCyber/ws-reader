# ws-reader

Leitor de WebSocket dinamico (ws:// / wss://) - Delfia.

- `ws-reader.html` - cliente para navegador (sem dependencias)
- `ws-reader.ps1` - cliente para PowerShell 5.1+ / 7+

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
