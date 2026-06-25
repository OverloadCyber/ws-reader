<#
.SYNOPSIS
    Leitor de WebSocket (ws:// / wss://) para PowerShell - Delfia.
.DESCRIPTION
    Conecta a uma URL WebSocket e imprime as mensagens recebidas em tempo real.
    Permite enviar mensagens digitando no terminal. Use Ctrl+C para sair.
.PARAMETER Url
    A URL do WebSocket (ex: wss://echo.websocket.org). Se omitida, será solicitada.
.PARAMETER Header
    Header(s) HTTP no handshake, formato "Nome: valor". Pode repetir. Ex: -Header "Authorization: Bearer xyz"
.PARAMETER SubProtocol
    Subprotocolo opcional.
.PARAMETER SocketIO
    Forca o modo Socket.IO/Engine.IO (responde ping->pong, manda 40 p/ entrar no
    namespace e decodifica os eventos 42[...]). Se omitido, e detectado automaticamente
    quando o servidor envia o frame de OPEN (0{"sid":...}).
.PARAMETER Namespace
    Namespace do Socket.IO (padrao "/"). Ex: -Namespace "/admin".
.PARAMETER OnConnect
    Mensagem(ns) a enviar automaticamente assim que conectar (replica as inscricoes
    que o navegador faz). Em Socket.IO sao enviadas apos o servidor confirmar o
    namespace; em modo cru, logo apos abrir. Pode repetir.
    Ex: -OnConnect '42["subscribe","sala-x"]'
.PARAMETER Raw
    Desliga o modo Socket.IO e mostra os frames crus, mesmo que sejam detectados.
.EXAMPLE
    .\ws-reader.ps1 -Url wss://echo.websocket.org
.EXAMPLE
    .\ws-reader.ps1 -Url wss://api.exemplo.com/socket -Header "Authorization: Bearer TOKEN"
.EXAMPLE
    .\ws-reader.ps1 -Url "wss://api.exemplo.com/socket.io/?EIO=4&transport=websocket" -Namespace "/admin"
.NOTES
    Requer PowerShell 5.1+ (Windows) ou PowerShell 7+ (multiplataforma).
#>
[CmdletBinding()]
param(
    [string]$Url,
    [string[]]$Header,
    [string]$SubProtocol,
    [switch]$SocketIO,
    [string]$Namespace = '/',
    [string[]]$OnConnect,
    [switch]$Raw
)

$ErrorActionPreference = 'Stop'

function Write-Line {
    param([string]$Tag, [string]$Body, [ConsoleColor]$Color)
    $t = (Get-Date).ToString('HH:mm:ss.fff')
    Write-Host "[$t] " -ForegroundColor DarkGray -NoNewline
    Write-Host ("{0,-7}" -f $Tag) -ForegroundColor $Color -NoNewline
    Write-Host " $Body"
}

function Format-MaybeJson {
    param([string]$Text)
    try   { return ($Text | ConvertFrom-Json | ConvertTo-Json -Depth 20) }
    catch { return $Text }
}

# Envia uma string de texto pelo socket (reaproveitado p/ input e p/ Socket.IO)
function Send-WsText {
    param([string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $out   = [System.ArraySegment[byte]]::new($bytes)
    $script:ws.SendAsync($out, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $script:cts.Token).GetAwaiter().GetResult()
}

# Envia as mensagens de -OnConnect (uma unica vez)
function Send-OnConnect {
    if ($script:onConnectSent) { return }
    if (-not $script:OnConnect)  { return }
    $script:onConnectSent = $true
    foreach ($m in $script:OnConnect) {
        Send-WsText $m
        Write-Line "> SUB" $m Cyan
    }
}

# Decodifica o payload de um pacote Socket.IO (o que vem depois do '4' do Engine.IO)
function Show-SIOMessage {
    param([string]$Sio)
    if ($Sio.Length -eq 0) { return }
    $t    = $Sio[0]
    $rest = $Sio.Substring(1)
    switch ($t) {
        '0' { Write-Line "< CONN" "namespace conectado $rest" Green; Send-OnConnect }
        '1' { Write-Line "< DISC" "namespace desconectado $rest" Yellow }
        '2' {
            # EVENT: [/namespace,][ackId]["nome", arg1, arg2, ...]
            $br = $rest.IndexOf('[')
            if ($br -lt 0) { Write-Line "< EVT" $rest Green; return }
            $payload = $rest.Substring($br)
            try {
                $arr  = $payload | ConvertFrom-Json
                $name = $arr[0]
                $data = ''
                if ($arr.Count -gt 1) {
                    $data = ($arr[1..($arr.Count - 1)] | ConvertTo-Json -Depth 20 -Compress)
                }
                Write-Line "< EVT" ("{0}  {1}" -f $name, $data) Green
            } catch {
                Write-Line "< EVT" $payload Green
            }
        }
        '3' { Write-Line "< ACK" $rest Green }
        '4' { Write-Line "< ERR" (Format-MaybeJson $rest) Red }
        default { Write-Line "< IN" (Format-MaybeJson $Sio) Green }
    }
}

# Trata um frame de texto quando o modo Socket.IO/Engine.IO esta ativo
function Show-SocketIO {
    param([string]$Text)
    if ($Text.Length -eq 0) { Write-Line "< IN" "(vazio)" Green; return }
    $type = $Text[0]
    switch ($type) {
        '0' {
            # Engine.IO OPEN - handshake
            Write-Line "< OPEN" (Format-MaybeJson $Text.Substring(1)) DarkCyan
            # Entra no namespace p/ comecar a receber eventos
            $connect = '40'
            if ($script:Namespace -and $script:Namespace -ne '/') {
                $connect = '40' + $script:Namespace + ','
            }
            Send-WsText $connect
            Write-Line "> SIO" "connect ($connect)" Cyan
        }
        '1' { Write-Line "< CLOSE" "Engine.IO close" Yellow }
        '2' {
            # PING -> responde PONG p/ manter a conexao viva
            Send-WsText '3'
            Write-Line "<> PP" "ping -> pong" DarkGray
        }
        '3' { Write-Line "< PONG" "" DarkGray }
        '4' { Show-SIOMessage $Text.Substring(1) }   # mensagem Socket.IO
        default { Write-Line "< IN" (Format-MaybeJson $Text) Green }
    }
}

# --- Banner ---
Write-Host ""
Write-Host "  DELFIA " -ForegroundColor Green -NoNewline
Write-Host "// ws reader" -ForegroundColor DarkGray
Write-Host "  ----------------------------------------" -ForegroundColor DarkGray

# --- URL dinâmica ---
if (-not $Url) {
    $Url = Read-Host "  URL do WebSocket (wss://...)"
}
$Url = $Url.Trim()
if ($Url -notmatch '^wss?://') {
    Write-Line "ERRO" "A URL deve comecar com ws:// ou wss://" Red
    exit 1
}

# --- Monta o cliente ---
$ws  = [System.Net.WebSockets.ClientWebSocket]::new()
if ($SubProtocol) { $ws.Options.AddSubProtocol($SubProtocol) }
if ($Header) {
    foreach ($h in $Header) {
        $idx = $h.IndexOf(':')
        if ($idx -lt 1) { Write-Line "ERRO" "Header invalido: $h (use 'Nome: valor')" Red; exit 1 }
        $name  = $h.Substring(0, $idx).Trim()
        $value = $h.Substring($idx + 1).Trim()
        $ws.Options.SetRequestHeader($name, $value)
    }
}

$cts = [System.Threading.CancellationTokenSource]::new()

# --- Trata Ctrl+C para fechar limpo ---
[Console]::TreatControlCAsInput = $false
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    if ($ws -and $ws.State -eq 'Open') { $ws.Abort() }
}

# --- Conecta ---
Write-Line "SYS" "Conectando a $Url ..." Yellow
try {
    $ws.ConnectAsync([Uri]$Url, $cts.Token).GetAwaiter().GetResult()
} catch {
    Write-Line "ERRO" $_.Exception.Message Red
    exit 1
}
Write-Line "SYS" "Conexao aberta. Digite e Enter p/ enviar. Ctrl+C p/ sair." Green
if ($SocketIO) { Write-Line "SYS" "Modo Socket.IO ativo (namespace '$Namespace')." Yellow }
Write-Host ""

# --- Loop de recepção ---
$buffer  = [byte[]]::new(8192)
$segment = [System.ArraySegment[byte]]::new($buffer)
$count   = 0
$sioMode = [bool]$SocketIO   # pode ser ligado por auto-deteccao ao ver o frame de OPEN
$onConnectSent = $false

# Modo cru: nao ha handshake de namespace, entao envia o OnConnect logo apos abrir.
# (No modo Socket.IO o envio ocorre apos o "< CONN" do servidor.)
if ($Raw) { Send-OnConnect }

try {
    while ($ws.State -eq 'Open') {

        # Recebe (com timeout curto p/ poder checar input do teclado)
        $recvTask = $ws.ReceiveAsync($segment, $cts.Token)
        while (-not $recvTask.IsCompleted) {
            # Permite enviar enquanto espera
            if ([Console]::KeyAvailable) {
                $msg = Read-Host
                if ($null -ne $msg -and $msg -ne '') {
                    Send-WsText $msg
                    Write-Line "> OUT" $msg Cyan
                }
            }
            Start-Sleep -Milliseconds 40
        }

        $result = $recvTask.GetAwaiter().GetResult()

        if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
            Write-Line "SYS" "Conexao fechada pelo servidor (code $($result.CloseStatus))" Yellow
            break
        }

        # Acumula mensagem completa (pode vir fragmentada)
        $ms = [System.IO.MemoryStream]::new()
        $ms.Write($buffer, 0, $result.Count)
        while (-not $result.EndOfMessage) {
            $result = $ws.ReceiveAsync($segment, $cts.Token).GetAwaiter().GetResult()
            $ms.Write($buffer, 0, $result.Count)
        }
        $count++

        if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Binary) {
            $data = $ms.ToArray()
            $hex  = ($data | ForEach-Object { $_.ToString('x2') }) -join ' '
            Write-Line "< BIN" "[$($data.Length) bytes] $hex" Green
        } else {
            $text = [Text.Encoding]::UTF8.GetString($ms.ToArray())

            # Auto-deteccao: frame de OPEN do Engine.IO (0{"sid":...}) liga o modo Socket.IO
            if (-not $sioMode -and -not $Raw -and $text -match '^0\{.*"sid"') {
                $sioMode = $true
                Write-Line "SYS" "Socket.IO/Engine.IO detectado - modo protocolo ativo." Yellow
            }

            if ($sioMode -and -not $Raw) {
                Show-SocketIO $text
            } else {
                Write-Line "< IN" (Format-MaybeJson $text) Green
            }
        }
        $ms.Dispose()
    }
}
catch [OperationCanceledException] {
    # Ctrl+C / cancelamento - saida limpa
}
catch {
    Write-Line "ERRO" $_.Exception.Message Red
}
finally {
    if ($ws.State -eq 'Open') {
        try { $ws.CloseAsync('NormalClosure', 'fechado pelo cliente', [Threading.CancellationToken]::None).GetAwaiter().GetResult() } catch {}
    }
    $ws.Dispose()
    Write-Host ""
    Write-Line "SYS" "Encerrado. Total recebido: $count msg" DarkGray
}
