<#
.SYNOPSIS
    Leitor de WebSocket (ws:// / wss://) para PowerShell — Delfia.
.DESCRIPTION
    Conecta a uma URL WebSocket e imprime as mensagens recebidas em tempo real.
    Permite enviar mensagens digitando no terminal. Use Ctrl+C para sair.
.PARAMETER Url
    A URL do WebSocket (ex: wss://echo.websocket.org). Se omitida, será solicitada.
.PARAMETER Header
    Header(s) HTTP no handshake, formato "Nome: valor". Pode repetir. Ex: -Header "Authorization: Bearer xyz"
.PARAMETER SubProtocol
    Subprotocolo opcional.
.EXAMPLE
    .\ws-reader.ps1 -Url wss://echo.websocket.org
.EXAMPLE
    .\ws-reader.ps1 -Url wss://api.exemplo.com/socket -Header "Authorization: Bearer TOKEN"
.NOTES
    Requer PowerShell 5.1+ (Windows) ou PowerShell 7+ (multiplataforma).
#>
[CmdletBinding()]
param(
    [string]$Url,
    [string[]]$Header,
    [string]$SubProtocol
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
Write-Host ""

# --- Loop de recepção ---
$buffer  = [byte[]]::new(8192)
$segment = [System.ArraySegment[byte]]::new($buffer)
$count   = 0

try {
    while ($ws.State -eq 'Open') {

        # Recebe (com timeout curto p/ poder checar input do teclado)
        $recvTask = $ws.ReceiveAsync($segment, $cts.Token)
        while (-not $recvTask.IsCompleted) {
            # Permite enviar enquanto espera
            if ([Console]::KeyAvailable) {
                $msg = Read-Host
                if ($null -ne $msg -and $msg -ne '') {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($msg)
                    $out   = [System.ArraySegment[byte]]::new($bytes)
                    $ws.SendAsync($out, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token).GetAwaiter().GetResult()
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
            Write-Line "< IN" (Format-MaybeJson $text) Green
        }
        $ms.Dispose()
    }
}
catch [OperationCanceledException] {
    # Ctrl+C / cancelamento — saida limpa
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
