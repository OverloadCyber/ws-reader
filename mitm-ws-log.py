"""
mitm-ws-log.py - Addon do mitmproxy p/ capturar HTTP + WebSocket - Delfia.

Loga as requisicoes/respostas HTTP (metodo, URL, headers e corpo JSON/texto) e
cada frame WebSocket, decodificando Socket.IO/Engine.IO (CONNECT, EVENT, ACK...).
Mostra o payload de auth do connect (40/ns,{...}), os eventos e o conteudo das
chamadas REST - tudo em texto limpo, sem cacar no DevTools.

USO (Windows) - so interceptando o host de interesse (recomendado):
    mitmdump --listen-port 8881 --allow-hosts "cx\.netscout\.com" \
             --set termlog_verbosity=warn -s mitm-ws-log.py

O --allow-hosts faz o proxy interceptar APENAS esse host (o resto passa direto,
sem ruido nem erro de certificado). O termlog_verbosity=warn silencia as linhas
de "client connect / server connect" do proprio mitmproxy; o que voce ve no
terminal e so a saida deste addon (que usa print, entao sempre aparece).

Filtro extra opcional dentro do addon (caso nao use --allow-hosts):
    --set caphost=cx.netscout.com

Gravar a captura num arquivo (p/ depois o Claude Code analisar):
    --set capfile=captura.log
Depois rode o Claude Code na pasta e peca: "analise captura.log".
"""

MAX_BODY = 4000  # corta corpos gigantes p/ nao inundar o terminal

# Cabecalhos de request que mais importam (mostrados em destaque). O resto vem depois.
KEY_REQ = ("cookie", "authorization", "origin", "user-agent", "content-type")


def _is_text(headers):
    ct = headers.get("content-type", "").lower()
    if not ct:
        return True
    return any(x in ct for x in ("json", "text", "javascript", "xml", "urlencoded"))


def _body(message):
    """Retorna o corpo como texto (cortado) ou um resumo se for binario/vazio."""
    raw = message.raw_content or b""
    if not raw:
        return None
    ct = message.headers.get("content-type", "")
    if _is_text(message.headers):
        try:
            text = message.get_text(strict=False)
        except Exception:
            text = raw.decode("utf-8", "replace")
        if text is None:
            return None
        if len(text) > MAX_BODY:
            return text[:MAX_BODY] + " ...[+%d chars]" % (len(text) - MAX_BODY)
        return text
    return "[%d bytes binarios, content-type: %s]" % (len(raw), ct)


def _decode_socketio(text):
    """Traduz um frame Engine.IO/Socket.IO p/ algo legivel. None se nao casar."""
    if not text:
        return None
    eio = text[0]
    simple = {"2": "Engine.IO ping", "3": "Engine.IO pong", "1": "Engine.IO CLOSE"}
    if eio in simple:
        return simple[eio]
    if eio == "0":
        return "Engine.IO OPEN " + text[1:]
    if eio != "4":
        return None
    sio = text[1:]
    if not sio:
        return "Socket.IO (vazio)"
    types = {
        "0": "CONNECT", "1": "DISCONNECT", "2": "EVENT", "3": "ACK",
        "4": "CONNECT_ERROR", "5": "BINARY_EVENT", "6": "BINARY_ACK",
    }
    return "Socket.IO " + types.get(sio[0], "?" + sio[0]) + "  " + sio[1:]


class Capture:
    def __init__(self):
        self.host = None
        self.outfile = None
        self._fh = None

    def load(self, loader):
        loader.add_option(
            "caphost", str, "",
            "Filtra a saida do addon: so loga flows cujo host contenha esse texto.",
        )
        loader.add_option(
            "capfile", str, "",
            "Se setado, grava toda a captura nesse arquivo (p/ o Claude Code ler).",
        )

    def configure(self, updated):
        from mitmproxy import ctx
        self.host = ctx.options.caphost or None
        self.outfile = ctx.options.capfile or None
        if self.outfile and self._fh is None:
            # append (a) p/ nao perder captura entre execucoes
            self._fh = open(self.outfile, "a", encoding="utf-8")

    def done(self):
        if self._fh:
            self._fh.close()
            self._fh = None

    def _out(self, line):
        # imprime no terminal e, se houver arquivo, grava nele tambem
        print(line)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()

    def _match(self, flow):
        return not self.host or self.host in flow.request.pretty_host

    # ---------- HTTP ----------
    def request(self, flow):
        if not self._match(flow):
            return
        r = flow.request
        self._out("\n" + "-" * 72)
        self._out("REQ  %s %s" % (r.method, r.pretty_url))
        # primeiro os headers importantes, depois os demais
        seen = set()
        for h in KEY_REQ:
            if h in r.headers:
                self._out("   > %s: %s" % (h, r.headers[h]))
                seen.add(h)
        for k, v in r.headers.items():
            if k.lower() not in seen:
                self._out("   > %s: %s" % (k, v))
        body = _body(r)
        if body:
            self._out("   REQ BODY: %s" % body)

    def response(self, flow):
        if not self._match(flow):
            return
        resp = flow.response
        ct = resp.headers.get("content-type", "")
        self._out("RESP %s  %s  (%s)" % (resp.status_code, flow.request.pretty_url, ct))
        body = _body(resp)
        if body:
            self._out("   RESP BODY: %s" % body)

    # ---------- WebSocket ----------
    def websocket_start(self, flow):
        if not self._match(flow):
            return
        self._out("\n" + "=" * 72)
        self._out("WS ABRIU  %s" % flow.request.pretty_url)
        for h in ("cookie", "origin", "authorization"):
            if h in flow.request.headers:
                self._out("   %s: %s" % (h, flow.request.headers[h]))
        self._out("=" * 72)

    def websocket_message(self, flow):
        if not self._match(flow):
            return
        m = flow.websocket.messages[-1]
        try:
            text = bytes(m.content).decode("utf-8", "replace")
        except Exception:
            text = repr(m.content)
        arrow = "ENVIA  >>" if m.from_client else "<< RECEBE"
        self._out("%s  %s" % (arrow, text))
        decoded = _decode_socketio(text)
        if decoded and decoded != text:
            self._out("            -> %s" % decoded)

    def websocket_end(self, flow):
        if self._match(flow):
            self._out("WS FECHOU  %s" % flow.request.pretty_url)


addons = [Capture()]
