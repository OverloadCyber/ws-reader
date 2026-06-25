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

    def load(self, loader):
        loader.add_option(
            "caphost", str, "",
            "Filtra a saida do addon: so loga flows cujo host contenha esse texto.",
        )

    def configure(self, updated):
        from mitmproxy import ctx
        self.host = ctx.options.caphost or None

    def _match(self, flow):
        return not self.host or self.host in flow.request.pretty_host

    # ---------- HTTP ----------
    def request(self, flow):
        if not self._match(flow):
            return
        r = flow.request
        print("\n" + "-" * 72)
        print("REQ  %s %s" % (r.method, r.pretty_url))
        # primeiro os headers importantes, depois os demais
        seen = set()
        for h in KEY_REQ:
            if h in r.headers:
                print("   > %s: %s" % (h, r.headers[h]))
                seen.add(h)
        for k, v in r.headers.items():
            if k.lower() not in seen:
                print("   > %s: %s" % (k, v))
        body = _body(r)
        if body:
            print("   REQ BODY: %s" % body)

    def response(self, flow):
        if not self._match(flow):
            return
        resp = flow.response
        ct = resp.headers.get("content-type", "")
        print("RESP %s  %s  (%s)" % (resp.status_code, flow.request.pretty_url, ct))
        body = _body(resp)
        if body:
            print("   RESP BODY: %s" % body)

    # ---------- WebSocket ----------
    def websocket_start(self, flow):
        if not self._match(flow):
            return
        print("\n" + "=" * 72)
        print("WS ABRIU  %s" % flow.request.pretty_url)
        for h in ("cookie", "origin", "authorization"):
            if h in flow.request.headers:
                print("   %s: %s" % (h, flow.request.headers[h]))
        print("=" * 72)

    def websocket_message(self, flow):
        if not self._match(flow):
            return
        m = flow.websocket.messages[-1]
        try:
            text = bytes(m.content).decode("utf-8", "replace")
        except Exception:
            text = repr(m.content)
        arrow = "ENVIA  >>" if m.from_client else "<< RECEBE"
        print("%s  %s" % (arrow, text))
        decoded = _decode_socketio(text)
        if decoded and decoded != text:
            print("            -> %s" % decoded)

    def websocket_end(self, flow):
        if self._match(flow):
            print("WS FECHOU  %s" % flow.request.pretty_url)


addons = [Capture()]
