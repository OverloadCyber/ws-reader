"""
mitm-ws-log.py - Addon do mitmproxy p/ capturar e decodificar WebSocket - Delfia.

Loga o handshake (URL + Cookie/Origin/Authorization) e cada frame WebSocket,
decodificando Socket.IO/Engine.IO (CONNECT, EVENT, ACK, ping/pong...). Mostra
de forma legivel o payload de auth do connect (40/ns,{...}) e os eventos.

USO (Windows):
    mitmdump --listen-port 8881 -s mitm-ws-log.py

Depois aponte o navegador p/ o proxy 127.0.0.1:8881 e instale o certificado
abrindo http://mitm.it no navegador (necessario p/ decifrar wss://).

Filtro opcional por host (so loga o que interessa):
    mitmdump --listen-port 8881 -s mitm-ws-log.py --set wshost=cx.netscout.com
"""
import logging

log = logging.getLogger("ws")


def _decode_socketio(text):
    """Traduz um frame Engine.IO/Socket.IO p/ algo legivel. Retorna None se nao casar."""
    if not text:
        return None
    eio = text[0]
    if eio == "2":
        return "Engine.IO ping"
    if eio == "3":
        return "Engine.IO pong"
    if eio == "0":
        return "Engine.IO OPEN " + text[1:]
    if eio == "1":
        return "Engine.IO CLOSE"
    if eio != "4":
        return None  # nao e um pacote 'message' do Engine.IO
    sio = text[1:]
    if not sio:
        return "Socket.IO (vazio)"
    types = {
        "0": "CONNECT",
        "1": "DISCONNECT",
        "2": "EVENT",
        "3": "ACK",
        "4": "CONNECT_ERROR",
        "5": "BINARY_EVENT",
        "6": "BINARY_ACK",
    }
    label = types.get(sio[0], "?" + sio[0])
    return "Socket.IO " + label + "  " + sio[1:]


class WsLog:
    def __init__(self):
        self.host = None

    def load(self, loader):
        loader.add_option(
            "wshost", str, "", "So loga WebSocket cujo host contenha esse texto."
        )

    def configure(self, updated):
        from mitmproxy import ctx
        self.host = ctx.options.wshost or None

    def _match(self, flow):
        if not self.host:
            return True
        return self.host in flow.request.pretty_host

    # Handshake do WebSocket (a requisicao HTTP de upgrade)
    def websocket_start(self, flow):
        if not self._match(flow):
            return
        req = flow.request
        log.info("=" * 70)
        log.info("WS ABRIU  %s", req.pretty_url)
        for h in ("cookie", "origin", "authorization", "user-agent"):
            if h in req.headers:
                log.info("   %-13s %s", h + ":", req.headers[h])
        log.info("=" * 70)

    # Cada mensagem (frame) trocada apos o handshake
    def websocket_message(self, flow):
        if not self._match(flow):
            return
        m = flow.websocket.messages[-1]
        try:
            text = bytes(m.content).decode("utf-8", "replace")
        except Exception:
            text = repr(m.content)
        arrow = "ENVIA  >>" if m.from_client else "<< RECEBE"
        log.info("%s  %s", arrow, text)
        decoded = _decode_socketio(text)
        if decoded and decoded != text:
            log.info("            -> %s", decoded)

    def websocket_end(self, flow):
        if self._match(flow):
            log.info("WS FECHOU  %s", flow.request.pretty_url)


addons = [WsLog()]
