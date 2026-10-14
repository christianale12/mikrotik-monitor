#!/usr/bin/env python3
"""
Monitoreo en vivo, alarmas, topologia y metricas OSPF
=====================================================
Este modulo es el corazon del panel en vivo:

  - muestrear()/poll(): lee las interfaces de cada equipo conectado,
    calcula la tasa real en bps (los contadores de RouterOS son
    acumulados, asi que se diferencian entre muestras) y arma la
    topologia detectada por los cables.
  - El motor de alarmas evalua reglas guardadas en monitoreo.yml sobre
    esas tasas, genera eventos y, si la regla lo pide, cambia el costo
    OSPF del enlace afectado (en los dos extremos) y lo restaura al
    bajar la alarma.
  - la topologia se cachea en memoria: la consumen el grafo SVG y la
    busqueda de pares para cambiar metricas.

Todo el estado vive bajo un candado unico porque Flask atiende en varios
hilos y el monitoreo refresca cada pocos segundos.
"""

import fnmatch
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

import transporte_mikrotik as tm

ARCHIVO = "monitoreo.yml"
CAPACIDAD_DEFECTO = 100_000_000
SATURADO_PCT_DEFECTO = 80
OLVIDO_TOPO = 120.0
MUESTRA_VIEJA = 60.0
TOPO_TTL = 4.0
ANTICIPO_RECONVERGENCIA = 30.0  # seg. de adelanto con que se aplica una franja, para que OSPF ya haya convergido al comenzar
METRICAS = ("rx-bps", "tx-bps", "total-bps", "red-bps", "pct")
OPERADORES = (">", ">=", "<", "<=", "==", "!=")

_lock = threading.RLock()
_poll_lock = threading.Lock()
_recoger_lock = threading.Lock()
_muestra = {}
_config = {"capacidad-default": CAPACIDAD_DEFECTO, "saturado-pct": SATURADO_PCT_DEFECTO,
           "capacidades": {}, "alarmas": [], "direccionamiento": [], "regla-activa": None}
_ruta = [None]
_estados = {}
_eventos = []
_seq = [0]
_topo = {"ts": 0.0, "nodos": [], "enlaces": []}
_cache_id = {}
_cache_rid = {}
_mem_nodos = {}     # nid -> {"nodo": {...}, "ts": t}  (para no borrar routers caidos)
_mem_enlaces = {}   # (host, iface) -> {"peer_host","peer_iface","peer_nodo","ts"}
_rutas_cache = {}   # host -> (ts, {destino: interfaz-Salida})
_aplicado = {}      # (host, iface) -> {"costo": int, "origen": str}  (lo que el motor dejó puesto)
_fallback = {}      # (host, iface) -> {"costo": int, "alarma": id}  (costo "normal" al liberar)
_efectos_activos = []  # últimos efectos de alarmas, para no pisarlos al cambiar de regla
_reconectar = [None]   # hook que setea la app para reconectar sesiones caidas
_ultimo = {}           # último resultado completo de poll(), para servirlo sin bloquear
DIAS = ("lun", "mar", "mie", "jue", "vie", "sab", "dom")


def set_reconectar(fn):
    """Registra la funcion (host) -> api|None con la que reintentar sesiones
    caidas. La usa 'recoger' cuando la API de un equipo dejo de responder
    (por ejemplo, si el router se apago y volvio a encender)."""
    _reconectar[0] = fn


def iniciar(dir_datos):
    """Carga (y deja anotada) la ruta del archivo de configuracion."""
    ruta = os.path.join(dir_datos, ARCHIVO)
    with _lock:
        _ruta[0] = ruta
        if os.path.isfile(ruta):
            try:
                with open(ruta, "r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f) or {}
                if isinstance(doc, dict):
                    _config.update({k: v for k, v in doc.items() if v is not None})
            except Exception:  # noqa: BLE001
                pass
        _config.setdefault("capacidad-default", CAPACIDAD_DEFECTO)
        _config.setdefault("saturado-pct", SATURADO_PCT_DEFECTO)
        _config.setdefault("capacidades", {})
        _config.setdefault("alarmas", [])
        _config.setdefault("direccionamiento", [])
        _config.setdefault("regla-activa", None)
        # Recordar los costos que el motor había dejado puestos: si la app se
        # cierra o reinicia, el reconciliador puede devolverlos a dinámico.
        _aplicado.clear()
        for it in (_config.get("aplicado") or []):
            try:
                _aplicado[(str(it["equipo"]), str(it["interfaz"]))] = {
                    "costo": int(it["costo"]),
                    "origen": str(it.get("origen") or ""),
                }
            except (KeyError, TypeError, ValueError):
                continue
    return ruta


def _guardar():
    ruta = _ruta[0]
    if not ruta:
        return
    with _lock:
        copia = {
            "capacidad-default": _config.get("capacidad-default", CAPACIDAD_DEFECTO),
            "saturado-pct": _config.get("saturado-pct", SATURADO_PCT_DEFECTO),
            "capacidades": dict(_config.get("capacidades") or {}),
            "alarmas": [dict(a) for a in (_config.get("alarmas") or [])],
            "regla-activa": _config.get("regla-activa"),
            "direccionamiento": [dict(r) for r in (_config.get("direccionamiento") or [])],
            "aplicado": [{"equipo": h, "interfaz": i,
                          "costo": v.get("costo"), "origen": v.get("origen") or ""}
                         for (h, i), v in _aplicado.items()],
        }
    try:
        with open(ruta, "w", encoding="utf-8") as f:
            yaml.safe_dump(copia, f, allow_unicode=True, sort_keys=False)
    except OSError:
        pass


def config():
    with _lock:
        return {
            "capacidad-default": _config.get("capacidad-default", CAPACIDAD_DEFECTO),
            "saturado-pct": _config.get("saturado-pct", SATURADO_PCT_DEFECTO),
            "capacidades": dict(_config.get("capacidades") or {}),
            "alarmas": [dict(a) for a in (_config.get("alarmas") or [])],
            "direccionamiento": [dict(r) for r in (_config.get("direccionamiento") or [])],
            "regla-activa": _config.get("regla-activa"),
            "ruta": _ruta[0] or "",
        }


def capacidad(host, interfaz):
    """Bps disponibles para esa interfaz (override por interfaz o global)."""
    with _lock:
        mapa = _config.get("capacidades") or {}
        v = mapa.get(f"{host}/{interfaz}")
        if v:
            try:
                return max(1, int(v))
            except (TypeError, ValueError):
                pass
        try:
            return max(1, int(_config.get("capacidad-default") or CAPACIDAD_DEFECTO))
        except (TypeError, ValueError):
            return CAPACIDAD_DEFECTO


def guardar_capacidades(default, mapa):
    try:
        valor = max(1, int(default))
    except (TypeError, ValueError):
        valor = CAPACIDAD_DEFECTO
    limpio = {}
    for clave, v in (mapa or {}).items():
        try:
            limpio[str(clave)] = max(1, int(v))
        except (TypeError, ValueError):
            continue
    with _lock:
        _config["capacidad-default"] = valor
        _config["capacidades"] = limpio
    _guardar()
    return config()


def guardar_saturado(pct):
    """Umbral (%) a partir del cual un enlace se considera saturado."""
    try:
        valor = max(1, min(100, int(float(pct))))
    except (TypeError, ValueError):
        valor = SATURADO_PCT_DEFECTO
    with _lock:
        _config["saturado-pct"] = valor
    _guardar()
    return config()


def guardar_alarmas(lista):
    limpias = []
    ids = set()
    for a in (lista or []):
        if not isinstance(a, dict):
            continue
        aid = str(a.get("id") or "").strip() or f"al-{len(limpias) + 1}"
        a = dict(a)
        a["id"] = aid
        a.setdefault("habilitada", True)
        a.setdefault("severidad", "alerta")
        a.setdefault("metrica", "pct")
        a.setdefault("operador", ">=")
        a.setdefault("accion", "manual")
        a.setdefault("duracion-s", 10)
        a.setdefault("limpiar-s", 30)
        try:
            a["umbral"] = float(a.get("umbral"))
        except (TypeError, ValueError):
            continue
        if aid in ids:
            continue
        ids.add(aid)
        limpias.append(a)
    with _lock:
        _config["alarmas"] = limpias
        for clave in list(_estados):
            if clave.split("|", 1)[0] not in ids:
                _estados.pop(clave, None)
    _guardar()
    return config()


def borrar_alarma(aid):
    with _lock:
        _config["alarmas"] = [a for a in (_config.get("alarmas") or [])
                              if str(a.get("id")) != str(aid)]
        for clave in list(_estados):
            if clave.split("|", 1)[0] == str(aid):
                _estados.pop(clave, None)
        for par in list(_fallback):
            if str(_fallback[par].get("alarma")) == str(aid):
                _fallback.pop(par, None)
    _guardar()
    return config()


def _normalizar_entrada(e):
    """Valida una entrada de direccionamiento: equipo + interfaz + costo."""
    if not isinstance(e, dict):
        return None
    equipo = str(e.get("equipo") or "").strip()
    interfaz = str(e.get("interfaz") or "").strip()
    if not equipo or not interfaz:
        return None
    try:
        costo = int(float(e.get("costo")))
    except (TypeError, ValueError):
        return None
    return {
        "equipo": equipo,
        "interfaz": interfaz,
        "costo": max(1, min(65535, costo)),
        "enlace": bool(e.get("enlace", True)),
        "rol": "evitar" if str(e.get("rol") or "").lower() == "evitar" else "ruta",
    }


def _normalizar_horario(h):
    """Franja horaria opcional: {desde, hasta, dias[]}. Vacía/invalidada = None."""
    if not isinstance(h, dict):
        return None
    desde = str(h.get("desde") or "").strip()
    hasta = str(h.get("hasta") or "").strip()
    if not desde or not hasta:
        return None
    dias = h.get("dias")
    if dias is None:
        dias = []
    if isinstance(dias, str):
        dias = [d.strip() for d in dias.split(",") if d.strip()]
    dias = [str(d).lower()[:3] for d in dias if str(d).lower()[:3] in DIAS]
    return {"desde": desde, "hasta": hasta, "dias": dias}


def guardar_direccionamiento(lista):
    """Guarda las reglas de direccionamiento (con nombre) aplicando validación."""
    limpias = []
    ids = set()
    for r in (lista or []):
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").strip() or f"dir-{len(limpias) + 1}"
        if rid in ids:
            continue
        r = dict(r)
        r["id"] = rid
        r["nombre"] = str(r.get("nombre") or rid).strip() or rid
        r.setdefault("habilitada", True)
        r["origen"] = str(r.get("origen") or "").strip()
        r["destino"] = str(r.get("destino") or "").strip()
        r["horario"] = _normalizar_horario(r.get("horario"))
        entradas = []
        for e in (r.get("entradas") or []):
            n = _normalizar_entrada(e)
            if n:
                entradas.append(n)
        r["entradas"] = entradas
        ids.add(rid)
        limpias.append(r)
    with _lock:
        _config["direccionamiento"] = limpias
        if str(_config.get("regla-activa")) not in ids:
            _config["regla-activa"] = None
    _guardar()
    return config()


def borrar_regla(rid):
    with _lock:
        _config["direccionamiento"] = [r for r in (_config.get("direccionamiento") or [])
                                       if str(r.get("id")) != str(rid)]
        if str(_config.get("regla-activa")) == str(rid):
            _config["regla-activa"] = None
    _guardar()
    return config()


def activar_regla(rid):
    """Marca una regla como la activa de forma manual (regla-activa)."""
    with _lock:
        existe = any(str(r.get("id")) == str(rid)
                     for r in (_config.get("direccionamiento") or []))
        _config["regla-activa"] = str(rid) if existe else None
    _guardar()
    return config()


def desactivar_regla():
    with _lock:
        _config["regla-activa"] = None
    _guardar()
    return config()


def _minutos(hhmm):
    try:
        partes = str(hhmm).split(":")
        return int(partes[0]) * 60 + int(partes[1])
    except (TypeError, ValueError, IndexError):
        return None


def _horario_cumple(horario, ahora_epoch=None):
    """True si la hora actual cae dentro de la franja (soporta cruce de medianoche)."""
    if not horario:
        return False
    desde = _minutos(horario.get("desde"))
    hasta = _minutos(horario.get("hasta"))
    if desde is None or hasta is None:
        return False
    lt = time.localtime(ahora_epoch if ahora_epoch is not None else time.time())
    dias = horario.get("dias") or []
    if dias and DIAS[lt.tm_wday] not in dias:
        return False
    ahora_min = lt.tm_hour * 60 + lt.tm_min
    if desde <= hasta:
        return desde <= ahora_min < hasta
    return ahora_min >= desde or ahora_min < hasta


def _horario_por_comenzar(horario, ahora_epoch=None, anticipo_s=0.0):
    """True si la franja arranca dentro de los próximos `anticipo_s` segundos.

    Se usa para aplicar la regla un poco antes de tiempo, así OSPF ya terminó
    de reconverger cuando la franja empieza de verdad.
    """
    if not horario or anticipo_s <= 0:
        return False
    desde = _minutos(horario.get("desde"))
    if desde is None:
        return False
    lt = time.localtime(ahora_epoch if ahora_epoch is not None else time.time())
    dias = horario.get("dias") or []
    if dias and DIAS[lt.tm_wday] not in dias:
        return False
    seg_dia = lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec
    falta = desde * 60 - seg_dia
    if falta < 0:
        falta += 86400
    return 0 < falta <= anticipo_s


def regla_vigente(ahora_epoch=None, anticipo=0.0):
    """Regla que debe estar aplicada ahora.

    Prioridad: manda la primera regla habilitada cuyo horario cumpla AHORA
    (modo 'horario', automático). Si ninguna franja está activa, recién ahí
    se usa la activada a mano (regla-activa, modo 'manual'). Así una regla con
    horario actúa sola durante su franja y no queda tapada por una manual.

    Devuelve (regla|None, modo) con modo en {'horario', 'manual', None}.
    """
    with _lock:
        reglas = [dict(r) for r in (_config.get("direccionamiento") or [])]
        activa = _config.get("regla-activa")
    for r in reglas:
        if not r.get("habilitada", True):
            continue
        if _horario_cumple(r.get("horario"), ahora_epoch):
            return r, "horario"
    if anticipo:
        # Pre-aplicar la franja que está por comenzar, SOLO si ninguna otra
        # está vigente ahora mismo (así no pisa una franja en curso).
        for r in reglas:
            if not r.get("habilitada", True):
                continue
            if _horario_por_comenzar(r.get("horario"), ahora_epoch, anticipo):
                return r, "horario"
    if activa:
        for r in reglas:
            if r.get("habilitada", True) and str(r.get("id")) == str(activa):
                return r, "manual"
    return None, None


def caminos_vigentes(sesiones, topo=None):
    """Caminos OSPF de la regla vigente (origen→destino) para el panel."""
    if topo is None:
        try:
            topo = topologia(sesiones)
        except Exception:  # noqa: BLE001
            topo = {"nodos": [], "enlaces": []}
    regla, _modo = regla_vigente(anticipo=ANTICIPO_RECONVERGENCIA)
    try:
        return _caminos_regla(topo, sesiones, regla)
    except Exception:  # noqa: BLE001
        return []


def estado_direccionamiento(ahora_epoch=None):
    """Regla vigente y costos que el motor tiene aplicados ahora mismo."""
    regla, modo = regla_vigente(ahora_epoch, anticipo=ANTICIPO_RECONVERGENCIA)
    with _lock:
        aplicado = [{"equipo": h, "interfaz": i, "costo": v.get("costo"),
                     "origen": v.get("origen") or ""}
                    for (h, i), v in _aplicado.items()]
    aplicado.sort(key=lambda x: (x["equipo"], x["interfaz"]))
    vigente = None
    if regla is not None:
        vigente = {"id": regla.get("id"), "nombre": regla.get("nombre"), "modo": modo}
    return {"vigente": vigente, "aplicado": aplicado}


def _entero(v):
    if isinstance(v, bool):
        return 0
    try:
        return int(float(str(v)))
    except (TypeError, ValueError):
        return 0


def muestrear(host, filas, ahora=None):
    """Devuelve las interfaces con rx/tx y las tasas en bps.

    Los contadores de RouterOS son acumulados: la tasa sale de la
    diferencia contra la muestra anterior dividida en el tiempo
    transcurrido. Si el contador baja (reinicio de interfaz) o paso
    demasiado tiempo, la tasa se toma como 0.
    """
    ahora = time.monotonic() if ahora is None else ahora
    with _lock:
        previa = _muestra.setdefault(host, {})
        salida = []
        for f in filas:
            nombre = str(f.get("nombre") or "")
            rx = _entero(f.get("rx"))
            tx = _entero(f.get("tx"))
            p = previa.get(nombre)
            rx_bps = tx_bps = 0.0
            if p:
                dt = ahora - p["t"]
                if 0 < dt <= MUESTRA_VIEJA:
                    rx_bps = max(0, rx - p["rx"]) * 8 / dt
                    tx_bps = max(0, tx - p["tx"]) * 8 / dt
            previa[nombre] = {"t": ahora, "rx": rx, "tx": tx}
            fila = dict(f)
            fila["rx-bps"] = int(round(rx_bps))
            fila["tx-bps"] = int(round(tx_bps))
            fila["total-bps"] = fila["rx-bps"] + fila["tx-bps"]
            salida.append(fila)
        return salida


def _utilizacion(fila, cap):
    peor = max(_entero(fila.get("rx-bps")), _entero(fila.get("tx-bps")))
    if cap <= 0:
        return 0.0
    return round(min(999.0, peor * 100.0 / cap), 1)


def _identidad(api, host):
    with _lock:
        v = _cache_id.get(host)
    if v and v[0] and time.time() - v[1] < 600:
        return v[0]
    if getattr(api, "rota", False):
        return v[0] if v else ""
    try:
        nombre = tm.identidad(api)
    except Exception:  # noqa: BLE001
        nombre = v[0] if v else ""
    # Mientras un equipo esta terminando de cargar (recien reiniciado) su
    # identidad todavia es la de fabrica ("MikroTik"): no la memorizamos, asi
    # en el proximo ciclo se vuelve a leer y aparece el nombre real (R1, etc.).
    defecto = str(nombre).strip().lower() in ("", "mikrotik", "routeros",
                                              "mikrotik routeros")
    with _lock:
        _cache_id[host] = (nombre, 0.0 if defecto else time.time())
    return nombre


def _router_id(api, host):
    with _lock:
        v = _cache_rid.get(host)
    if v and v[0] and time.time() - v[1] < 600:
        return v[0]
    rid = ""
    if getattr(api, "rota", False):
        return v[0] if v else ""
    try:
        inst = tm.ospf_instancias(api)
        rid = str(inst[0].get("router-id") or "") if inst else ""
    except Exception:  # noqa: BLE001
        rid = v[0] if v else ""
    defecto = rid in ("", "0.0.0.0")
    with _lock:
        _cache_rid[host] = (rid, 0.0 if defecto else time.time())
    return rid


def _gestion(host, dirs):
    """Interfaz de gestión: la que tiene una IP que contiene al host."""
    for d in dirs:
        addr = str(d.get("address") or "")
        try:
            if tm._en_rango(host, addr):
                return str(d.get("interface") or "")
        except Exception:  # noqa: BLE001
            continue
    return ""


def _red_de(addr):
    try:
        base, pref = tm._red_base(str(addr))
        return f"{base}/{pref}"
    except Exception:  # noqa: BLE001
        return str(addr or "")


def _lado(host, nodo, iface, addr, info, oif, vec):
    cap = capacidad(host, iface)
    rx = _entero(info.get("rx-bps"))
    tx = _entero(info.get("tx-bps"))
    return {
        "equipo": host,
        "nodo": nodo,
        "interfaz": iface,
        "direccion": addr,
        "red": _red_de(addr),
        "running": str(info.get("running", "")).lower() in ("true", "1", "yes"),
        "link-downs": _entero(info.get("link-downs")),
        "costo": _entero(oif.get("costo")) or None,
        "ospf": str(vec.get("estado") or "") if vec else "",
        "vecino-rid": str(vec.get("router-id") or "") if vec else "",
        "rx-bps": rx,
        "tx-bps": tx,
        "total-bps": rx + tx,
        "capacidad": cap,
        "pct": _utilizacion(info, cap),
        "rx": _entero(info.get("rx")),
        "tx": _entero(info.get("tx")),
    }


def _rutas_de(sesiones, host):
    """Rutas OSPF activas de un router: {destino: {interfaces de salida}}.

    Con ECMP una ruta puede tener varios next-hop; se devuelven todos para
    poder mostrar redireccion por multiples caminos. Cacheado por TOPO_TTL.
    """
    ahora = time.time()
    v = _rutas_cache.get(host)
    if v and ahora - v[0] < TOPO_TTL:
        return v[1]
    mapa = {}
    api = (sesiones.get(host) or {}).get("api") if sesiones else None
    if api and not getattr(api, "rota", False):
        try:
            for r in tm.ospf_rutas(api):
                if r.get("activa") not in (True, "true", "yes", "1"):
                    continue
                salidas = set()
                itf = str(r.get("interfaz") or "")
                if itf:
                    salidas.add(itf)
                for m in re.findall(r"via\s+([^\s,]+)", str(r.get("gateway-status") or "")):
                    salidas.add(m)
                if salidas:
                    mapa.setdefault(str(r.get("destino") or ""), set()).update(salidas)
        except Exception:  # noqa: BLE001
            pass
    _rutas_cache[host] = (ahora, mapa)
    return mapa


def _mapas_traza(topo):
    """Mapas auxiliares para trazar un camino sobre la topología detectada."""
    peer_itf = {}
    for e in topo.get("enlaces", []):
        a, b = e.get("a"), e.get("b")
        if a and b and a.get("equipo") and b.get("equipo"):
            peer_itf[(a["equipo"], a["interfaz"])] = (b["equipo"], b["interfaz"])
            peer_itf[(b["equipo"], b["interfaz"])] = (a["equipo"], a["interfaz"])
    host_a_rid = {}
    rid_a_host = {}
    for n in topo.get("nodos", []):
        rid = n.get("router-id")
        host = n.get("host")
        if rid and host:
            host_a_rid[host] = rid
            rid_a_host[rid] = host
    return peer_itf, rid_a_host, host_a_rid


def _host_de_nodo(topo, ref):
    """Resuelve una referencia (host, identidad, nodo o router-id) a host."""
    ref = str(ref or "").strip()
    if not ref:
        return ""
    for n in topo.get("nodos", []):
        if ref in (n.get("host"), n.get("id"), n.get("identidad"), n.get("router-id")):
            return str(n.get("host") or "")
    return ""


def _caminos_regla(topo, sesiones, regla):
    """Camino(s) OSPF entre el origen y el destino declarados en la regla.

    Devuelve una lista de caminos, cada uno con las aristas (equipo/interfaz)
    y la secuencia de nodos. Vacío si la regla no define origen y destino.
    """
    if not regla:
        return []
    ho = _host_de_nodo(topo, regla.get("origen"))
    hd = _host_de_nodo(topo, regla.get("destino"))
    if not ho or not hd or ho == hd:
        return []
    peer_itf, _, host_a_rid = _mapas_traza(topo)
    rid_dest = host_a_rid.get(hd, "")
    if not rid_dest:
        return []

    def rec(host, saltos, visto):
        if host in visto or saltos > 8:
            return [[]]
        if host == hd:
            return [[]]
        visto = visto | {host}
        salidas = _rutas_de(sesiones, host).get(rid_dest + "/32") or set()
        out = []
        for itf in sorted(salidas):
            edge = (host, itf)
            peer = peer_itf.get(edge)
            if not peer or peer[0] == hd:
                out.append([edge])
                continue
            for s in rec(peer[0], saltos + 1, visto):
                out.append([edge] + s)
        return out

    caminos = []
    for camino in rec(ho, 0, set()):
        if not camino:
            continue
        nodos = [ho]
        actual = ho
        for eq, itf in camino:
            peer = peer_itf.get((eq, itf))
            if peer and peer[0] != actual:
                actual = peer[0]
                nodos.append(actual)
        if nodos[-1] != hd:
            nodos.append(hd)
        caminos.append({
            "aristas": [{"equipo": eq, "interfaz": itf} for eq, itf in camino],
            "nodos": nodos,
        })
    return caminos


def _armar_topologia(recogidos, sesiones=None):
    ahora = time.time()
    nodos = []
    por_host = {}
    rid_a_host = {}
    ident_a_host = {}
    nodo_rid = {}
    usados = set()
    for host, d in recogidos.items():
        ident = d["identidad"] or host
        nid = ident
        n = 2
        while nid in usados:
            nid = f"{ident}#{n}"
            n += 1
        usados.add(nid)
        nodo = {
            "id": nid,
            "host": host,
            "identidad": ident,
            "router-id": d["router-id"],
            "externo": False,
        }
        nodos.append(nodo)
        por_host[host] = nid
        nodo_rid[nid] = d["router-id"]
        if d["router-id"]:
            rid_a_host[d["router-id"]] = host
        ident_a_host.setdefault(ident, host)
        _mem_nodos[nid] = {"nodo": nodo, "ts": ahora}

    # routers que dejaron de responder: se siguen dibujando un rato en su lugar
    for nid, reg in list(_mem_nodos.items()):
        if nid in usados:
            continue
        # Si el equipo volvio a responder con otra identidad (p.ej. paso de
        # "MikroTik" a "R1"), descartar el nodo viejo en vez de dejarlo pegado.
        if (reg.get("nodo") or {}).get("host") in recogidos:
            _mem_nodos.pop(nid, None)
            continue
        if ahora - float(reg.get("ts") or 0) > OLVIDO_TOPO:
            _mem_nodos.pop(nid, None)
            continue
        nodo = dict(reg["nodo"])
        nodo["mem"] = True
        nodos.append(nodo)
        usados.add(nid)
        nodo_rid.setdefault(nid, nodo.get("router-id") or "")

    # Identidad/router-id recordados de equipos que no responden ahora. Sirven
    # para reconocer a un vecino OSPF "pegado" del router apagado y marcarlo
    # como enlace caido, en vez de inventar un nodo externo con el trafico del
    # lado que si esta encendido.
    mem_rid, mem_ident = {}, {}
    for reg in _mem_nodos.values():
        nodo = reg.get("nodo") or {}
        h = nodo.get("host")
        if not h or h in recogidos:
            continue
        rid_m = str(nodo.get("router-id") or "")
        if rid_m:
            mem_rid.setdefault(rid_m, h)
        ident_m = str(nodo.get("identidad") or "")
        if ident_m:
            mem_ident.setdefault(ident_m, h)

    addr_idx = {}
    for host, d in recogidos.items():
        for dd in d["dirs"]:
            addr = str(dd.get("address") or "")
            iface = str(dd.get("interface") or "")
            if not addr or not iface:
                continue
            addr_idx[addr] = (host, iface)
            addr_idx[addr.split("/")[0]] = (host, iface)

    exactos = {}
    parciales = []
    sueltos = []

    ext_nid = {}

    def nodo_externo(etiqueta):
        etiqueta = etiqueta or "desconocido"
        if etiqueta in ext_nid:
            return ext_nid[etiqueta]
        nid = etiqueta
        n = 2
        while nid in usados:
            nid = f"{etiqueta}#{n}"
            n += 1
        usados.add(nid)
        nodos.append({"id": nid, "host": "", "identidad": etiqueta,
                      "router-id": etiqueta if etiqueta.count(".") == 3 else "",
                      "externo": True})
        ext_nid[etiqueta] = nid
        return nid

    for host, d in recogidos.items():
        nodo = por_host[host]
        gestion = _gestion(host, d["dirs"])
        itf_info = {str(i.get("nombre")): i for i in d["interfaces"]}
        oif = {str(o.get("interfaz")): o for o in d["ospf-itf"]}
        vecs = {str(v.get("interfaz")): v for v in d["ospf-vec"]}
        for dd in d["dirs"]:
            iface = str(dd.get("interface") or "")
            addr = str(dd.get("address") or "")
            if not iface or not addr:
                continue
            pref = int(addr.split("/")[1]) if "/" in addr else 32
            if pref >= 32 or iface == gestion:
                continue
            try:
                if tm._en_rango(host, addr):
                    continue
            except Exception:  # noqa: BLE001
                pass
            info = itf_info.get(iface, {})
            vec = vecs.get(iface)
            lado = _lado(host, nodo, iface, addr, info, oif.get(iface, {}), vec)
            if vec:
                destino = addr_idx.get(str(vec.get("direccion") or "").split("/")[0])
                if destino and destino[0] != host:
                    clave = frozenset({(host, iface), destino})
                    exactos.setdefault(clave, []).append(lado)
                    continue
                rid_v = str(vec.get("router-id") or "")
                # El vecino OSPF puede quedar "pegado" un rato aunque el router
                # del otro lado ya este apagado: si coincide con uno recordado
                # que no responde, se lo trata como caido (no como externo).
                dest_host = rid_a_host.get(rid_v) or mem_rid.get(rid_v)
                if dest_host and dest_host != host:
                    lado["pendiente"] = dest_host
                    parciales.append(lado)
                    continue
                nid = nodo_externo(rid_v)
                lado["nodo-externo"] = nid
                exactos.setdefault(frozenset({(host, iface), ("ext", nid)}), []).append(lado)
                continue
            m = d["mndp"].get(iface) or {}
            ident_vec = str(m.get("identity") or "")
            dest_host = ident_a_host.get(ident_vec) or mem_ident.get(ident_vec)
            if dest_host and dest_host != host:
                lado["pendiente"] = dest_host
                parciales.append(lado)
            elif ident_vec:
                nid = nodo_externo(ident_vec)
                lado["nodo-externo"] = nid
                exactos.setdefault(frozenset({(host, iface), ("ext", nid)}), []).append(lado)
            else:
                lado["sin-vecino"] = True
                sueltos.append(lado)

    por_par = {}
    for lado in parciales:
        a, b = sorted([lado["equipo"], lado.pop("pendiente")])
        clave = (a, b)
        g = por_par.setdefault(clave, {"a": [], "b": []})
        g["a" if lado["equipo"] == a else "b"].append(lado)

    for (a, b), g in por_par.items():
        la = sorted(g["a"], key=lambda x: x["interfaz"])
        lb = sorted(g["b"], key=lambda x: x["interfaz"])
        if len(la) == len(lb) and la:
            for x, y in zip(la, lb):
                clave = frozenset({(a, x["interfaz"]), (b, y["interfaz"])})
                lista = exactos.setdefault(clave, [])
                lista.append(x)
                lista.append(y)
        else:
            for x in la:
                exactos.setdefault(frozenset({(a, x["interfaz"]), (b, "?")}), []).append(x)
            for y in lb:
                exactos.setdefault(frozenset({(a, "?"), (b, y["interfaz"])}), []).append(y)

    def lado_sintetico(host, iface):
        """Reconstruye un extremo desde los datos ya recogidos del equipo."""
        d = recogidos.get(host)
        if not d:
            return None
        dd = next((x for x in d["dirs"] if str(x.get("interface")) == iface), None)
        if not dd:
            return None
        addr = str(dd.get("address") or "")
        info = next((i for i in d["interfaces"] if str(i.get("nombre")) == iface), {})
        oif = next((o for o in d["ospf-itf"] if str(o.get("interfaz")) == iface), {})
        return _lado(host, por_host.get(host, host), iface, addr, info, oif, None)

    enlaces = []
    for clave, lados in exactos.items():
        lados = sorted(lados, key=lambda x: (x["equipo"], x["interfaz"]))
        a = lados[0]
        b = lados[1] if len(lados) > 1 else None
        if b is None:
            for ep in clave:
                if ep[0] == "ext":
                    continue
                if (ep[0], ep[1]) != (a["equipo"], a["interfaz"]):
                    b = lado_sintetico(ep[0], ep[1])
                    break
        enlaces.append(_armar_enlace(a, b))
    for lado in sueltos:
        enlaces.append(_armar_enlace(lado, None))

    # completar el extremo faltante con lo recordado y actualizar la memoria
    for e in enlaces:
        a, b = e["a"], e["b"]
        if a and not b and not a.get("nodo-externo"):
            mem = _mem_enlaces.get((a["equipo"], a["interfaz"]))
            if mem:
                b = {
                    "equipo": mem.get("peer_host") or "",
                    "nodo": mem.get("peer_nodo") or "",
                    "interfaz": mem.get("peer_iface") or "",
                    "direccion": "", "red": "", "running": False, "link-downs": 0,
                    "costo": None, "ospf": "", "vecino-rid": "", "rx-bps": 0,
                    "tx-bps": 0, "total-bps": 0, "capacidad": 0, "pct": 0, "mem": True,
                }
                e["b"] = b
                e["estado"] = "caido"
        if a and b:
            _mem_enlaces[(a["equipo"], a["interfaz"])] = {
                "peer_host": b.get("equipo"), "peer_iface": b.get("interfaz"),
                "peer_nodo": b.get("nodo"), "ts": ahora}
            _mem_enlaces[(b["equipo"], b["interfaz"])] = {
                "peer_host": a.get("equipo"), "peer_iface": a.get("interfaz"),
                "peer_nodo": a.get("nodo"), "ts": ahora}
    for par, reg in list(_mem_enlaces.items()):
        if ahora - float(reg.get("ts") or 0) > OLVIDO_TOPO:
            _mem_enlaces.pop(par, None)

    # Enlaces entre dos equipos recordados que hoy no responden: reconstruir el
    # cable desde la memoria para no dejar el mapa sin enlaces cuando cae todo.
    host_nid = dict(por_host)
    for _nid, _reg in _mem_nodos.items():
        _h = (_reg.get("nodo") or {}).get("host")
        if _h:
            host_nid.setdefault(_h, (_reg.get("nodo") or {}).get("id"))
    punta_dibujada = set()
    for e in enlaces:
        for lado in (e["a"], e["b"]):
            if lado and lado.get("equipo") and lado.get("interfaz"):
                punta_dibujada.add((lado["equipo"], lado["interfaz"]))
    base_mem = {"direccion": "", "red": "", "running": False, "link-downs": 0,
                "costo": None, "ospf": "", "vecino-rid": "", "rx-bps": 0,
                "tx-bps": 0, "total-bps": 0, "capacidad": 0, "pct": 0, "mem": True}
    for (h, itf), reg in list(_mem_enlaces.items()):
        ph, pi = reg.get("peer_host"), reg.get("peer_iface")
        if not h or not itf or not ph or not pi:
            continue
        if (h, itf) in punta_dibujada or (ph, pi) in punta_dibujada:
            continue
        if h not in host_nid or ph not in host_nid:
            continue
        a = dict(base_mem, equipo=h, nodo=host_nid[h], interfaz=itf)
        b = dict(base_mem, equipo=ph, nodo=host_nid[ph], interfaz=pi)
        enlaces.append(_armar_enlace(a, b))
        punta_dibujada.add((h, itf))
        punta_dibujada.add((ph, pi))

    # deduplicar el mismo cable (en un corte puede reportarlo una sola punta)
    def _clave_cable(e):
        ends = []
        for lado in (e["a"], e["b"]):
            if not lado:
                continue
            if lado.get("equipo") and lado.get("interfaz"):
                ends.append(("h", lado["equipo"], lado["interfaz"]))
            elif lado.get("nodo-externo"):
                ends.append(("ext", lado["nodo-externo"]))
        return frozenset(ends)

    def _peso(e):
        return sum(1 for lado in (e["a"], e["b"]) if lado and not lado.get("mem"))

    vistos = {}
    unicos = []
    for e in enlaces:
        k = _clave_cable(e)
        if not k:
            unicos.append(e)
            continue
        if k in vistos:
            pos = vistos[k]
            if _peso(e) > _peso(unicos[pos]):
                unicos[pos] = e
            continue
        vistos[k] = len(unicos)
        unicos.append(e)
    enlaces = unicos

    # quitar tramos de una sola punta ya representados por un enlace completo
    conj = [_clave_cable(e) for e in enlaces]
    enlaces = [e for i, e in enumerate(enlaces)
               if not conj[i]
               or not any(j != i and conj[i] < conj[j] for j in range(len(enlaces)))]

    # saturacion y camino(s) de reenvio (por rutas OSPF de los routers afectados)
    umbral = float(_config.get("saturado-pct", SATURADO_PCT_DEFECTO) or SATURADO_PCT_DEFECTO)
    for e in enlaces:
        e["saturado"] = bool(e["pct"] and float(e["pct"]) >= umbral)
        e["reenvio"] = False
    idx = {}
    for e in enlaces:
        for lado in (e["a"], e["b"]):
            if lado and lado.get("equipo") and lado.get("interfaz"):
                idx[(lado["equipo"], lado["interfaz"])] = e
    # vecino por extremo del cable (para trazar la ruta salto a salto)
    peer_itf = {}
    for e in enlaces:
        a, b = e["a"], e["b"]
        if a and b and a.get("equipo") and b.get("equipo"):
            peer_itf[(a["equipo"], a["interfaz"])] = (b["equipo"], b["interfaz"])
            peer_itf[(b["equipo"], b["interfaz"])] = (a["equipo"], a["interfaz"])

    afectadas = set()
    for e in enlaces:
        if e["estado"] in ("caido", "degradado") or e["saturado"]:
            for lado in (e["a"], e["b"]):
                if lado and lado.get("equipo"):
                    afectadas.add((lado["equipo"], lado["interfaz"]))

    def _traza(host, rid_dest, host_dest, saltos=0, visto=None):
        """Caminos (listas de aristas) desde un router hasta el destino, por OSPF.

        Devuelve varias listas cuando hay ECMP (varios next-hop)."""
        if visto is None:
            visto = set()
        if host in visto or saltos > 8:
            return [[]]
        if host_dest and host == host_dest:
            return [[]]
        visto = visto | {host}
        salidas = _rutas_de(sesiones, host).get(rid_dest + "/32") or set()
        out = []
        for itf in salidas:
            edge = (host, itf)
            if edge in afectadas:
                continue
            peer = peer_itf.get(edge)
            if not peer or (host_dest and peer[0] == host_dest):
                out.append([edge])
                continue
            sub = _traza(peer[0], rid_dest, host_dest, saltos + 1, visto)
            out.extend([edge] + s for s in sub)
        return out

    for e in enlaces:
        a, b = e["a"], e["b"]
        if not (a and b):
            continue
        if not (e["estado"] in ("caido", "degradado") or e["saturado"]):
            continue
        for local, remoto in ((a, b), (b, a)):
            rid = nodo_rid.get(remoto.get("nodo") or "")
            if not rid or not local.get("equipo") or not remoto.get("equipo"):
                continue
            for camino in _traza(local["equipo"], rid, remoto["equipo"]):
                for edge in camino:
                    if edge in afectadas or edge == (local["equipo"], local["interfaz"]):
                        continue
                    ae = idx.get(edge)
                    if ae is not None and ae is not e:
                        ae["reenvio"] = True
                        hacia = ae.setdefault("reenvio-hacia", [])
                        if remoto["nodo"] not in hacia:
                            hacia.append(remoto["nodo"])

    enlaces.sort(key=lambda e: (e["red"], e["a"]["equipo"], e["a"]["interfaz"]))
    nodos.sort(key=lambda n: (n["externo"], n["id"]))
    return {"nodos": nodos, "enlaces": enlaces}


def _armar_enlace(a, b):
    if not b:
        if a.get("sin-vecino"):
            estado = "caido" if not a["running"] else "sin-ospf"
        else:
            estado = "un-lado"
    elif not a["running"] or not b["running"]:
        estado = "caido"
    elif a["ospf"] == "Full" and b["ospf"] == "Full":
        estado = "full"
    elif a["ospf"] or b["ospf"]:
        estado = "degradado"
    else:
        estado = "sin-ospf"
    pcts = [a["pct"]] + ([b["pct"]] if b else [])
    return {
        "red": a["red"] or (b["red"] if b else ""),
        "estado": estado,
        "pct": max(pcts),
        "a": a,
        "b": b,
        "id": f"{a['equipo']}:{a['interfaz']}",
    }


def _leer_equipo(api, host):
    """Una pasada de lecturas de las que depende el monitoreo y la topologia."""
    return {
        "filas": tm.interfaces_con_trafico(api),
        "dirs": tm._filas(api, "/ip/address/print"),
        "ospf-itf": tm.ospf_interfaces_lista(api),
        "ospf-vec": tm.ospf_vecinos(api),
        "mndp": tm.vecinos_interfaz(api),
    }


def _intentar_reconectar(host):
    """Pide a la app reconectar el equipo si su API dejo de responder."""
    fn = _reconectar[0]
    if not fn:
        return None
    try:
        return fn(host)
    except Exception:  # noqa: BLE001
        return None


def _recoger_host(sesiones, host):
    """I/O de red de un equipo. Se ejecuta en paralelo, uno por host."""
    th = time.time()
    ses = sesiones.get(host) or {}
    api = ses.get("api")
    if not api:
        return None
    err = None
    leido = None
    marcas = []
    # Chequeo rapido del puerto API (0,4 s): evita leer o reconectar el socket
    # de un router apagado, que cuesta segundos por consulta/intento. Y cuando
    # el router vuelve, el puerto responde al instante y se reabre.
    try:
        puerto_ok = bool(tm._puerto_abierto(host, 8728, timeout=0.4))
    except Exception:  # noqa: BLE001
        puerto_ok = True
    marcas.append("puerto=%s/%.2f" % (puerto_ok, time.time() - th))
    if not puerto_ok:
        err = "puerto API cerrado (¿apagado?)"
        try:
            api._rota = True
        except Exception:  # noqa: BLE001
            pass
    elif not getattr(api, "rota", False):
        _t = time.time()
        try:
            leido = _leer_equipo(api, host)
            if not (leido.get("filas") or leido.get("dirs")):
                # Un socket muerto a veces devuelve vacio en vez de error.
                leido = None
                err = "sin respuesta (¿apagado?)"
                try:
                    api._rota = True
                except Exception:  # noqa: BLE001
                    pass
        except Exception as e:  # noqa: BLE001
            err = str(e)
            try:
                api._rota = True
            except Exception:  # noqa: BLE001
                pass
        marcas.append("leer=%.2f" % (time.time() - _t))
    if leido is None and puerto_ok:
        # El puerto responde pero la sesion puede haber quedado vieja (p.ej. el
        # equipo se reinicio): reabrir la conexion.
        _t = time.time()
        api = _intentar_reconectar(host)
        marcas.append("recon=%.2f/%s" % (time.time() - _t, api is not None))
        if api is not None:
            # Tras un reinicio la identidad pudo haber cambiado: releerla.
            with _lock:
                _cache_id.pop(host, None)
                _cache_rid.pop(host, None)
            try:
                leido = _leer_equipo(api, host)
                if not (leido.get("filas") or leido.get("dirs")):
                    leido = None
                    err = err or "sin respuesta (¿apagado?)"
            except Exception as e:  # noqa: BLE001
                err = str(e)
                leido = None
    nombre = rid = None
    if leido is not None:
        nombre = _identidad(api, host)
        rid = _router_id(api, host)
    return {"host": host, "api": api, "leido": leido, "err": err,
            "nombre": nombre, "rid": rid, "th": th, "marcas": marcas}


def recoger(sesiones, hosts=None):
    """Lee de cada equipo todo lo necesario para monitoreo y topologia.

    Las lecturas de red de cada equipo corren en paralelo: asi un equipo lento
    (o recien encendido, cuya API todavia no responde) no demora a los demas.
    """
    elegidos = [h for h in (hosts or list(sesiones)) if h in sesiones]
    if not elegidos:
        return {}, []
    with _recoger_lock:
        trabajos = {}
        if len(elegidos) == 1:
            host = elegidos[0]
            try:
                trabajos[host] = _recoger_host(sesiones, host)
            except Exception as e:  # noqa: BLE001
                trabajos[host] = {"host": host, "api": None, "leido": None,
                                  "err": str(e), "nombre": None, "rid": None,
                                  "th": time.time(), "marcas": []}
        else:
            with ThreadPoolExecutor(max_workers=min(len(elegidos), 8)) as ex:
                futuros = {ex.submit(_recoger_host, sesiones, h): h for h in elegidos}
                for fut in as_completed(futuros):
                    host = futuros[fut]
                    try:
                        trabajos[host] = fut.result()
                    except Exception as e:  # noqa: BLE001
                        trabajos[host] = {"host": host, "api": None, "leido": None,
                                          "err": str(e), "nombre": None, "rid": None,
                                          "th": time.time(), "marcas": []}

    recogidos = {}
    equipos = []
    for host in elegidos:
        r = trabajos.get(host)
        if not r:
            continue
        leido = r["leido"]
        if leido is None:
            with _lock:
                _muestra.pop(host, None)
            equipos.append({"host": host, "ok": False,
                            "error": r["err"] or "sin respuesta (¿apagado?)",
                            "interfaces": []})
            continue
        filas = leido["filas"]
        dirs = leido["dirs"]
        ospf_itf = leido["ospf-itf"]
        ospf_vec = leido["ospf-vec"]
        mndp = leido["mndp"]
        nombre = r["nombre"]
        rid = r["rid"]
        interfaces = muestrear(host, filas)
        for i in interfaces:
            i["direccion"] = ""
        for d in dirs:
            for i in interfaces:
                if str(d.get("interface")) == i["nombre"]:
                    i["direccion"] = str(d.get("address") or "")
                    i["red"] = _red_de(d.get("address"))
        for i in interfaces:
            i["capacidad"] = capacidad(host, i["nombre"])
            i["pct"] = _utilizacion(i, i["capacidad"])
            i["alarma"] = None
        recogidos[host] = {
            "host": host,
            "identidad": nombre,
            "router-id": rid,
            "interfaces": interfaces,
            "dirs": dirs,
            "ospf-itf": ospf_itf,
            "ospf-vec": ospf_vec,
            "mndp": mndp,
        }
        equipos.append({
            "host": host,
            "identidad": nombre,
            "router-id": rid,
            "ok": True,
            "error": None,
            "interfaces": interfaces,
        })
    return recogidos, equipos


def topologia(sesiones, forzar=False):
    """Topologia detectada (nodos + enlaces), cacheada por TOPO_TTL."""
    with _lock:
        ts = _topo.get("ts")
        guardada = dict(_topo)
    if not forzar and time.time() - float(ts or 0) < TOPO_TTL:
        return guardada
    recogidos, _ = recoger(sesiones)
    nueva = _armar_topologia(recogidos, sesiones)
    nueva["ts"] = time.time()
    with _lock:
        _topo.clear()
        _topo.update(nueva)
    return nueva


def _existe_enlace(topo, host, iface):
    for e in topo.get("enlaces", []):
        for lado in (e.get("a"), e.get("b")):
            if lado and lado.get("equipo") == host and lado.get("interfaz") == iface:
                return e
    return None


def _extremos(topo, host, iface):
    e = _existe_enlace(topo, host, iface)
    if not e:
        return [(host, iface)]
    res = []
    for lado in (e.get("a"), e.get("b")):
        if lado and lado.get("equipo") and lado.get("interfaz") != "?":
            par = (lado["equipo"], lado["interfaz"])
            if par not in res:
                res.append(par)
    if not res:
        res = [(host, iface)]
    return res


def cambiar_costo(sesiones, host, interfaz, costo):
    """Cambia el costo OSPF de una interfaz (None = restaurar el dinámico)."""
    api = (sesiones.get(host) or {}).get("api")
    if not api:
        return False, f"No hay sesión activa con {host}."
    err = tm.fijar_costo_ospf(api, interfaz, costo)
    if err:
        return False, err
    with _lock:
        _topo["ts"] = 0.0
    if costo is None:
        return True, f"{host} {interfaz}: costo dinámico restaurado."
    return True, f"{host} {interfaz}: costo {costo} aplicado."


def cambiar_costo_enlace(sesiones, host, interfaz, costo, top=None):
    """Aplica el costo a los dos extremos del enlace. Devuelve (ok, mensajes)."""
    topo = top if top is not None else topologia(sesiones)
    extremos = _extremos(topo, host, interfaz)
    mensajes = []
    ok = True
    for eq, itf in extremos:
        bien, msg = cambiar_costo(sesiones, eq, itf, costo)
        ok = ok and bien
        mensajes.append(msg)
    return ok, mensajes


def _valor_metrica(fila, metrica):
    if metrica not in METRICAS:
        return None
    return _entero(fila.get(metrica))


def _cumple(valor, operador, umbral):
    if operador == ">":
        return valor > umbral
    if operador == ">=":
        return valor >= umbral
    if operador == "<":
        return valor < umbral
    if operador == "<=":
        return valor <= umbral
    if operador == "==":
        return valor == umbral
    if operador == "!=":
        return valor != umbral
    return valor >= umbral


def _nuevo_evento(**campos):
    with _lock:
        _seq[0] += 1
        ev = {"seq": _seq[0], "ts": time.time()}
        ev.update(campos)
        _eventos.append(ev)
        if len(_eventos) > 300:
            del _eventos[:-300]
    return ev


def eventos_desde(seq=0):
    with _lock:
        return [dict(e) for e in _eventos if int(e.get("seq") or 0) > int(seq or 0)]


def _host_por_equipo(equipo, equipos):
    """Traduce lo que el usuario escribió (host o identidad) al host real."""
    equipo = str(equipo or "").strip()
    if not equipo:
        return None
    for e in equipos:
        if equipo in (e.get("host"), e.get("identidad")):
            return e.get("host") or equipo
    return equipo


def _pares_de_entrada(topo, equipos, entrada):
    """Extremos afectados por una entrada (equipo/interfaz) de una regla."""
    host = _host_por_equipo(entrada.get("equipo"), equipos)
    if not host:
        return []
    iface = str(entrada.get("interfaz") or "")
    if entrada.get("enlace", True):
        return _extremos(topo, host, iface)
    return [(host, iface)]


def _reconciliar_costos(sesiones, topo, equipos, efectos_alarma):
    """Lleva los costos OSPF al estado deseado.

    Prioridad: alarma activa > regla de direccionamiento vigente > costo
    "normal" recordado > dinámico. Solo envía a los equipos la diferencia
    contra lo que ya había aplicado, así no reinicia OSPF en cada ciclo.
    """
    deseado = {}   # (host, iface) -> costo
    origen = {}    # (host, iface) -> etiqueta de dónde sale el costo
    regla, modo = regla_vigente(anticipo=ANTICIPO_RECONVERGENCIA)
    if regla is not None:
        etq = f"regla {(regla.get('nombre') or regla.get('id'))}"
        for ent in regla.get("entradas") or []:
            for par in _pares_de_entrada(topo, equipos, ent):
                deseado[par] = int(ent["costo"])
                origen[par] = etq
    with _lock:
        fallback = dict(_fallback)
    for par, info in fallback.items():
        if par not in deseado:
            deseado[par] = int(info.get("costo") or 0)
            origen[par] = "costo normal"
    for ef in efectos_alarma or []:
        etq = f"alarma {ef.get('nombre') or ef.get('alarma') or ''}".strip()
        for par in _pares_de_entrada(topo, equipos,
                                     {"equipo": ef.get("equipo"),
                                      "interfaz": ef.get("interfaz"),
                                      "enlace": True}):
            deseado[par] = int(ef["costo"])
            origen[par] = etq
    with _lock:
        aplicado = dict(_aplicado)
    # No escribir en equipos caidos: su socket esta muerto y fijar_costo_ospf
    # bloquearia el sondeo ~8 s por par. Se dejan pendientes en 'deseado' para
    # aplicarlos cuando el equipo vuelva a responder.
    caidos = {e.get("host") for e in (equipos or []) if not e.get("ok")}
    cambios = []
    for par in set(aplicado) | set(deseado):
        quieren = deseado.get(par)
        tienen = aplicado.get(par, {}).get("costo")
        if quieren == tienen:
            continue
        eq, itf = par
        api = (sesiones.get(eq) or {}).get("api")
        if not api or eq in caidos or getattr(api, "rota", False):
            continue
        try:
            err = tm.fijar_costo_ospf(api, itf, quieren)
        except Exception as e:  # noqa: BLE001
            err = str(e)
            try:
                api._rota = True
            except Exception:  # noqa: BLE001
                pass
        if err:
            cambios.append(err)
            continue
        if quieren is None:
            with _lock:
                _aplicado.pop(par, None)
            cambios.append(f"{eq} {itf}: costo dinámico")
        else:
            with _lock:
                _aplicado[par] = {"costo": quieren, "origen": origen.get(par, "")}
            cambios.append(f"{eq} {itf}: costo {quieren}")
    if cambios:
        with _lock:
            _topo["ts"] = 0.0
            _rutas_cache.clear()   # que el próximo trazado de camino no use rutas viejas
        _guardar()
    return cambios


def _evaluar_alarmas(sesiones, topo, equipos, ahora):
    """Mantiene el estado de cada regla y lanza eventos.

    Por defecto la regla se evalua por cada interfaz que matchea su alcance
    (equipo/identidad y patron de interfaz), asi que una sola regla puede
    disparar varias instancias a la vez.

    Con metrica "red-bps" la regla se evalua sobre la SUMA de rx+tx de
    TODAS las interfaces que matchean el alcance; es el mismo numero que
    muestra la tarjeta "Trafico total" del monitor, para que el umbral se
    pueda leer directo de ahi.

    El cambio de costo no se aplica aca: se devuelve la lista de 'efectos'
    activos y el reconciliador (con prioridad sobre las reglas de
    direccionamiento) es el que deja los costos puestos.

    Devuelve (resumen, efectos).
    """
    alarmas = config().get("alarmas") or []
    efectos = []
    resumen = []
    orden_sev = {"info": 1, "alerta": 2, "critico": 3}
    for al in alarmas:
        if not al.get("habilitada", True):
            continue
        eq = str(al.get("equipo") or "").strip()
        patron = str(al.get("interfaz") or "").strip() or "*"
        metrica = str(al.get("metrica") or "pct")
        op = str(al.get("operador") or ">=")
        umbral = float(al.get("umbral") or 0)
        dur = float(al.get("duracion-s") or 0)
        limpia = float(al.get("limpiar-s") or 0)
        severidad = str(al.get("severidad") or "alerta")
        accion = str(al.get("accion") or "manual")
        try:
            costo = int(float(al.get("costo"))) if al.get("costo") is not None else None
        except (TypeError, ValueError):
            costo = None
        try:
            cn = int(float(al.get("costo-normal"))) if al.get("costo-normal") is not None else None
        except (TypeError, ValueError):
            cn = None

        # Interfaces que matchean el alcance de la regla.
        alcance = []
        for eq_datos in equipos:
            if not eq_datos.get("ok"):
                continue
            host = eq_datos["host"]
            if eq and eq not in (host, eq_datos.get("identidad") or ""):
                continue
            ident = eq_datos.get("identidad") or ""
            for fila in eq_datos.get("interfaces") or []:
                iface = fila.get("nombre") or ""
                if not fnmatch.fnmatchcase(iface, patron):
                    continue
                alcance.append((host, ident, iface, fila))

        # Instancias a evaluar: una por interfaz, o una sola con la suma.
        if metrica == "red-bps":
            if alcance:
                suma = sum(_entero(f[3].get("total-bps")) for f in alcance)
                orden = sorted(alcance,
                               key=lambda f: -_entero(f[3].get("total-bps")))
                instancias = [(f"red|{patron}", suma, "", "", patron, orden[:1], orden)]
            else:
                instancias = []
        else:
            instancias = []
            for (host, ident, iface, fila) in alcance:
                valor = _valor_metrica(fila, metrica)
                if valor is None:
                    continue
                instancias.append((f"{host}|{iface}", valor, host, ident, iface,
                                   [(host, ident, iface, fila)], alcance))

        if not instancias:
            resumen.append({
                "id": al["id"],
                "nombre": al.get("nombre") or al["id"],
                "host": "",
                "identidad": "",
                "interfaz": patron,
                "metrica": metrica,
                "operador": op,
                "umbral": umbral,
                "valor": None,
                "severidad": severidad,
                "accion": accion,
                "estado": "sin-datos",
                "desde": ahora,
                "duracion-s": dur,
                "limpiar-s": limpia,
            })
            continue

        for (suf, valor, host, ident, iface, objetivos, _alcance) in instancias:
            clave = f"{al['id']}|{suf}"
            with _lock:
                est = _estados.setdefault(clave, {
                    "activa": False, "cond": None, "t": ahora,
                    "valor": valor, "desde": ahora, "costos": [],
                })
            cumple = _cumple(valor, op, umbral)
            if cumple != bool(est.get("cond")):
                est["cond"] = cumple
                est["t"] = ahora
            est["valor"] = valor
            etiqueta = iface if metrica != "red-bps" else f"total de red ({patron})"
            quien = ident or host or "red"
            if cumple and not est["activa"] and ahora - est["t"] >= dur:
                est["activa"] = True
                est["desde"] = ahora
                mensaje = (f"{quien} {etiqueta}: "
                           f"{metrica}={valor} {op} {umbral:g} ({severidad})")
                accion_txt = ""
                if accion == "automatica":
                    if costo is not None:
                        for (ohost, _oident, oiface, _ofila) in objetivos:
                            efectos.append({
                                "equipo": ohost, "interfaz": oiface,
                                "costo": max(1, min(65535, costo)),
                                "alarma": al["id"],
                                "nombre": al.get("nombre") or al["id"],
                            })
                        accion_txt = f"costo {costo} al enlace (prioridad alarma)"
                        mensaje += f" -> {accion_txt}"
                    if cn is not None:
                        with _lock:
                            for (ohost, _oident, oiface, _ofila) in objetivos:
                                for par in _extremos(topo, ohost, oiface):
                                    _fallback[par] = {"costo": max(1, min(65535, cn)),
                                                      "alarma": al["id"]}
                eq_ev = host or (objetivos[0][0] if objetivos else "")
                _nuevo_evento(tipo="activada", alarma=al["id"],
                               nombre=al.get("nombre") or al["id"],
                               severidad=severidad, equipo=eq_ev,
                               identidad=ident, interfaz=iface, valor=valor,
                               umbral=umbral, metrica=metrica, mensaje=mensaje,
                               detalle=accion_txt)
            elif not cumple and est["activa"] and ahora - est["t"] >= limpia:
                est["activa"] = False
                est["desde"] = ahora
                mensaje = (f"{quien} {etiqueta}: "
                           f"{metrica}={valor} recuperada")
                if accion == "automatica":
                    mensaje += " (vuelve a la regla de direccionamiento activa)"
                est["costos"] = []
                _nuevo_evento(tipo="desactivada", alarma=al["id"],
                               nombre=al.get("nombre") or al["id"],
                               severidad="ok", equipo=host, identidad=ident,
                               interfaz=iface, valor=valor, umbral=umbral,
                               metrica=metrica, mensaje=mensaje, detalle="")
            if est["activa"]:
                for (_h, _i, _if, fila) in objetivos:
                    previa = fila.get("alarma")
                    if orden_sev.get(severidad, 0) >= orden_sev.get(previa or "", 0):
                        fila["alarma"] = severidad
            resumen.append({
                "id": al["id"],
                "nombre": al.get("nombre") or al["id"],
                "host": host,
                "identidad": ident,
                "interfaz": iface,
                "metrica": metrica,
                "operador": op,
                "umbral": umbral,
                "valor": valor,
                "severidad": severidad,
                "accion": accion,
                "estado": "activa" if est["activa"] else "ok",
                "desde": est.get("desde") or ahora,
                "duracion-s": dur,
                "limpiar-s": limpia,
            })
    return resumen, efectos


def _lado_de(topo, host, iface):
    for e in topo.get("enlaces", []):
        for lado in (e.get("a"), e.get("b")):
            if lado and lado.get("equipo") == host and lado.get("interfaz") == iface:
                return lado
    return None


def _poll_bajo_lock(sesiones, hosts=None):
    """Cuerpo de un ciclo de sondeo. Se ejecuta con _poll_lock ya tomado."""
    global _efectos_activos
    recogidos, equipos = recoger(sesiones, hosts)
    topo = _armar_topologia(recogidos, sesiones)
    topo["ts"] = time.time()
    with _lock:
        _topo.clear()
        _topo.update(topo)
    alarmas, efectos = _evaluar_alarmas(sesiones, topo, equipos, time.time())
    with _lock:
        _efectos_activos = efectos
    cambios = _reconciliar_costos(sesiones, topo, equipos, efectos)
    if cambios:
        topo = _armar_topologia(recogidos, sesiones)
        topo["ts"] = time.time()
        with _lock:
            _topo.clear()
            _topo.update(topo)
    regla_vig, _modo = regla_vigente(anticipo=ANTICIPO_RECONVERGENCIA)
    dir_estado = estado_direccionamiento()
    dir_estado["caminos"] = _caminos_regla(topo, sesiones, regla_vig)
    with _lock:
        ultimo = _seq[0]
    res = {
        "ok": True,
        "ts": time.time(),
        "equipos": equipos,
        "alarmas": alarmas,
        "topologia": topo,
        "direccionamiento": dir_estado,
        "seq": ultimo,
    }
    with _lock:
        _ultimo.clear()
        _ultimo.update(res)
    return res


def poll(sesiones, hosts=None):
    """Ciclo completo de monitoreo: lee, calcula, evalúa alarmas, arma topología.

    Un candado propio evita que dos refrescos simultáneos (por ejemplo al
    reanudar la pestaña) lean y escriban el estado de las alarmas a la vez.
    """
    with _poll_lock:
        return _poll_bajo_lock(sesiones, hosts)


def intentar_poll(sesiones, hosts=None):
    """Igual que poll() pero sin bloquear: si ya hay un ciclo en curso devuelve
    None de inmediato, para que una petición HTTP no quede esperando a que
    termine el sondeo (clave cuando un router recién encendido responde lento)."""
    if not _poll_lock.acquire(blocking=False):
        return None
    try:
        return _poll_bajo_lock(sesiones, hosts)
    finally:
        _poll_lock.release()


def snapshot():
    """Último resultado de sondeo ya calculado, o None si todavía no hubo uno."""
    with _lock:
        return dict(_ultimo) if _ultimo else None


def olvidar_snapshot():
    """Descarta el último sondeo (al desconectar todos los equipos)."""
    with _lock:
        _ultimo.clear()



def restaurar_todos(sesiones, hosts=None):
    """Devuelve TODOS los costos OSPF a dinámico (borra las filas estáticas).

    Sirve para limpiar de golpe lo que el motor o cambios manuales hayan
    dejado puesto, incluso si la app se reinició y perdió el registro."""
    elegidos = [h for h in (hosts or list(sesiones)) if h in sesiones]
    msgs = []
    ok = True
    for host in elegidos:
        api = (sesiones.get(host) or {}).get("api")
        if not api or getattr(api, "rota", False):
            continue
        try:
            filas = tm.ospf_interfaces_lista(api)
        except Exception as e:  # noqa: BLE001
            msgs.append(f"{host}: {e}")
            ok = False
            try:
                api._rota = True
            except Exception:  # noqa: BLE001
                pass
            continue
        for f in filas:
            if not f.get("estatico"):
                continue
            err = tm.fijar_costo_ospf(api, f.get("interfaz"), None)
            if err:
                msgs.append(err)
                ok = False
            else:
                msgs.append(f"{host} {f.get('interfaz')}: costo dinámico")
    with _lock:
        _aplicado.clear()
        _fallback.clear()
        _topo["ts"] = 0.0
    _guardar()
    return ok, msgs


def ultimo_poll():
    """Marca de tiempo del último ciclo completo (para el hilo de fondo)."""
    with _lock:
        return float(_topo.get("ts") or 0.0)


def aplicar_regla_ahora(sesiones):
    """Empuja ya el estado deseado usando la topología ya detectada.

    Así, al cambiar de una regla a otra, los costos se aplican sin esperar al
    próximo ciclo completo (que relee tráfico e interfaces de cada equipo)."""
    if not sesiones:
        return []
    with _lock:
        topo = {"ts": _topo.get("ts"),
                "nodos": list(_topo.get("nodos") or []),
                "enlaces": list(_topo.get("enlaces") or [])}
        efectos = list(_efectos_activos)
    if not topo.get("nodos") and not topo.get("enlaces"):
        return []
    equipos = []
    vistos = set()
    for n in topo.get("nodos", []):
        h = n.get("host")
        if h and h not in vistos:
            vistos.add(h)
            equipos.append({"host": h, "identidad": n.get("identidad") or ""})
    for h in sesiones:
        if h not in vistos:
            vistos.add(h)
            api = (sesiones.get(h) or {}).get("api")
            equipos.append({"host": h, "identidad": "",
                            "ok": not getattr(api, "rota", False)})
    with _poll_lock:
        return _reconciliar_costos(sesiones, topo, equipos, efectos)


def metricas(sesiones, hosts=None):
    """Costos y estado OSPF por interfaz, para la pestaña de métricas."""
    elegidos = [h for h in (hosts or list(sesiones)) if h in sesiones]
    salida = []
    for host in elegidos:
        api = (sesiones.get(host) or {}).get("api")
        if not api:
            continue
        if getattr(api, "rota", False):
            salida.append({"host": host, "ok": False,
                           "error": "sin respuesta (¿apagado?)", "interfaces": []})
            continue
        try:
            filas = tm.ospf_interfaces_lista(api)
            nombre = _identidad(api, host)
        except Exception as e:  # noqa: BLE001
            salida.append({"host": host, "ok": False, "error": str(e), "interfaces": []})
            continue
        salida.append({
            "host": host,
            "identidad": nombre,
            "ok": True,
            "error": None,
            "interfaces": filas,
        })
    return salida


def reiniciar_estados():
    with _lock:
        _estados.clear()
        _eventos.clear()
        _seq[0] = 0
    return True
