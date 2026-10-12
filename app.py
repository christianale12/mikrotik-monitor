#!/usr/bin/env python3
"""
App Flask "Monitor MikroTik" - consultas a la API de MikroTik (RouterOS 6.x)
=============================================================================
Backend que provee:

  GET  /                      -> pagina principal (HTML + Jinja)
  POST /api/escanear          -> escanear la red local buscando MikroTiks
  POST /api/conectar          -> abrir sesion API con host/usuario/clave
  POST /api/datos             -> obtener una categoria de informacion
  POST /api/desconectar       -> cerrar la sesion

La conexion se mantiene viva entre consultas en memoria (una sola ventana).
"""

import os
import sys
import io
import time
import threading

import yaml
from flask import Flask, jsonify, render_template, request

import monitoreo as mono
import transporte_mikrotik as tm


if getattr(sys, "frozen", False):
    _BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))


def _dir_datos():
    """Carpeta escribible junto al exe (o al script) para monitoreo.yml."""
    if getattr(sys, "frozen", False):
        carpeta = os.path.dirname(os.path.abspath(sys.executable))
    else:
        carpeta = os.path.dirname(os.path.abspath(__file__))
    try:
        os.makedirs(carpeta, exist_ok=True)
    except OSError:
        carpeta = os.path.expanduser("~")
    return carpeta

# Prioridad a los templates editables (al lado del exe / carpeta del proyecto)
_EXTERNO = os.path.join(os.path.dirname(__file__), "templates")
if not os.path.isdir(_EXTERNO) and getattr(sys, "frozen", False):
    _junto_exe = os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "templates")
    _arriba = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.executable))), "templates")
    for _c in (_junto_exe, _arriba):
        if os.path.isdir(_c):
            _EXTERNO = _c
            break
_TEMPL = _EXTERNO if os.path.isdir(_EXTERNO) else os.path.join(_BASE, "templates")

app = Flask(__name__, template_folder=_TEMPL)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = "monitor_mikrotik_secret"

# Sesiones activas: host -> {"api": api, "host": host, "usuario": usuario}
SESIONES = {}

# Alarmas y capacidades de enlace (monitoreo.yml junto al exe)
mono.iniciar(_dir_datos())


def _hilo_reconciliador():
    """Mantiene los costos OSPF en su estado deseado aunque la interfaz esté
    cerrada: si no hay regla vigente, devuelve a dinámico lo que el motor había
    cambiado (evita que quede "pegado" el camino de la última regla)."""
    while True:
        time.sleep(3)
        try:
            if not SESIONES:
                continue
            if time.time() - mono.ultimo_poll() < 8:
                continue
            mono.poll(SESIONES)
        except Exception:  # noqa: BLE001
            pass


threading.Thread(target=_hilo_reconciliador, daemon=True).start()


def _datos_request():
    """Devuelve el payload del request (JSON o formulario)."""
    return request.get_json(silent=True) or request.form


def _api_para(datos):
    """Devuelve (api, host, error) para el host pedido en los datos.

    Si no se indica host, se usa la unica sesion activa; si hay varias
    se pide que se especifique. Mantiene compatibilidad con la UI anterior.
    """
    host = (datos.get("host") or datos.get("equipo") or "").strip()
    if not host:
        if len(SESIONES) == 1:
            host = next(iter(SESIONES))
        elif len(SESIONES) > 1:
            return None, None, "Hay varias sesiones abiertas; indicá qué equipo (host)."
        else:
            return None, None, "No hay sesiones activas. Conectá un MikroTik primero."
    ses = SESIONES.get(host)
    if not ses:
        return None, None, f"No hay sesión activa para {host}."
    return ses.get("api"), host, None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/escanear", methods=["POST"])
def escanear():
    try:
        encontrados, redes, ip_local = tm.detectar_mikrotiks(timeout=0.5)
        return jsonify({"ok": True, "redes": redes, "ip_local": ip_local, "hosts": encontrados})
    except tm.ErrorMikroTik as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/identificar", methods=["POST"])
def identificar():
    datos = request.get_json(silent=True) or request.form
    host = (datos.get("host") or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "Falta la IP del MikroTik."})
    try:
        info = tm.identificar_host(host)
        return jsonify({"ok": True, "info": info})
    except tm.ErrorMikroTik as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/conectar", methods=["POST"])
def conectar():
    """Conecta UN equipo. Tambien admite una lista 'equipos' para conectar varios."""
    datos = _datos_request()
    host = (datos.get("host") or "").strip()
    usuario = (datos.get("usuario") or "").strip()
    password = datos.get("password") or ""

    if not host or not usuario:
        return jsonify({"ok": False, "error": "Faltan IP y usuario."})

    try:
        api = tm.conectar(host, usuario, password)
    except tm.ErrorMikroTik as e:
        SESIONES.pop(host, None)
        return jsonify({"ok": False, "host": host, "error": str(e)})

    # Guardar y verificar con un estado general
    SESIONES[host] = {"api": api, "host": host, "usuario": usuario}
    try:
        estado = tm.estado_general(api)
    except tm.ErrorMikroTik as e:
        return jsonify({"ok": True, "host": host, "mensaje": f"Conectado (no se pudo leer estado: {e})"})

    return jsonify({"ok": True, "host": host, "estado": estado, "conectados": list(SESIONES)})


@app.route("/api/conectar_multi", methods=["POST"])
def conectar_multi():
    """Conecta varios MikroTik a la vez. Recibe 'equipos': [{host,usuario,password}]
    o directamente el 'yaml' de una topología (con 'equipos' dentro)."""
    datos = _datos_request()
    equipos = datos.get("equipos")
    if isinstance(equipos, str):
        try:
            import json as _json_eq
            equipos = _json_eq.loads(equipos)
        except Exception:  # noqa: BLE001
            return jsonify({"ok": False, "error": "equipos debe ser una lista JSON."})

    if not isinstance(equipos, list) or not equipos:
        # soporte: conectar desde un YAML de topología
        texto = datos.get("yaml") or ""
        if not texto:
            return jsonify({"ok": False, "error": "Falta la lista 'equipos' o el YAML a conectar."})
        try:
            doc = yaml.safe_load(texto) or {}
        except Exception as e:  # noqa: BLE001
            return jsonify({"ok": False, "error": f"El YAML no es válido: {e}"})
        topo = doc.get("ospf", doc) if isinstance(doc, dict) else {}
        equipos = topo.get("equipos") or []
        if not isinstance(equipos, list) or not equipos:
            return jsonify({"ok": False, "error": "El YAML no define 'equipos'."})

    resultados = []
    for eq in equipos:
        host = str(eq.get("host") or "").strip()
        usr = str(eq.get("usuario") or "admin").strip()
        pwd = str(eq.get("password") or "")
        if not host:
            resultados.append({"host": host, "ok": False, "error": "Falta IP."})
            continue
        try:
            api = tm.conectar(host, usr, pwd)
            SESIONES[host] = {"api": api, "host": host, "usuario": usr}
            ident = ""
            try:
                ident = tm.estado_general(api).get("identidad", "")
            except Exception:  # noqa: BLE001
                pass
            resultados.append({"host": host, "ok": True, "identidad": ident})
        except tm.ErrorMikroTik as e:
            resultados.append({"host": host, "ok": False, "error": str(e)})

    return jsonify({"ok": True, "resultados": resultados, "conectados": list(SESIONES)})


@app.route("/api/equipos", methods=["POST", "GET"])
def equipos():
    """Lista los equipos conectados y su estado."""
    lista = []
    for host, ses in SESIONES.items():
        api = ses.get("api")
        ident = ""
        try:
            ident = tm.estado_general(api).get("identidad", "")
        except Exception:  # noqa: BLE001
            pass
        lista.append({
            "host": host,
            "usuario": ses.get("usuario", ""),
            "identidad": ident,
            "conectado": True,
        })
    return jsonify({"ok": True, "equipos": lista, "activo": list(SESIONES)[0] if len(SESIONES) == 1 else ""})


def _ctx_topo(datos):
    """(topo, equipos_list, error) desde el 'yaml' o 'config' recibido.

    El YAML puede venir como texto ('yaml') o ya parseado ('config').
    'topo' es el diccionario con area / redistribute-connected / equipos.
    """
    texto = datos.get("yaml") or ""
    config = datos.get("config")
    try:
        if isinstance(config, dict):
            doc = config
        elif texto:
            doc = yaml.safe_load(texto) or {}
        else:
            return None, None, "Falta el YAML de topología OSPF."
    except Exception as e:  # noqa: BLE001
        return None, None, f"El YAML no es válido: {e}"

    topo = doc.get("ospf", doc) if isinstance(doc, dict) else {}
    equipos_list = topo.get("equipos") or []
    if not isinstance(equipos_list, list) or not equipos_list:
        return None, None, "El YAML no define 'equipos'."
    return topo, equipos_list, None


def _peerdatos(equipos_list):
    """{identity: {redes, router-id}} de los equipos del YAML.

    Hace falta para que cada router reconozca quién está detrás de cada
    cable (la identidad que manda por MNDP no es la IP). Escala con la
    cantidad de equipos que haya en el YAML, sin límite.
    """
    peerdatos = {}
    for eq in equipos_list:
        host = str(eq.get("host") or "").strip()
        if not host:
            continue
        ses = SESIONES.get(host)
        if ses and ses.get("api"):
            api_p = ses["api"]
        else:
            try:
                api_p = tm.conectar(host,
                                    str(eq.get("usuario") or "admin").strip(),
                                    str(eq.get("password") or ""))
            except tm.ErrorMikroTik:
                continue
        try:
            ident = tm.estado_general(api_p).get("identidad", "")
        except Exception:  # noqa: BLE001
            ident = ""
        if ident:
            peerdatos[ident] = {"redes": eq.get("networks") or [],
                                "router-id": str(eq.get("router-id") or "").strip()}
    return peerdatos


def _aplicar_topo(datos, aplicar):
    """Recorre los equipos del YAML y ejecuta 'aplicar' en cada uno.

    'aplicar(api, eq, peerdatos, area, redistribute)' devuelve la lista de
    mensajes. Tanto el paso 1 (OSPF) como el paso 2 (interfaces por cable)
    usan este mismo recorrido, así que no hay nada repetido ni fijo: los
    equipos son los que traiga el YAML.
    """
    topo, equipos_list, err = _ctx_topo(datos)
    if err:
        return {"ok": False, "error": err}

    area = str(topo.get("area") or "0.0.0.0")
    _r = topo.get("redistribute-connected", False)
    redistribute = _r if isinstance(_r, bool) else str(_r).strip().lower() in ("1", "true", "yes", "on")

    solo = datos.get("equipos")
    if isinstance(solo, str):
        try:
            import json as _json_solo
            solo = _json_solo.loads(solo)
        except Exception:  # noqa: BLE001
            solo = [s.strip() for s in solo.split(",") if s.strip()]
    if isinstance(solo, list) and solo:
        objetivos = {str(x) for x in solo}
        equipos_list = [e for e in equipos_list if str(e.get("host") or "").strip() in objetivos]

    peerdatos = _peerdatos(equipos_list)
    resultados = []
    for eq in equipos_list:
        host = str(eq.get("host") or "").strip()
        usr = str(eq.get("usuario") or "admin").strip()
        pwd = str(eq.get("password") or "")
        router_id = str(eq.get("router-id") or "").strip()
        if not host or not router_id:
            resultados.append({"host": host or router_id, "ok": False,
                               "router-id": router_id, "error": "Faltan host y/o router-id."})
            continue

        ses = SESIONES.get(host)
        if ses and ses.get("api"):
            api = ses["api"]
        else:
            try:
                api = tm.conectar(host, usr, pwd)
                SESIONES[host] = {"api": api, "host": host, "usuario": usr}
            except tm.ErrorMikroTik as e:
                resultados.append({"host": host, "ok": False, "router-id": router_id,
                                   "error": str(e)})
                continue

        try:
            msgs = aplicar(api, eq, peerdatos, area, redistribute)
            resultados.append({"host": host, "ok": True, "router-id": router_id,
                               "mensajes": msgs, "error": None})
        except Exception as e:  # noqa: BLE001
            resultados.append({"host": host, "ok": False, "router-id": router_id,
                               "error": str(e)})

    ok_n = sum(1 for r in resultados if r.get("ok"))
    return {"ok": ok_n == len(resultados), "aplicados": ok_n,
            "total": len(resultados), "resultados": resultados}


@app.route("/api/ospf_levantar", methods=["POST"])
def ospf_levantar():
    """Paso 1: levanta OSPF desde el YAML de topología.

    Configura loopback (/32 del router-id), instancia OSPF con su
    router-id y las redes OSPF del YAML en todos los equipos del
    documento ('equipos' opcional para restringir a unos pocos).
    Las IPs de los enlaces las asigna el paso 2 (/api/ospf_interfaces).
    """
    datos = _datos_request()

    def _aplicar(api, eq, peerdatos, area, redistribute):
        return tm.configurar_ospf(api, str(eq.get("router-id") or "").strip(),
                                  eq.get("networks") or [], area=area,
                                  redistribute=redistribute,
                                  loopback=eq.get("loopback"))

    return jsonify(_aplicar_topo(datos, _aplicar))


@app.route("/api/ospf_interfaces", methods=["POST"])
def ospf_interfaces():
    """Paso 2: configura las interfaces según cómo estén cableadas.

    En cada equipo descubre por MNDP qué vecino hay en cada interfaz,
    y pone la IP /30 que le corresponde según la red que ese par comparte
    en el YAML. Regenera además las redes OSPF a partir de lo cableado.
    Re-ejecutar resincroniza (sirve si se agregan/quitan placas, cables
    o routers).
    """
    datos = _datos_request()

    def _aplicar(api, eq, peerdatos, area, redistribute):
        return tm.configurar_p2p(api, str(eq.get("router-id") or "").strip(),
                                 eq.get("networks") or [], peerdatos,
                                 host=str(eq.get("host") or "").strip(),
                                 area=area)

    return jsonify(_aplicar_topo(datos, _aplicar))


@app.route("/api/ospf_generar", methods=["POST"])
def ospf_generar():
    """Arma el inventario OSPF (ospf.yml) solo, leyendo la topología por MNDP.

    Recorre los equipos (los pedidos en 'equipos'/'hosts' o, si no hay,
    los que aparezcan escaneando la red), deduce por vecinos MNDP quién
    está cableado con quién, numera R1..Rn, fija identidad (R<n>) y clave
    si se pide, y devuelve el YAML listo para el paso 1.
    """
    datos = _datos_request()
    usuario = (datos.get("usuario") or "admin").strip()
    password = datos.get("password")
    password = "123" if password is None else str(password)
    identidad_pedida = datos.get("identidad")
    fijar = True if identidad_pedida is None else bool(identidad_pedida)
    clave_pedida = datos.get("clave")
    clave = password if clave_pedida is None and fijar else clave_pedida

    hosts = _lista_hosts(datos)
    if not hosts:
        if SESIONES:
            hosts = list(SESIONES)
        else:
            try:
                hosts, _redes, _ip = tm.detectar_mikrotiks(timeout=0.5)
            except tm.ErrorMikroTik as e:
                return jsonify({"ok": False, "error": str(e)})
    if not hosts:
        return jsonify({"ok": False, "error": "No se encontró ningún MikroTik en la red."})

    try:
        res = tm.generar_inventario_ospf(
            hosts, usuario=usuario, password=password,
            fijar_identidad=fijar, forzar_identidad=fijar, fijar_clave=clave)
    except tm.ErrorMikroTik as e:
        return jsonify({"ok": False, "error": str(e)})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True, "escaneados": hosts, **res})


@app.route("/api/datos", methods=["POST"])
def datos():
    datos = _datos_request()
    categoria = datos.get("categoria", "")

    api, host, err = _api_para(datos)
    if err:
        return jsonify({"ok": False, "error": err})

    try:
        if categoria == "estado":
            data = tm.estado_general(api)
        elif categoria == "interfaces":
            data = tm.interfaces_lista(api)
        elif categoria == "ip":
            data = {
                "direcciones": tm.ips_completas(api),
                "arp": tm.arp_lista(api),
                "dhcp": tm.dhcp_lista(api),
            }
        elif categoria == "rutas":
            data = {
                "rutas": tm.rutas_lista(api),
                "firewall": tm.filtros_lista(api),
            }
        elif categoria == "vlanes":
            data = tm.vlanes(api)
        elif categoria == "nat":
            data = tm.nat(api)
        elif categoria == "wifi":
            data = tm.clientes_wifi(api)
        elif categoria == "ospf":
            data = {
                "instancias": tm.ospf_instancias(api),
                "areas": tm.ospf_areas(api),
                "vecinos": tm.ospf_vecinos(api),
                "redes": tm.ospf_redes(api),
                "rutas": tm.ospf_rutas(api),
            }
        elif categoria == "trafico":
            data = tm.interfaces_con_trafico(api)
        else:
            return jsonify({"ok": False, "error": f"Categoria desconocida: {categoria}"})
    except tm.ErrorMikroTik as e:
        return jsonify({"ok": False, "error": str(e)})

    return jsonify({"ok": True, "host": host, "categoria": categoria, "datos": data})


def _lista_hosts(datos):
    """Hosts pedidos en el request: lista, texto separado por comas o None."""
    hosts = datos.get("hosts") or datos.get("equipos")
    if isinstance(hosts, str):
        hosts = [h.strip() for h in hosts.split(",") if h.strip()]
    if isinstance(hosts, list) and hosts:
        return [str(h).strip() for h in hosts if str(h).strip()]
    return None


@app.route("/api/monitoreo", methods=["POST"])
def api_monitoreo():
    """Ciclo del monitoreo en vivo: tasas, alarmas activas y eventos nuevos.

    'desde' es el ultimo seq que vio el cliente, asi solo recibe los
    eventos que aparecieron desde entonces.
    """
    datos = _datos_request()
    if not SESIONES:
        return jsonify({"ok": True, "ts": time.time(), "equipos": [],
                        "alarmas": [], "seq": 0, "sin_sesion": True,
                        "eventos": mono.eventos_desde(datos.get("desde") or 0)})
    try:
        res = mono.poll(SESIONES, _lista_hosts(datos))
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)})
    res["eventos"] = mono.eventos_desde(datos.get("desde") or 0)
    return jsonify(res)


@app.route("/api/topologia", methods=["POST"])
def api_topologia():
    """Grafo detectado: nodos (routers) y enlaces (interfaces por cable)."""
    datos = _datos_request()
    if not SESIONES:
        return jsonify({"ok": True, "nodos": [], "enlaces": [], "ts": time.time()})
    try:
        res = mono.topologia(SESIONES, forzar=bool(datos.get("forzar")))
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True, "nodos": res.get("nodos") or [],
                    "enlaces": res.get("enlaces") or [], "ts": res.get("ts")})


@app.route("/api/alarmas", methods=["POST"])
def api_alarmas():
    """Alta/baja/consulta de reglas de alarma y su configuración."""
    datos = _datos_request()
    accion = str(datos.get("accion") or "listar").strip().lower()

    if accion == "guardar":
        lista = datos.get("alarmas")
        if isinstance(lista, list) and lista:
            cfg = mono.guardar_alarmas(lista)
        else:
            alarma = datos.get("alarma") or {}
            actual = mono.config().get("alarmas") or []
            aid = str(alarma.get("id") or "").strip()
            nuevo = [a for a in actual if str(a.get("id")) != aid]
            if not aid:
                alarma["id"] = f"al-{int(time.time())}"
            nuevo.append(alarma)
            cfg = mono.guardar_alarmas(nuevo)
        return jsonify({"ok": True, "config": cfg})

    if accion == "borrar":
        cfg = mono.borrar_alarma(datos.get("id"))
        return jsonify({"ok": True, "config": cfg})

    if accion == "restaurar_estados":
        mono.reiniciar_estados()
        return jsonify({"ok": True})

    return jsonify({"ok": True, "config": mono.config()})


@app.route("/api/direccionamiento", methods=["POST"])
def api_direccionamiento():
    """Reglas de direccionamiento por nombre (aplicar/quitar secuencias de costos)."""
    datos = _datos_request()
    accion = str(datos.get("accion") or "listar").strip().lower()

    def _aplicar_ya():
        try:
            mono.aplicar_regla_ahora(SESIONES)
        except Exception:  # noqa: BLE001
            pass

    if accion == "guardar":
        cfg = mono.guardar_direccionamiento(datos.get("reglas") or datos.get("direccionamiento"))
        threading.Thread(target=_aplicar_ya, daemon=True).start()
        return jsonify({"ok": True, "config": cfg})

    if accion == "borrar":
        cfg = mono.borrar_regla(datos.get("id"))
        threading.Thread(target=_aplicar_ya, daemon=True).start()
        return jsonify({"ok": True, "config": cfg})

    if accion == "activar":
        cfg = mono.activar_regla(datos.get("id"))
        threading.Thread(target=_aplicar_ya, daemon=True).start()
        return jsonify({"ok": True, "config": cfg})

    if accion in ("desactivar", "quitar"):
        cfg = mono.desactivar_regla()
        threading.Thread(target=_aplicar_ya, daemon=True).start()
        return jsonify({"ok": True, "config": cfg})

    if accion == "restaurar":
        ok, msgs = mono.restaurar_todos(SESIONES)
        return jsonify({"ok": True, "config": mono.config(), "resultado": msgs})

    estado = mono.estado_direccionamiento()
    estado["caminos"] = mono.caminos_vigentes(SESIONES)
    return jsonify({"ok": True, "config": mono.config(), "estado": estado})


@app.route("/api/capacidades", methods=["POST"])
def api_capacidades():
    """Velocidad de los enlaces (para el % de congestión) por equipo/interfaz."""
    datos = _datos_request()
    if str(datos.get("accion") or "").strip().lower() == "guardar":
        cfg = mono.config()
        if "default" in datos or "capacidades" in datos:
            cfg = mono.guardar_capacidades(datos.get("default"),
                                           datos.get("capacidades") or {})
        if datos.get("saturado-pct") is not None:
            cfg = mono.guardar_saturado(datos.get("saturado-pct"))
        return jsonify({"ok": True, "config": cfg})
    return jsonify({"ok": True, "config": mono.config()})


@app.route("/api/metricas", methods=["POST"])
def api_metricas():
    """Costos OSPF por interfaz y cambio manual (individual o de enlace)."""
    datos = _datos_request()
    accion = str(datos.get("accion") or "listar").strip().lower()

    if accion == "cambiar":
        host = str(datos.get("host") or datos.get("equipo") or "").strip()
        interfaz = str(datos.get("interfaz") or "").strip()
        if "costo" not in datos:
            return jsonify({"ok": False, "error": "Falta el costo."})
        bruto = datos.get("costo")
        costo = None  # null = borrar el override y volver al costo dinámico
        if bruto is not None:
            try:
                costo = int(bruto)
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "El costo debe ser un número."})
        if not host or not interfaz:
            return jsonify({"ok": False, "error": "Faltan equipo e interfaz."})
        try:
            if datos.get("enlace"):
                ok, mensajes = mono.cambiar_costo_enlace(SESIONES, host, interfaz, costo)
            else:
                ok, msg = mono.cambiar_costo(SESIONES, host, interfaz, costo)
                mensajes = [msg]
        except Exception as e:  # noqa: BLE001
            return jsonify({"ok": False, "error": str(e)})
        return jsonify({"ok": ok, "mensajes": mensajes})

    try:
        equipos = mono.metricas(SESIONES, _lista_hosts(datos))
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True, "equipos": equipos,
                    "topologia": mono.topologia(SESIONES)})


@app.route("/api/exportar", methods=["POST"])
def exportar():
    """Genera la configuracion del equipo en YAML con las secciones elegidas.

    La interfaz web envia en 'secciones' la lista de bloques a incluir
    (equipo, interfaces, ip, rutas, vlanes, filtros, nat, arp, dhcp).
    El usuario elige dónde guardar mediante el cuadro nativo 'Guardar como'.
    """
    if SESIONES and not any(s.get("api") for s in SESIONES.values()):
        return jsonify({"ok": False, "error": "No hay sesion activa. Conectate primero."})

    datos = _datos_request()
    api, host, err = _api_para(datos)
    if err:
        return jsonify({"ok": False, "error": err})
    secciones = datos.get("secciones")
    if isinstance(secciones, str):
        try:
            import json as _json
            secciones = _json.loads(secciones)
        except Exception:  # noqa: BLE001
            secciones = secciones.split(",")
    # "completa"/"todas" -> exportar todos los bloques (configuracion completa)
    if datos.get("completa") or (secciones and list(secciones) == ["completa"]):
        secciones = None

    try:
        config = tm.configuracion_completa(api, secciones=secciones)
    except tm.ErrorMikroTik as e:
        return jsonify({"ok": False, "error": str(e)})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Error generando la configuracion: {e}"})

    config["exportado"] = time.strftime("%Y-%m-%d %H:%M:%S")

    buffer = io.StringIO()
    yaml.safe_dump(
        {"mikrotik": config},
        buffer,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=120,
    )

    stamp = time.strftime("%Y%m%d-%H%M%S")
    ident = str(config.get("equipo", {}).get("identidad", "mikrotik")).strip()
    ident = "".join(c for c in ident if c.isalnum() or c in "-_") or "mikrotik"
    nombre_archivo = f"config_{ident}_{stamp}.yaml"

    return jsonify({"ok": True, "yaml": buffer.getvalue(), "archivo": nombre_archivo})


@app.route("/api/desconectar", methods=["POST"])
def desconectar():
    datos = _datos_request()
    host = (datos.get("host") or "").strip()
    if host:
        ses = SESIONES.pop(host, None)
        if ses:
            try:
                ses["api"].close()
            except Exception:  # noqa: BLE001
                pass
        return jsonify({"ok": True, "desconectado": host, "conectados": list(SESIONES)})
    for ses in SESIONES.values():
        try:
            ses["api"].close()
        except Exception:  # noqa: BLE001
            pass
    SESIONES.clear()
    return jsonify({"ok": True, "desconectado": "todos", "conectados": []})


# -------------------------------------------------------------------------
# Restauracion selectiva: aplicar a la API el valor de un solo item cambiado
# -------------------------------------------------------------------------
import re as _re

# Mapeo: seccion (clave del YAML) -> (ruta de print/set en la API,
#                                      campos editables  yaml -> campo RouterOS)
SECCIONES_API = {
    "interfaces": ("/interface", {
        "nombre": "name", "descripcion": "comment", "mtu": "mtu",
        "mac": "mac-address", "disabled": "disabled",
    }),
    "ip": ("/ip/address", {
        "interfaz": "interface", "direccion": "address", "red": "network",
    }),
    "rutas": ("/ip/route", {
        "destino": "dst-address", "gateway": "gateway", "distancia": "distance",
    }),
    "filtros": ("/ip/firewall/filter", {
        "cadena": "chain", "accion": "action", "protocolo": "protocol",
        "origen": "src-address", "destino": "dst-address",
        "puerto-origen": "src-port", "puerto-destino": "dst-port",
        "interfaz-origen": "in-interface", "interfaz-destino": "out-interface",
        "comentario": "comment", "disabled": "disabled",
    }),
    "nat": ("/ip/firewall/nat", {
        "cadena": "chain", "accion": "action", "protocolo": "protocol",
        "origen": "src-address", "destino": "dst-address",
        "puerto-origen": "src-port", "puerto-destino": "dst-port",
        "interfaz-origen": "in-interface", "interfaz-destino": "out-interface",
        "a-direccion": "to-addresses", "a-puerto": "to-ports",
        "comentario": "comment",
    }),
    "vlan": ("/interface/vlan", {
        "name": "name", "vlan-id": "vlan-id", "interface": "interface",
        "disabled": "disabled",
    }),
    "bridge": ("/interface/bridge", {
        "name": "name", "mtu": "mtu", "disabled": "disabled",
    }),
    "bridge_vlan": ("/interface/bridge/vlan", {
        "vlan-ids": "vlan-ids", "bridge": "bridge",
        "tagged": "tagged", "untagged": "untagged",
    }),
    "pools": ("/ip/pool", {
        "name": "name", "ranges": "ranges", "next-pool": "next-pool",
        "comentario": "comment",
    }),
    "dhcp_servidores": ("/ip/dhcp-server", {
        "nombre": "name", "interfaz": "interface", "pool": "address-pool",
        "lease-tiempo": "lease-time", "autoritativo": "authoritative",
        "dhcp-options": "dhcp-options", "comentario": "comment",
        "disabled": "disabled",
    }),
    "dhcp_redes": ("/ip/dhcp-server/network", {
        "direccion": "address", "gateway": "gateway", "dns": "dns-server",
        "ntp": "ntp-server", "dominio": "domain", "comentario": "comment",
    }),
    "equipo": ("/system/identity", {"identidad": "name"}),
}

_RUTA_RE = _re.compile(r"^(?P<seccion>[a-z_]+)(?:\.(?P<sub>[a-z_]+))?\[(?P<indice>\d+)\]\.(?P<campo>[^.]+)$")
_RUTA_FILA_RE = _re.compile(r"^(?P<seccion>[a-z_]+)(?:\.(?P<sub>[a-z_]+))?\[(?P<indice>\d+)\]$")
_RUTA_DICT_RE = _re.compile(r"^(?P<seccion>equipo)\.(?P<campo>[^.]+)$")

_LLAVES_FILA = {
    "interfaces": ("nombre",),
    "ip": ("interfaz", "direccion", "prefijo"),
    "rutas": ("destino",),
    "filtros": ("cadena", "accion", "protocolo", "origen", "destino", "puerto-origen", "puerto-destino",
                "interfaz-origen", "interfaz-destino", "comentario"),
    "nat": ("cadena", "accion", "protocolo", "origen", "destino", "puerto-origen", "puerto-destino",
            "interfaz-origen", "interfaz-destino", "comentario"),
    "vlan": ("name",),
    "bridge": ("name",),
    "bridge_vlan": ("bridge", "vlan-ids"),
    "pools": ("name",),
    "dhcp_servidores": ("nombre",),
    "dhcp_redes": ("direccion",),
    "usuarios": ("name",),
    "arp": ("direccion", "mac"),
    "dhcp": ("mac", "direccion"),
    "interfaz": ("interfaz",),  # no usado
}

# Secciones donde se permite restaurar una fila completa (crear/borrar item)
_SECCIONES_FILA = {"ip", "rutas", "filtros", "nat", "vlan", "bridge_vlan", "pools",
                   "dhcp_servidores", "dhcp_redes"}

# Campos volátiles que cambian en cada export y no indican un cambio de
# configuracion real: se ignoran al comparar.
_CAMPOS_DINAMICOS = {
    "hora", "uptime", "fecha", "exportado",
    "rx", "tx", "last-logged-in", "cache-used",
    "current-tagged", "current-untagged",
}


def _clave_fila(seccion, fila):
    """Tupla estable para identificar una fila de una lista en el YAML."""
    claves = _LLAVES_FILA.get(seccion)
    if not claves or not isinstance(fila, dict):
        return None
    return tuple(str(fila.get(k, "")) for k in claves)


def _fila_para_buscar(seccion, fila):
    """Traduce una fila YAML a claves RouterOS para buscar en el print."""
    if seccion == "interfaces" or seccion == "vlan" or seccion == "bridge":
        return {"name": str(fila.get("nombre", "") or fila.get("name", ""))}
    if seccion == "ip":
        pref = str(fila.get("prefijo", ""))
        dir_ip = str(fila.get("direccion", ""))
        addr = f"{dir_ip}/{pref}" if pref and not dir_ip.endswith(f"/{pref}") else dir_ip
        return {"address": addr}
    if seccion == "rutas":
        return {"dst-address": str(fila.get("destino", ""))}
    if seccion == "filtros":
        return {
            "chain": str(fila.get("cadena", "")),
            "src-address": str(fila.get("origen", "")),
            "action": str(fila.get("accion", "")),
            "comment": str(fila.get("comentario", "")),
            "protocol": str(fila.get("protocolo", "")),
            "dst-port": str(fila.get("puerto-destino", "")),
        }
    if seccion == "nat":
        return {
            "chain": str(fila.get("cadena", "")),
            "src-address": str(fila.get("origen", "")),
            "action": str(fila.get("accion", "")),
            "comment": str(fila.get("comentario", "")),
            "protocol": str(fila.get("protocolo", "")),
            "dst-port": str(fila.get("puerto-destino", "")),
        }
    if seccion == "bridge_vlan":
        return {
            "bridge": str(fila.get("bridge", "")),
            "vlan-ids": str(fila.get("vlan-ids", "")),
        }
    if seccion == "pools":
        return {"name": str(fila.get("name", ""))}
    if seccion == "dhcp_servidores":
        return {"name": str(fila.get("nombre", ""))}
    if seccion == "dhcp_redes":
        return {"address": str(fila.get("direccion", ""))}
    if seccion == "usuarios":
        return {"name": str(fila.get("name", ""))}
    if seccion == "arp":
        return {"address": str(fila.get("direccion", "")), "mac-address": str(fila.get("mac", ""))}
    if seccion == "dhcp":
        return {"mac-address": str(fila.get("mac", "")), "address": str(fila.get("direccion", ""))}
    return None


def _coincide_fila(seccion, fila_print, fila_yaml):
    """True si una fila del print del router representa la misma fila del YAML."""
    clave_bs = _fila_para_buscar(seccion, fila_yaml)
    if not clave_bs:
        return False
    for k, v in clave_bs.items():
        vp = fila_print.get(k)
        if vp is None:
            # RouterOS omite los campos vacios en el print: si el YAML
            # tambien los tiene vacios, la fila puede ser igual.
            if str(v) in ("", "false", "no"):
                continue
            return False
        vp = vp.decode(errors="replace") if isinstance(vp, bytes) else str(vp)
        if vp != v:
            return False
    return True


def _ubicar_lista(doc, seccion, sub):
    """Devuelve la lista de filas de una seccion dentro del YAML ya parseado."""
    if sub and isinstance(doc.get(seccion), dict):
        return doc[seccion].get(sub, [])
    lista = doc.get(seccion, [])
    return lista


def _valor_bytes_fila(fila, clave):
    v = fila.get(clave)
    if isinstance(v, bytes):
        return v.decode(errors="replace")
    return "" if v is None else str(v)


def _clave_api(seccion, sub):
    """Clave real en SECCIONES_API para una seccion del YAML."""
    if seccion in SECCIONES_API:
        return seccion
    if sub and sub in SECCIONES_API:
        return sub
    return None


def _buscar_fila_en_router(api, seccion, fila_yaml):
    """Devuelve el .id de la fila del router que coincide con la del YAML,
    o None si no existe."""
    path = SECCIONES_API[seccion][0]
    filas = list(api(f"{path}/print"))
    for f in filas:
        if _coincide_fila(seccion, f, fila_yaml):
            for k, v in (f.items() if isinstance(f, dict) else []):
                if k == ".id":
                    return v.decode() if isinstance(v, bytes) else str(v)
    return None


def _reposicionar_fila_nueva(api, path, seccion, fila_yaml, indice):
    """Mueve la fila recien creada a su posicion original en la lista.

    Tras /add la fila queda al final; se la mueve antes de la fila que hoy
    ocupa el indice pedido. Si el router no soporta move, se deja al final.
    """
    try:
        filas = list(api(f"{path}/print"))
    except Exception:  # noqa: BLE001
        return
    if not filas:
        return
    if indice < 0 or indice >= len(filas) - 1 or not isinstance(filas[-1], dict):
        # Ya esta al final (o no hay donde mover): no hace falta.
        return
    nuevo_id = None
    for k, v in filas[-1].items():
        if k == ".id":
            nuevo_id = v.decode() if isinstance(v, bytes) else str(v)
    dest_id = None
    for k, v in filas[indice].items():
        if k == ".id":
            dest_id = v.decode() if isinstance(v, bytes) else str(v)
    if not nuevo_id or not dest_id or nuevo_id == dest_id:
        return
    try:
        list(api(f"{path}/move", **{"numbers": nuevo_id, "destination": dest_id}))
    except Exception:  # noqa: BLE001
        try:
            list(api(f"{path}/move", **{".id": nuevo_id, "destination": dest_id}))
        except Exception:  # noqa: BLE001
            pass


def _es_fila_dinamica(fila_yaml):
    """True si la fila del YAML es dinamica (la gestiona RouterOS)."""
    v = fila_yaml.get("dinamica") if isinstance(fila_yaml, dict) else None
    return str(v).lower() in ("true", "yes")


def _restaurar_ruta_dinamica(api, ruta, fila_a):
    """Restaura una ruta conectada (dinamica) volviendo a crear su IP origen.

    Las rutas dinamicas no se crean con /ip/route/add (quedaria una copia
    estatica duplicada); RouterOS las regenera solo cuando la direccion IP
    de su interfaz vuelve a existir.
    """
    gw = str(fila_a.get("gateway", "") or "")
    fuente = str(fila_a.get("pref-fuente", "") or "")
    destino = str(fila_a.get("destino", "") or "")
    if not gw or not fuente:
        return {"ruta": ruta, "ok": True,
                "mensaje": "ruta dinámica sin interfaz/fuente: la regenera el equipo"}
    import ipaddress as _ipa
    try:
        _ipa.ip_address(gw)
    except ValueError:
        pass
    else:
        # El gateway es una IP (ruta dinamica tipo OSPF/DHCP), no una interfaz
        # conectada: no se puede recrear agregando una IP local.
        return {"ruta": ruta, "ok": True,
                "mensaje": "ruta dinámica vía gateway de IP: la regenera el protocolo"}
    pref = destino.split("/")[1] if "/" in destino else ""
    addr = f"{fuente}/{pref}".rstrip("/")
    # Si la IP ya existe, la ruta conectada vuelve sola -> no duplicar.
    for f in list(api("/ip/address/print")):
        if str(f.get("address", "")) == addr and str(f.get("interface", "")) == gw:
            return {"ruta": ruta, "ok": True,
                    "mensaje": f"ruta conectada ya regenerada por su IP ({addr})"}
    list(api("/ip/address/add", **{"address": addr, "interface": gw}))
    return {"ruta": ruta, "ok": True,
            "mensaje": f"/ip/address/add {addr} en {gw} (vuelve la ruta conectada)"}


def _valor_api(v):
    """Normaliza un valor YAML para la API de RouterOS.

    RouterOS usa 'yes'/'no' (o 'true'/'false') para booleanos; los bool de
    Python no deben enviarse como 'True'/'False' porque la API los rechaza.
    Las listas se unen con coma (ej: dhcp-options).
    """
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v)
    return str(v)


def _crear_fila_en_router(api, seccion, fila_yaml, indice=None):
    """Crea una fila en el router a partir de la fila del YAML."""
    path, campos = SECCIONES_API[seccion]
    kwargs = {}
    for k_yml, k_ros in campos.items():
        if k_yml == "direccion" and seccion == "ip":
            continue  # se arma abajo con el prefijo
        v = fila_yaml.get(k_yml)
        if v is None or _valor_api(v) == "":
            continue
        kwargs[k_ros] = _valor_api(v)
    if seccion == "ip":
        addr = str(fila_yaml.get("direccion", ""))
        pref = str(fila_yaml.get("prefijo", ""))
        kwargs["address"] = f"{addr}/{pref}".rstrip("/")
    list(api(f"{path}/add", **kwargs))
    if indice is not None and seccion in ("filtros", "nat"):
        # Las reglas de firewall/NAT se evalúan en orden: vuelve a su posición.
        _reposicionar_fila_nueva(api, path, seccion, fila_yaml, indice)


def _aplicar_campo(api, seccion, fila_yaml, campo, valor):
    """Aplica el cambio de un solo campo sobre la fila identificada."""
    path, campos = SECCIONES_API[seccion]
    if campo not in campos:
        return f"El campo '{campo}' no se puede restaurar."
    if seccion == "equipo":
        list(api(f"{path}/set", **{"name": str(valor)}))
        return None
    row_id = _buscar_fila_en_router(api, seccion, fila_yaml)
    if not row_id:
        return "El item ya no existe en el router."
    campo_ros = campos[campo]
    if seccion == "ip" and campo == "direccion":
        valor = f"{valor}/{fila_yaml.get('prefijo', '')}".rstrip("/")
    list(api(f"{path}/set", **{".id": row_id, campo_ros: _valor_api(valor)}))
    return None


def _aplicar_un_cambio(api, ruta, doc_a, doc_b):
    """Aplica un solo cambio (una ruta) al router restaurando el estado de A.

    - ruta con campo  -> set de ese campo desde la fila de A
    - ruta de fila    -> segun la direccion del diff:
        * eliminado (estaba en A y no en B): se crea el item (vuelve A)
        * agregado   (esta en B y no en A):  se borra el item del router
    Devuelve un dict con resultado ok/error para esa ruta."""
    m = _RUTA_RE.match(ruta) or _RUTA_FILA_RE.match(ruta) or _RUTA_DICT_RE.match(ruta)
    if not m:
        return {"ruta": ruta, "ok": False, "error": f"Ruta no interpretable: {ruta}"}

    seccion = m.group("seccion")
    sub = m.groupdict().get("sub")
    indice_raw = m.groupdict().get("indice")
    indice = int(indice_raw) if indice_raw is not None else None
    campo = m.groupdict().get("campo")

    clave = _clave_api(seccion, sub)
    if not clave:
        return {"ruta": ruta, "ok": False, "error": "Sección no editable."}

    try:
        lista_a = _ubicar_lista(doc_a, seccion, sub)
        lista_b = _ubicar_lista(doc_b, seccion, sub)
        ind = indice or 0
        fila_a = lista_a[ind] if ind < len(lista_a) else None
        fila_b = lista_b[ind] if ind < len(lista_b) else None
        if clave != "equipo":
            # Claves que existen solo en A (eliminado) o solo en B (agregado).
            ck_a = {_clave_fila(seccion, f) for f in lista_a} - {None}
            ck_b = {_clave_fila(seccion, f) for f in lista_b} - {None}
            solo_a = ck_a - ck_b
            solo_b = ck_b - ck_a
            if fila_a is not None and _clave_fila(seccion, fila_a) in solo_a:
                fila_b = None
            elif fila_b is not None and _clave_fila(seccion, fila_b) in solo_b:
                fila_a = None
            else:
                # No es cambio de fila puro: emparejar por clave para el set.
                if fila_a is not None:
                    ck = _clave_fila(seccion, fila_a)
                    if ck is not None:
                        fila_b = next((f for f in lista_b if _clave_fila(seccion, f) == ck), None)
                if fila_b is not None and fila_a is not None:
                    ck = _clave_fila(seccion, fila_a)
                    if ck is None:
                        fila_a = None
    except Exception as e:  # noqa: BLE001
        return {"ruta": ruta, "ok": False, "error": str(e)}

    try:
        if campo is None:
            # Operacion sobre la fila completa
            if clave == "equipo":
                return {"ruta": ruta, "ok": False, "error": "Equipo no aplica filas."}
            if clave == "interfaces":
                return {"ruta": ruta, "ok": False, "error": "Las interfaces no se agregan ni se eliminan."}
            if fila_a is None and fila_b is not None:
                # Agregado: no existe en A, existe en B -> borrar del router
                if clave not in _SECCIONES_FILA:
                    return {"ruta": ruta, "ok": False, "error": "Ese tipo de item no se puede eliminar."}
                if clave in ("rutas", "ip") and _es_fila_dinamica(fila_b):
                    # Las rutas/IP dinamicas no se borran ni se agregan a mano:
                    # desaparecen solas cuando se quita su causa (IP / cliente DHCP).
                    return {"ruta": ruta, "ok": True,
                            "mensaje": f"{clave} dinámica: no se elimina manualmente (se regenera sola)"}
                row_id = _buscar_fila_en_router(api, clave, fila_b)
                if not row_id:
                    return {"ruta": ruta, "ok": False, "error": "El item ya no existe en el router."}
                path = SECCIONES_API[clave][0]
                list(api(f"{path}/remove", **{".id": row_id}))
                # idf: se removio el item agregado
                return {"ruta": ruta, "ok": True, "mensaje": f"{path}/remove .id={row_id}"}
            if fila_a is not None and fila_b is None:
                # Eliminado: existia en A, no en B -> volver a crearlo
                if clave == "rutas" and _es_fila_dinamica(fila_a):
                    # Ruta conectada: la regenera RouterOS si la IP de esa
                    # interfaz vuelve a existir. Se restaura la IP origen.
                    return _restaurar_ruta_dinamica(api, ruta, fila_a)
                _crear_fila_en_router(api, clave, fila_a, indice=indice)
                path = SECCIONES_API[clave][0]
                return {"ruta": ruta, "ok": True, "mensaje": f"{path}/add restaurado"}
            return {"ruta": ruta, "ok": False, "error": "El item existe en ambos YAML; no requiere restaurar fila."}
        # Campo puntual: aplicar el valor de A
        if fila_a is None:
            return {"ruta": ruta, "ok": False, "error": "El item no existe en el YAML guardado."}
        valor = fila_a.get(campo, "")
        if valor is None:
            valor = ""
        err = _aplicar_campo(api, clave, fila_a, campo, valor)
        if err:
            return {"ruta": ruta, "ok": False, "error": err}
        return {"ruta": ruta, "ok": True, "mensaje": f"{SECCIONES_API[clave][0]}/set {campo}={valor}"}
    except Exception as e:  # noqa: BLE001
        return {"ruta": ruta, "ok": False, "error": f"El router rechazó el cambio: {e}"}


def _clave_orden(ruta):
    """Clave estable para ordenar rutas por seccion e indice numerico."""
    m = _RUTA_RE.match(ruta) or _RUTA_FILA_RE.match(ruta) or _RUTA_DICT_RE.match(ruta)
    if not m:
        return (ruta, 0, "")
    ind = m.groupdict().get("indice")
    try:
        n = int(ind) if ind is not None else -1
    except (TypeError, ValueError):
        n = -1
    return (m.group("seccion"), n, (m.groupdict().get("campo") or ""))


@app.route("/api/restaurar", methods=["POST"])
def restaurar():
    """Restaura cambios seleccionados al router, devolviendo el router al
    estado de la configuracion A (anterior). Recibe 'rutas' (las seleccionadas)
    y ambos YAML ('yaml_a' y 'yaml_b') para saber la direccion del cambio.
    """
    datos = _datos_request()
    api, host, err = _api_para(datos)
    if err:
        return jsonify({"ok": False, "error": err})
    rutas = datos.get("rutas")
    if isinstance(rutas, str):
        try:
            import json as _json_par
            rutas = _json_par.loads(rutas)
        except Exception:  # noqa: BLE001
            rutas = [r.strip() for r in rutas.split(",") if r.strip()]
    if not rutas:
        una = (datos.get("ruta") or "").strip()
        rutas = [una] if una else []
    rutas = [r for r in rutas if r]

    # Aplicar en orden estable: por seccion y por indice numerico, para que el
    # high -> reposicionamiento de reglas (firewall/NAT) use indices correctos
    # y las restauraciones en cascada no se pisen entre si.
    rutas.sort(key=_clave_orden)

    texto_a = datos.get("yaml_a") or datos.get("yaml") or ""
    texto_b = datos.get("yaml_b") or datos.get("yaml") or ""

    if not rutas:
        return jsonify({"ok": False, "error": "Faltan rutas para restaurar."})
    if not texto_a or not texto_b:
        return jsonify({"ok": False, "error": "Faltan los YAML (anterior y actual)."})

    try:
        doc_a = yaml.safe_load(texto_a) or {}
        doc_b = yaml.safe_load(texto_b) or {}
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Uno de los YAML no es válido: {e}"})
    if isinstance(doc_a, dict) and set(doc_a) == {"mikrotik"}:
        doc_a = doc_a["mikrotik"]
    if isinstance(doc_b, dict) and set(doc_b) == {"mikrotik"}:
        doc_b = doc_b["mikrotik"]

    resultados = [_aplicar_un_cambio(api, r, doc_a, doc_b) for r in rutas]
    ok_n = sum(1 for r in resultados if r.get("ok"))

    return jsonify({
        "ok": ok_n == len(resultados),
        "aplicados": ok_n,
        "total": len(resultados),
        "resultados": resultados,
    })


@app.route("/api/restaurar_completa", methods=["POST"])
def restaurar_completa():
    """Restaura el equipo a una configuración completa guardada en YAML.

    Compara el YAML deseado (A) contra el estado actual del router (B,
    leído en vivo con todas las secciones) y aplica automáticamente todos
    los cambios restaurables para volver al estado A.
    """
    datos = _datos_request()
    api, host, err = _api_para(datos)
    if err:
        return jsonify({"ok": False, "error": err})
    texto = datos.get("yaml") or ""
    if not texto:
        return jsonify({"ok": False, "error": "Falta el YAML de configuración a restaurar."})

    try:
        doc_a = yaml.safe_load(texto) or {}
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"El YAML no es válido: {e}"})
    if isinstance(doc_a, dict) and set(doc_a) == {"mikrotik"}:
        doc_a = doc_a["mikrotik"]

    try:
        doc_b = tm.configuracion_completa(api, secciones=None)
        doc_b.pop("exportado", None)
    except tm.ErrorMikroTik as e:
        return jsonify({"ok": False, "error": str(e)})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Error leyendo el estado actual: {e}"})

    diffs = _flatten_diff(doc_a, doc_b)
    diffs.sort(key=lambda d: _clave_orden(d["ruta"]))

    solo_analizar = bool(datos.get("solo_analizar"))

    # Calcular los restaurables (misma logica que el comparador)
    restaurables = []
    for d in diffs:
        m = _RUTA_RE.match(d["ruta"]) or _RUTA_FILA_RE.match(d["ruta"]) or _RUTA_DICT_RE.match(d["ruta"])
        if not m:
            continue
        seccion = m.group("seccion")
        sub = m.groupdict().get("sub")
        campo = m.groupdict().get("campo")
        clave = _clave_api(seccion, sub)
        if d["tipo"] == "cambiado" and clave and campo in SECCIONES_API.get(clave, ({},))[1]:
            restaurables.append(d)
        elif d["tipo"] in ("agregado", "eliminado") and clave in _SECCIONES_FILA:
            restaurables.append(d)

    if solo_analizar:
        conteos = {"agregado": 0, "eliminado": 0, "cambiado": 0}
        for d in restaurables:
            conteos[d["tipo"]] += 1
        return jsonify({
            "ok": True,
            "total": len(restaurables),
            "agregado": conteos["agregado"],
            "eliminado": conteos["eliminado"],
            "cambiado": conteos["cambiado"],
        })

    # Aplicar cada cambio restaurable en orden estable
    aplicados = 0
    resultados = []
    for d in restaurables:
        res = _aplicar_un_cambio(api, d["ruta"], doc_a, doc_b)
        resultados.append(res)
        if res.get("ok"):
            aplicados += 1

    fallos = [r for r in resultados if not r.get("ok")]
    return jsonify({
        "ok": aplicados == len(resultados),
        "aplicados": aplicados,
        "total": len(resultados),
        "resultados": resultados,
        "error": ("Algunos cambios no se pudieron aplicar." if fallos else None),
    })


def _flatten_diff(a, b, ruta=""):
    """Compara dos estructuras YAML y devuelve lista de diferencias.

    Cada diferencia es un dict:
      {tipo: 'agregado'|'eliminado'|'cambiado', ruta, antes, ahora}

    Las listas de filas (dicts) se emparejan por clave natural (nombre,
    direccion+prefijo, etc.) para que agregar/eliminar un item no corra
    los indices de los demas. Las listas de valores sueltos se comparan
    por indice. Los campos volatiles (contadores, timestamps) se ignoran.
    """
    diffs = []

    def _normalizar(v):
        if isinstance(v, (dict, list)):
            return v
        return v

    def _es_ignorable(r):
        """True si el ultimo campo de la ruta es volatil o un id interno."""
        campo = r.rsplit(".", 1)[-1]
        if campo.startswith(".id"):
            return True
        return campo in _CAMPOS_DINAMICOS

    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            sub = f"{ruta}.{k}" if ruta else k
            if k not in b:
                if _es_ignorable(sub):
                    continue
                diffs.append({"tipo": "eliminado", "ruta": sub, "antes": a[k], "ahora": None})
            elif k not in a:
                if _es_ignorable(sub):
                    continue
                diffs.append({"tipo": "agregado", "ruta": sub, "antes": None, "ahora": b[k]})
            else:
                diffs.extend(_flatten_diff(a[k], b[k], sub))
    elif isinstance(a, list) and isinstance(b, list):
        # Determinar si la lista es de filas (dicts) que se pueden emparejar por clave.
        seccion = ruta.rsplit(".", 1)[-1]
        es_dicts = bool(a) and all(isinstance(x, dict) for x in a)
        es_dicts_b = bool(b) and all(isinstance(x, dict) for x in b)
        tiene_clave = seccion in _LLAVES_FILA
        if es_dicts and es_dicts_b and tiene_clave:
            # Emparejar por clave natural
            usados_b = set()
            for i, fa in enumerate(a):
                clave = _clave_fila(seccion, fa)
                if clave is None:
                    continue
                j = next((j for j, fb in enumerate(b) if j not in usados_b and _clave_fila(seccion, fb) == clave), None)
                if j is not None:
                    usados_b.add(j)
                    sub = f"{ruta}[{i}]"
                    diffs.extend(_flatten_diff(fa, b[j], sub))
                else:
                    diffs.append({"tipo": "eliminado", "ruta": f"{ruta}[{i}]", "antes": fa, "ahora": None})
            for j, fb in enumerate(b):
                if j not in usados_b:
                    diffs.append({"tipo": "agregado", "ruta": f"{ruta}[{j}]", "antes": None, "ahora": fb})
        else:
            largo = max(len(a), len(b))
            for i in range(largo):
                sub = f"{ruta}[{i}]"
                if i >= len(a):
                    diffs.append({"tipo": "agregado", "ruta": sub, "antes": None, "ahora": b[i]})
                elif i >= len(b):
                    diffs.append({"tipo": "eliminado", "ruta": sub, "antes": a[i], "ahora": None})
                else:
                    diffs.extend(_flatten_diff(a[i], b[i], sub))
    else:
        if _normalizar(a) != _normalizar(b) and not _es_ignorable(ruta):
            diffs.append({"tipo": "cambiado", "ruta": ruta, "antes": a, "ahora": b})
    return diffs


def _resumen_valor(v):
    """Condensa un valor (dict/list) a texto corto para mostrar."""
    if isinstance(v, dict):
        items = [f"{k}={_resumen_valor(x)}" for k, x in list(v.items())[:6]]
        return ("{ " + ", ".join(items) + (", …" if len(v) > 6 else "") + " }")
    if isinstance(v, list):
        items = [_resumen_valor(x) for x in v[:6]]
        return "[ " + ", ".join(items) + (", …" if len(v) > 6 else "") + " ]"
    if v is None:
        return ""
    return str(v)


@app.route("/api/comparar", methods=["POST"])
def comparar():
    """Compara dos YAML de configuracion y devuelve las diferencias."""
    datos = request.get_json(silent=True) or request.form
    texto_a = datos.get("yaml_a") or ""
    texto_b = datos.get("yaml_b") or ""
    nombre_a = datos.get("archivo_a") or "anterior.yaml"
    nombre_b = datos.get("archivo_b") or "actual.yaml"

    if not texto_a or not texto_b:
        return jsonify({"ok": False, "error": "Faltan los dos archivos YAML."})

    try:
        doc_a = yaml.safe_load(texto_a) or {}
        doc_b = yaml.safe_load(texto_b) or {}
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Uno de los archivos no es un YAML válido: {e}"})

    # Quitar la envoltura "mikrotik:" para comparar el contenido real
    def _quitar_envoltura(d):
        if isinstance(d, dict) and set(d) == {"mikrotik"}:
            return d["mikrotik"]
        return d

    diffs = _flatten_diff(_quitar_envoltura(doc_a), _quitar_envoltura(doc_b))
    diffs.sort(key=lambda d: d["ruta"])

    conteo = {"agregado": 0, "eliminado": 0, "cambiado": 0}
    for d in diffs:
        conteo[d["tipo"]] += 1

    cambios = []
    for d in diffs:
        restaurable = False
        m = _RUTA_RE.match(d["ruta"]) or _RUTA_FILA_RE.match(d["ruta"]) or _RUTA_DICT_RE.match(d["ruta"])
        if m:
            seccion = m.group("seccion")
            sub = m.groupdict().get("sub")
            campo = m.groupdict().get("campo")
            clave = _clave_api(seccion, sub)
            if d["tipo"] == "cambiado" and clave and campo in SECCIONES_API.get(clave, ({},))[1]:
                restaurable = True
            elif d["tipo"] in ("agregado", "eliminado") and clave in _SECCIONES_FILA:
                restaurable = True
        cambios.append({
            "tipo": d["tipo"],
            "ruta": d["ruta"],
            "antes": _resumen_valor(d.get("antes")),
            "ahora": _resumen_valor(d.get("ahora")),
            "restaurable": restaurable,
        })

    return jsonify({
        "ok": True,
        "archivo_a": nombre_a,
        "archivo_b": nombre_b,
        "total": len(cambios),
        "conteo": conteo,
        "diferencias": cambios,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010, debug=False)