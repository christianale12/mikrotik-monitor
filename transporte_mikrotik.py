#!/usr/bin/env python3
"""
Conexion a la API de MikroTik (RouterOS 6.x, puerto 8728)
========================================================
Usa librouteros (protocolo binario de la API de RouterOS).

Incluye:
  - detectar_mikrotiks(): escaneo TCP rapido de la red local buscando
    puerto 8728 abierto (el puerto de la API de MikroTik).
  - conectar(): abre la sesion API con usuario/password.
  - Funciones de lectura de informacion (estado, interfaces, ip/dhcp/arp,
    rutas/firewall, clientes wifi).

Todos los errores se convierten a excepciones Propias con mensaje claro
para mostrarlas en la interfaz.
"""

import ipaddress
import socket
import threading
import time

import librouteros
from librouteros import exceptions as rex


class ErrorMikroTik(Exception):
    """Error de la app con mensaje para mostrar al usuario."""


def _local_red():
    """Devuelve la subred local y la IP local de esta PC.

    Usa el truco de conectar un socket UDP a 8.8.8.8 para que el SO
    descubra la interfaz por la que sale el trafico (sin enviar nada).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
    except OSError:
        socket.close(s)
        return None, None
    finally:
        s.close()

    for iface in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        try:
            ip = iface[4][0]
            if ip.startswith("127."):
                continue
            if ip == ip_local:
                break
        except (IndexError, TypeError):
            continue

    net = ipaddress.ip_network(f"{ip_local}/24", strict=False)
    return str(net), ip_local


def _puerto_abierto(ip, puerto=8728, timeout=0.4):
    """True si el puerto TCP esta abierto en esa IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, puerto)) == 0
    except OSError:
        return False


def _ips_de_interfaces():
    """IPv4 de TODAS las interfaces activas (incluye virbr0, docker0, etc.).

    getaddrinfo(gethostname()) suele devolver solo 127.0.1.1, asi que se
    consultan las interfaces reales. En Linux via ioctl(SIOCGIFADDR); en
    otros SOs se devuelve vacio y se usan los respaldos. Best-effort.
    """
    ips = []
    try:
        import fcntl
        import struct
        SIOCGIFADDR = 0x8915
        for _, nombre in socket.if_nameindex():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    paquete = struct.pack("256s", nombre[:15].encode("utf-8"))
                    datos = fcntl.ioctl(s.fileno(), SIOCGIFADDR, paquete)
                    ips.append(socket.inet_ntoa(datos[20:24]))
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return ips


def _redes_locales():
    """Devuelve todas las redes /24 de las interfaces IPv4 activas de esta PC.

    En vez de depender de una sola interfaz (truco UDP), se enumeran
    Todas las IPs locales no-loopback para cubrir PC con varias
    placas de red / VPN / máquinas virtuales (VBox, GNS3...).
    """
    candidatas = list(_ips_de_interfaces())
    try:
        candidatas += [info[4][0] for info in
                       socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    except (socket.gaierror, IndexError, TypeError, OSError):
        pass

    # Respaldo: interfaz por donde sale el trafico a internet.
    if not candidatas:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                candidatas.append(s.getsockname()[0])
            finally:
                s.close()
        except OSError:
            pass

    redes = []
    for ip in candidatas:
        if not ip or ip.startswith("127."):
            continue
        try:
            red = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            continue
        if red not in redes:
            redes.append(red)

    return sorted(set(redes))


def detectar_mikrotiks(puerto=8728, timeout=0.4, max_hilos=100):
    """Escanea todas las redes locales buscando hosts con el puerto API abierto.

    Devuelve (ips_encontradas, reds_escanheadas, ip_local). En vez de fijar
    una sola red, cubre cada interfaz activa del equipo.
    """
    redes = _redes_locales()
    if not redes:
        raise ErrorMikroTik("No se pudo determinar ninguna red local.")

    ips_local = set()
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        try:
            ip = info[4][0]
        except (IndexError, TypeError):
            continue
        if ip and not ip.startswith("127."):
            ips_local.add(ip)

    candidatos = []
    for red in redes:
        for h in ipaddress.ip_network(red).hosts():
            h = str(h)
            if h not in ips_local:
                candidatos.append(h)
    candidatos = sorted(set(candidatos))

    encontrados = []
    lock = threading.Lock()

    def _probar(h):
        if _puerto_abierto(h, puerto, timeout):
            with lock:
                encontrados.append(h)

    sem = threading.Semaphore(max_hilos)

    def _worker(h):
        with sem:
            _probar(h)

    hilos = [threading.Thread(target=_worker, args=(h,)) for h in candidatos]
    for t in hilos:
        t.start()
    for t in hilos:
        t.join()

    encontrados.sort()
    ip_local = sorted(ips_local)[0] if ips_local else ""
    return encontrados, redes, ip_local


class _ApiSerial:
    """Envuelve una conexion librouteros serializando cada uso del socket.

    La app consulta desde varios hilos (ademas del monitoreo que refresca
    cada pocos segundos) y la API es un socket con un solo hilo de
    respuestas: sin esto, dos lecturas simultaneas mezclarian los paquetes
    y se caeria la sesion. Devuelve las respuestas ya materializadas en
    lista, porque las funciones de librouteros son perezosas y leer
    despues de soltar el candado seria tan peligroso como no candar.
    """

    def __init__(self, api, host=""):
        object.__setattr__(self, "_api", api)
        object.__setattr__(self, "_lock", threading.RLock())
        object.__setattr__(self, "_host", host or getattr(api, "host", ""))

    @property
    def host(self):
        return object.__getattribute__(self, "_host")

    def __call__(self, *args, **kwargs):
        lock = object.__getattribute__(self, "_lock")
        api = object.__getattribute__(self, "_api")
        with lock:
            res = api(*args, **kwargs)
            if isinstance(res, (list, tuple)):
                return list(res)
            try:
                return list(res)
            except TypeError:
                return res

    def __getattr__(self, nombre):
        api = object.__getattribute__(self, "_api")
        lock = object.__getattribute__(self, "_lock")
        attr = getattr(api, nombre)
        if not callable(attr):
            return attr

        def _envuelto(*args, **kwargs):
            with lock:
                return attr(*args, **kwargs)

        return _envuelto

    def __repr__(self):
        return f"<ApiSerial {object.__getattribute__(self, '_host')}>"


def conectar(host, usuario, password, puerto=8728, timeout=8):
    """Abre una sesion con la API de MikroTik y la devuelve."""
    try:
        api = librouteros.connect(
            host=host,
            username=usuario,
            password=password,
            port=puerto,
            timeout=timeout,
        )
    except rex.MultiTrapError as e:
        raise ErrorMikroTik(f"Credenciales incorrectas ({e})") from None
    except rex.TrapError as e:
        raise ErrorMikroTik(f"El router rechazo la consulta durante el login ({e})") from None
    except rex.LibRouterosError as e:
        raise ErrorMikroTik(f"Error del protocolo API ({e})") from None
    except OSError as e:
        raise ErrorMikroTik(f"No se pudo conectar a {host}:{puerto} ({e})") from None
    except Exception as e:  # noqa: BLE001
        raise ErrorMikroTik(f"Error conectando a {host}: {e}") from None
    return _ApiSerial(api, host)


def _filas(api, path):
    """Ejecuta '/<path>/print' y devuelve lista de dicts."""
    try:
        filas = []
        for row in api(path):
            d = dict(row)
            try:
                for k, v in list(d.items()):
                    d[k] = v.decode() if isinstance(v, bytes) else v
            except Exception:  # noqa: BLE001
                pass
            filas.append(d)
        return filas
    except rex.TrapError as e:
        raise ErrorMikroTik(f"El router rechazo /{path} ({e})") from None
    except Exception as e:  # noqa: BLE001
        raise ErrorMikroTik(f"Error leyendo /{path}: {e}") from None


def _primero(api, path):
    filas = _filas(api, path)
    return filas[0] if filas else {}


def identificar_host(host, puerto=8728, timeout=4, usuario="admin", password=""):
    """Intenta entrar a un host solo para leer identidad/versión.

    Si las credenciales por defecto alcanzan, devuelve nombre y versión.
    Si el usuario/contraseña es inválido devuelve identidad vacia con
    'protegido': True para que la app sepa que requiere credenciales.
    """
    try:
        api = librouteros.connect(
            host=host, username=usuario, password=password,
            port=puerto, timeout=timeout,
        )
    except rex.MultiTrapError:
        return {"ip": host, "identidad": "", "version": "", "protegido": True}
    except rex.TrapError:
        return {"ip": host, "identidad": "", "version": "", "protegido": True}
    except (rex.LibRouterosError, OSError) as e:
        raise ErrorMikroTik(f"No se pudo identificar {host}: {e}") from None

    try:
        ident = _primero(api, "/system/identity/print")
        res = _primero(api, "/system/resource/print")
    except ErrorMikroTik:
        ident, res = {}, {}
    finally:
        try:
            api.close()
        except Exception:  # noqa: BLE001
            pass
    return {
        "ip": host,
        "identidad": ident.get("name", ""),
        "version": res.get("version", ""),
        "protegido": False,
    }


def estado_general(api):
    """Version, uptime, recursos (CPU/RAM/disco), reloj y serie."""
    ident = _primero(api, "/system/identity/print")
    res = _primero(api, "/system/resource/print")
    reloj = _primero(api, "/system/clock/print")
    return {
        "identidad": ident.get("name", "Sin nombre"),
        "version": res.get("version", ""),
        "board": res.get("board-name", ""),
        "serial": res.get("serial-number", ""),
        "uptime": res.get("uptime", ""),
        "cpu": res.get("cpu-load", ""),
        "memoria_total": res.get("total-memory", ""),
        "memoria_libre": res.get("free-memory", ""),
        "disco_total": res.get("total-hdd-space", ""),
        "disco_libre": res.get("free-hdd-space", ""),
        "fecha": reloj.get("date", ""),
        "hora": reloj.get("time", ""),
    }


def interfaces(api):
    """Lista de interfaces con estado y trafico."""
    return _filas(api, "/interface/print")


def ips_y_arp_dhcp(api):
    """Direcciones IP, tabla ARP y clientes DHCP."""
    direcciones = _filas(api, "/ip/address/print")
    arp = _filas(api, "/ip/arp/print")
    dhcp = _filas(api, "/ip/dhcp-server/lease/print")
    return {"direcciones": direcciones, "arp": arp, "dhcp": dhcp}


def rutas_y_firewall(api):
    """Tabla de rutas y reglas de firewall."""
    rutas = _filas(api, "/ip/route/print")
    firewall = _filas(api, "/ip/firewall/rule/print")
    return {"rutas": rutas, "firewall": firewall}


def clientes_wifi(api):
    """Clientes conectados por Wireless (si el equipo es AP)."""
    return _filas(api, "/interface/wireless/registration-table/print")


def vlanes(api):
    """VLANs en interfaces (802.1Q) y configuración de bridges."""
    vlan_if = _filas(api, "/interface/vlan/print")
    bridges = _filas(api, "/interface/bridge/print")
    bridge_vlans = _filas(api, "/interface/bridge/vlan/print")
    return {"vlan": vlan_if, "bridge": bridges, "bridge_vlan": bridge_vlans}


def nat(api):
    """Reglas NAT (srcnat/dstnat) con claves en español."""
    filas = []
    for f in _filas(api, "/ip/firewall/nat/print"):
        filas.append({
            "cadena": f.get("chain", ""),
            "accion": f.get("action", ""),
            "protocolo": f.get("protocol", ""),
            "origen": f.get("src-address", ""),
            "destino": f.get("dst-address", ""),
            "puerto-origen": f.get("src-port", ""),
            "puerto-destino": f.get("dst-port", ""),
            "a-direccion": f.get("to-addresses", ""),
            "a-puerto": f.get("to-ports", ""),
            "comentario": f.get("comment", ""),
            "interfaz-origen": f.get("in-interface", ""),
            "interfaz-destino": f.get("out-interface", ""),
        })
    return filas


def configuracion_completa(api, secciones=None):
    """Reune la configuracion del equipo para exportar a YAML.

    secciones: lista de claves a incluir. Si es None, se incluyen todas.
    Posibles claves: equipo, interfaces, ip, rutas, vlanes, filtros, nat,
    arp, dhcp, dns, usuarios, gateway.
    """
    todas = {
        "equipo", "interfaces", "ip", "rutas", "vlanes",
        "filtros", "nat", "arp", "dhcp", "dhcp_servidores", "dhcp_redes",
        "pools", "dns", "usuarios", "gateway",
    }
    if secciones is None:
        secciones = todas
    else:
        secciones = set(secciones) & todas

    def _seguro(fn, por_defecto=None):
        try:
            valor = fn()
            return valor
        except Exception:  # noqa: BLE001
            return por_defecto if por_defecto is not None else []

    datos = {}
    if "equipo" in secciones:
        sis = _seguro(lambda: estado_general(api), {})
        if not isinstance(sis, dict):
            sis = {}
        datos["equipo"] = {
            "identidad": sis.get("identidad", ""),
            "version": sis.get("version", ""),
            "board": sis.get("board", ""),
            "serial": sis.get("serial", ""),
            "uptime": sis.get("uptime", ""),
            "fecha": sis.get("fecha", ""),
            "hora": sis.get("hora", ""),
        }
    if "interfaces" in secciones:
        datos["interfaces"] = _seguro(lambda: interfaces_lista(api))
    if "ip" in secciones:
        datos["ip"] = _seguro(lambda: ips_completas(api))
    if "rutas" in secciones:
        datos["rutas"] = _seguro(lambda: rutas_lista(api))
    if "vlanes" in secciones:
        datos["vlanes"] = _seguro(lambda: vlanes(api))
    if "filtros" in secciones:
        datos["filtros"] = _seguro(lambda: filtros_lista(api))
    if "nat" in secciones:
        datos["nat"] = _seguro(lambda: nat(api))
    if "arp" in secciones:
        datos["arp"] = _seguro(lambda: arp_lista(api))
    if "dhcp" in secciones:
        datos["dhcp"] = _seguro(lambda: dhcp_lista(api))
    if "dhcp_servidores" in secciones:
        datos["dhcp_servidores"] = _seguro(lambda: dhcp_servidores(api))
    if "dhcp_redes" in secciones:
        datos["dhcp_redes"] = _seguro(lambda: dhcp_redes(api))
    if "pools" in secciones:
        datos["pools"] = _seguro(lambda: pools_lista(api))
    if "dns" in secciones:
        datos["dns"] = _seguro(lambda: dns(api), {})
        if not isinstance(datos["dns"], dict):
            datos["dns"] = {}
    if "usuarios" in secciones:
        datos["usuarios"] = _seguro(lambda: usuarios(api))
    if "gateway" in secciones:
        datos["gateway"] = _seguro(lambda: gateway_predeterminado(api), {})
        if not isinstance(datos["gateway"], dict):
            datos["gateway"] = {}

    return datos


def interfaces_lista(api):
    """Interfaces con campos relevantes (nombre, descripcion, speed, poe...)."""
    filas = []
    for f in _filas(api, "/interface/print"):
        filas.append({
            "nombre": f.get("name", ""),
            "tipo": f.get("type", ""),
            "running": f.get("running", ""),
            "disabled": f.get("disabled", ""),
            "descripcion": f.get("comment", ""),
            "mtu": f.get("mtu", ""),
            "mac": f.get("mac-address", ""),
            "rx": f.get("rx-byte", ""),
            "tx": f.get("tx-byte", ""),
        })
    return filas


def ips_completas(api):
    """IPs con mascara: direccion/red calcula el prefijo. Incluye gateway si el router lo tiene definido (default-route)."""
    filas = []
    for f in _filas(api, "/ip/address/print"):
        dir_ip = f.get("address", "")
        red = f.get("network", "")
        # "address" trae "ip/prefix" (ej 192.168.1.1/24)
        prefijo = ""
        if "/" in dir_ip:
            prefijo = dir_ip.split("/", 1)[1]
        filas.append({
            "interfaz": f.get("interface", ""),
            "direccion": dir_ip.split("/", 1)[0] if "/" in dir_ip else dir_ip,
            "mascara": _prefijo_a_mascara(prefijo),
            "prefijo": prefijo,
            "red": red,
            "dinamica": f.get("dynamic", ""),
        })
    return filas


def _prefijo_a_mascara(prefijo):
    try:
        n = int(prefijo)
        if 0 <= n <= 32:
            bits = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF
            return ".".join(str((bits >> (8 * i)) & 0xFF) for i in (3, 2, 1, 0))
    except (ValueError, TypeError):
        pass
    return ""


def rutas_lista(api):
    """Rutas con gateway, distancia y métrica OSPF cuando aplica."""
    filas = []
    for f in _filas(api, "/ip/route/print"):
        filas.append({
            "destino": f.get("dst-address", ""),
            "gateway": f.get("gateway", ""),
            "distancia": f.get("distance", ""),
            "metrica-ospf": f.get("ospf-metric", ""),
            "tipo-ospf": f.get("ospf-type", ""),
            "activo": f.get("active", ""),
            "dinamica": f.get("dynamic", ""),
            "pref-fuente": f.get("pref-src", ""),
        })
    return filas


def filtros_lista(api):
    """Reglas de firewall (= filtros/ACL)."""
    filas = []
    for f in _filas(api, "/ip/firewall/filter/print"):
        filas.append({
            "cadena": f.get("chain", ""),
            "accion": f.get("action", ""),
            "protocolo": f.get("protocol", ""),
            "origen": f.get("src-address", ""),
            "destino": f.get("dst-address", ""),
            "puerto-origen": f.get("src-port", ""),
            "puerto-destino": f.get("dst-port", ""),
            "interfaz-origen": f.get("in-interface", ""),
            "interfaz-destino": f.get("out-interface", ""),
            "comentario": f.get("comment", ""),
            "disabled": f.get("disabled", ""),
        })
    return filas


def arp_lista(api):
    filas = []
    for f in _filas(api, "/ip/arp/print"):
        filas.append({
            "direccion": f.get("address", ""),
            "mac": f.get("mac-address", ""),
            "interfaz": f.get("interface", ""),
            "dinamica": f.get("dynamic", ""),
        })
    return filas


def dhcp_lista(api):
    filas = []
    for f in _filas(api, "/ip/dhcp-server/lease/print"):
        filas.append({
            "hostname": f.get("host-name", ""),
            "direccion": f.get("address", ""),
            "mac": f.get("mac-address", ""),
            "servidor": f.get("server", ""),
            "estado": f.get("status", ""),
        })
    return filas


def dhcp_servidores(api):
    """Servidores DHCP (/ip/dhcp-server) con su configuracion."""
    filas = []
    for f in _filas(api, "/ip/dhcp-server/print"):
        filas.append({
            "nombre": f.get("name", ""),
            "interfaz": f.get("interface", ""),
            "pool": f.get("address-pool", ""),
            "lease-tiempo": f.get("lease-time", ""),
            "autoritativo": f.get("authoritative", ""),
            "dhcp-options": f.get("dhcp-options", ""),
            "comentario": f.get("comment", ""),
            "disabled": f.get("disabled", ""),
        })
    return filas


def dhcp_redes(api):
    """Redes que publica cada servidor DHCP (/ip/dhcp-server/network)."""
    filas = []
    for f in _filas(api, "/ip/dhcp-server/network/print"):
        filas.append({
            "direccion": f.get("address", ""),
            "gateway": f.get("gateway", ""),
            "dns": f.get("dns-server", ""),
            "ntp": f.get("ntp-server", ""),
            "dominio": f.get("domain", ""),
            "comentario": f.get("comment", ""),
        })
    return filas


def pools_lista(api):
    """Pools de direcciones del DHCP (rangos IP que reparte)."""
    filas = []
    for f in _filas(api, "/ip/pool/print"):
        filas.append({
            "name": f.get("name", ""),
            "ranges": f.get("ranges", ""),
            "next-pool": f.get("next-pool", ""),
            "comentario": f.get("comment", ""),
        })
    return filas


def dns(api):
    """Servidores DNS configurados y reglas DNS estaticas."""
    return {
        "servidores": _filas(api, "/ip/dns/print"),
        "estaticas": _filas(api, "/ip/dns/static/print"),
    }


def usuarios(api):
    """Usuarios locales (sin contraseñas)."""
    return _filas(api, "/user/print")


def gateway_predeterminado(api):
    """Gateway por defecto (ruta 0.0.0.0/0)."""
    for f in _filas(api, "/ip/route/print"):
        if f.get("dst-address") in ("0.0.0.0/0", "::/0"):
            return {
                "destino": f.get("dst-address", ""),
                "gateway": f.get("gateway", ""),
                "interfaz": f.get("interface", ""),
                "dinamica": f.get("dynamic", ""),
            }
    return {}


# -------------------------------------------------------------------------
# OSPF: lectura y configuracion (RouterOS 6 y 7; el menu cambia de version)
# -------------------------------------------------------------------------
def _decod(o):
    return o.decode(errors="replace") if isinstance(o, bytes) else o


def _version_mayor(api):
    """Numero mayor de la version de RouterOS (7, 6, ...). 6 si no se sabe."""
    try:
        v = _decod(_primero(api, "/system/resource/print").get("version", ""))
        d = "".join(c for c in v.split()[0] if c.isdigit() or c == ".")
        return int(float(d.split(".")[0])) if d else 6
    except Exception:  # noqa: BLE001
        return 6


def _menu_redes_ospf(api):
    """Menu donde se anuncian las redes OSPF segun la version.

    RouterOS 7 usa /routing/ospf/interface-template (campo 'networks');
    RouterOS 6 usa /routing/ospf/network (campo 'network').
    """
    if _version_mayor(api) >= 7:
        return "/routing/ospf/interface-template"
    return "/routing/ospf/network"


def _campo_red_ospf(api):
    return "networks" if _version_mayor(api) >= 7 else "network"


def _leer_redes_ospf(api):
    """{red: invalid} del menu de redes OSPF que corresponda a la version."""
    menu = _menu_redes_ospf(api)
    campo = _campo_red_ospf(api)
    out = {}
    for f in _filas(api, menu + "/print"):
        out[_decod(f.get(campo, ""))] = _decod(f.get("invalid", False))
    return out


def _agregar_red_ospf(api, red, area_nombre=""):
    """Anuncia 'red' en el menu OSPF correspondiente (v6 o v7).

    Los enlaces (prefijo < /32) se anuncian como point-to-point en v7 para
    que no haya eleccion DR/BDR y la adyacencia suba Full enseguida. En v6
    el tipo se fija con una interfaz estatica aparte (ver _regenerar_redes_ospf).
    """
    menu = _menu_redes_ospf(api)
    kwargs = {_campo_red_ospf(api): red}
    if area_nombre:
        kwargs["area"] = area_nombre
    if _version_mayor(api) >= 7 and _prefijo_de(red) < 32:
        kwargs["type"] = "ptp"
    list(api(menu + "/add", **kwargs))


def _ptp_activo(api, v7, itf_transito):
    """True si los enlaces ya estan anunciados como point-to-point.

    v7: toda red de enlace (prefijo < /32) del interface-template debe tener
    type=ptp. v6: cada interfaz de enlace debe tener una entrada estatica de
    /routing/ospf/interface con network-type=point-to-point.
    """
    if v7:
        return all(_decod(f.get("type", "")) == "ptp"
                   for f in _filas(api, "/routing/ospf/interface-template/print")
                   if _prefijo_de(_decod(f.get("networks", ""))) < 32)
    ptp = {_decod(f.get("interface", ""))
           for f in _filas(api, "/routing/ospf/interface/print")
           if _decod(f.get("network-type", "")) == "point-to-point"}
    return all(itf in ptp for itf in itf_transito)


def ospf_instancias(api):
    """Instancias OSPF: router-id, redistribucion, estado."""
    filas = []
    for f in _filas(api, "/routing/ospf/instance/print"):
        filas.append({
            "nombre": _decod(f.get("name", "")),
            "router-id": _decod(f.get("router-id", "")),
            "redistribute-connected": _decod(
                f.get("redistribute-connected", "") or f.get("redistribute", "")),
            "redistribute-static": _decod(f.get("redistribute-static", "")),
            "estado": _decod(f.get("state", "")),
            "disabled": _decod(f.get("disabled", "")),
        })
    return filas


def ospf_areas(api):
    """Areas OSPF configuradas."""
    filas = []
    for f in _filas(api, "/routing/ospf/area/print"):
        filas.append({
            "nombre": _decod(f.get("name", "")),
            "area-id": _decod(f.get("area-id", "")),
            "tipo": _decod(f.get("type", "")),
            "instancia": _decod(f.get("instance", "")),
            "vecinos": _decod(f.get("neighbors", "")),
            "adyacentes": _decod(f.get("adjacent-neighbors", "")),
            "disabled": _decod(f.get("disabled", "")),
        })
    return filas


def ospf_vecinos(api):
    """Tabla de vecinos OSPF: estado de adyacencia, router-id, direccion."""
    filas = []
    for f in _filas(api, "/routing/ospf/neighbor/print"):
        filas.append({
            "router-id": _decod(f.get("router-id", "")),
            "direccion": _decod(f.get("address", "")),
            "interfaz": _decod(f.get("interface", "")),
            "estado": _decod(f.get("state", "")),
            "prioridad": _decod(f.get("priority", "")),
            "adyacencia": _decod(f.get("adjacency", "")),
            "instancia": _decod(f.get("instance", "")),
        })
    return filas


def ospf_redes(api):
    """Redes anunciadas en OSPF (/routing/ospf/network en v6,
    /routing/ospf/interface-template en v7)."""
    menu = _menu_redes_ospf(api)
    campo = _campo_red_ospf(api)
    filas = []
    for f in _filas(api, menu + "/print"):
        filas.append({
            "red": _decod(f.get(campo, "")),
            "area": _decod(f.get("area", "")),
            "disabled": _decod(f.get("disabled", "")),
        })
    return filas


def ospf_rutas(api):
    """Rutas OSPF aprendidas (dinamicas con distancia 110 por defecto).

    En RouterOS 6 las rutas OSPF se marcan con el campo 'ospf': True.
    """
    filas = []
    for f in _filas(api, "/ip/route/print"):
        if f.get("ospf") not in (True, "true"):
            continue
        filas.append({
            "destino": _decod(f.get("dst-address", "")),
            "gateway": _decod(f.get("gateway", "")),
            "distancia": _decod(f.get("distance", "")),
            "interfaz": _decod(f.get("interface", "")),
            "gateway-status": _decod(f.get("gateway-status", "")),
            "activa": _decod(f.get("active", "")),
            "tipo": _decod(f.get("ospf-type", "")),
            "pref-fuente": _decod(f.get("pref-src", "")),
        })
    return filas


def _crear_loopback(api):
    """Crea una interfaz virtual 'loopback-ospf' para el router-id.

    RouterOS 7 tiene /interface/loopback; RouterOS 6 no, asi que se usa
    como respaldo un bridge sin puertos. Devuelve el nombre de la interfaz.
    """
    for f in _filas(api, "/interface/print"):
        if _decod(f.get("name", "")) == "loopback-ospf":
            return "loopback-ospf"
    try:
        list(api("/interface/loopback/add", **{"name": "loopback-ospf"}))
    except Exception:  # noqa: BLE001 - ROS6 sin /interface/loopback
        # RouterOS 6: bridge virtual sin puertos
        list(api("/interface/bridge/add", **{"name": "loopback-ospf"}))
    return "loopback-ospf"


def _asignar_ip_a_interfaz(api, interfaz, direccion):
    """Asigna address a la interfaz si no existe ya una igual."""
    for f in _filas(api, "/ip/address/print"):
        if _decod(f.get("address", "")) == direccion:
            return
    list(api("/ip/address/add", **{"address": direccion, "interface": interfaz}))


def _set_instancia_ospf(api, router_id, redistribute=True, area="0.0.0.0"):
    """Configura la instancia OSPF por defecto (router-id + redistribucion).

    RouterOS 7 no trae instancia por defecto: se crea ('default') y el area
    backbone se asocia a ella. El router-id se aplica siempre; la
    redistribucion es best-effort (v6 'redistribute-connected=yes',
    v7 'redistribute=connected'), asi que si falla no aborta la config.
    """
    v7 = _version_mayor(api) >= 7
    instancias = _filas(api, "/routing/ospf/instance/print")
    nombre_inst = "default"
    if not instancias:
        if not v7:
            return "No hay ninguna instancia OSPF para configurar."
        try:
            list(api("/routing/ospf/instance/add",
                     **{"name": nombre_inst, "router-id": router_id}))
            instancias = _filas(api, "/routing/ospf/instance/print")
        except Exception as e:  # noqa: BLE001
            return f"No se pudo crear la instancia OSPF: {e}"

    inst = instancias[0] if instancias else {}
    iid = _decod(inst.get(".id", ""))
    nombre_inst = _decod(inst.get("name", "")) or nombre_inst
    if not iid:
        return "La instancia OSPF no expone .id."

    list(api("/routing/ospf/instance/set", **{".id": iid, "router-id": router_id}))

    if redistribute:
        campo = "redistribute" if v7 else "redistribute-connected"
        valor = "connected" if v7 else "yes"
        try:
            list(api("/routing/ospf/instance/set", **{".id": iid, campo: valor}))
        except Exception as e:  # noqa: BLE001
            return f"{campo} no aceptado ({e}); se aplicó solo el router-id"
    else:
        # No redistribuir lo conectado: así la red de gestión no se cuela en
        # OSPF (las redes de los enlaces ya se anuncian por network). Ademas
        # sirve para limpiar una redistribución previa.
        campo = "redistribute" if v7 else "redistribute-connected"
        valor = "" if v7 else "no"
        try:
            list(api("/routing/ospf/instance/set", **{".id": iid, campo: valor}))
        except Exception:  # noqa: BLE001 - best-effort
            pass

    # Asegurar area backbone (en v7 hay que indicar la instancia)
    areas = _filas(api, "/routing/ospf/area/print")
    if not any(_decod(a.get("area-id", "")) == "0.0.0.0" for a in areas):
        kwargs = {"name": "backbone", "area-id": "0.0.0.0"}
        if v7:
            kwargs["instance"] = nombre_inst
        list(api("/routing/ospf/area/add", **kwargs))
    return None


def vecinos_interfaz(api):
    """Vecinos RouterOS por interfaz local (discovery MNDP/LLDP).

    Devuelve {interfaz_local: {'identity', 'mac', 'address'}}. Sirve para
    armar la topologia del anillo sin saber de antemano en qué interfaz
    física está cada red.
    """
    tabla = {}
    for f in _filas(api, "/ip/neighbor/print"):
        itf = _decod(f.get("interface", ""))
        if not itf:
            continue
        tabla.setdefault(itf, {
            "identity": _decod(f.get("identity", "")),
            "mac": _decod(f.get("mac-address", "")),
            "address": _decod(f.get("address", "")),
        })
    return tabla


def _prefijo_de(red):
    try:
        return int(str(red).split("/")[1])
    except (IndexError, ValueError):
        return 32


def _red_sin_prefijo(red):
    return str(red).split("/")[0]


def _ip_a_int(ip):
    """'10.0.12.0' -> entero de 32 bits (None si no es una IP válida)."""
    try:
        a, b, c, d = (int(x) for x in str(ip).split("."))
        return (a << 24) | (b << 16) | (c << 8) | d
    except (TypeError, ValueError):
        return None


def _int_a_ip(n):
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def _base_red(ip, pref):
    """Entero de la base de red que contiene 'ip' con 'pref' bits de máscara."""
    val = _ip_a_int(ip)
    if val is None:
        return None
    if pref >= 32:
        return val
    mascara = (~((1 << (32 - pref)) - 1)) & 0xFFFFFFFF
    return val & mascara


def _red_base(red):
    """('10.0.12.0', 24) a partir de una red 'ip/pref' (aplica la máscara)."""
    pref = _prefijo_de(red)
    base = _base_red(_red_sin_prefijo(red), pref)
    return (_int_a_ip(base) if base is not None else _red_sin_prefijo(red), pref)


def _en_rango(ip, red):
    """True si 'ip' cae dentro del rango de la red 'ip/pref'."""
    base, pref = _red_base(red)
    b = _base_red(base, pref)
    v = _ip_a_int(ip)
    if b is None or v is None:
        return False
    fin = b if pref >= 32 else b + (1 << (32 - pref)) - 1
    return b <= v <= fin


def _redes_equivalentes(actuales, deseadas):
    """True si las redes OSPF actuales ya activan las mismas interfaces.

    Un /30 de un enlace equivale al /24 del YAML que lo contiene (activa
    las mismas interfaces), así que re-ejecutar el paso 1 después del
    paso 2 no cuenta como cambio y no reinicia OSPF. Los /32 tienen que
    coincidir exactos y ninguna entrada puede estar 'invalid'.
    'actuales' es {red: invalid}.
    """
    if any(actuales.values()):
        return False
    a = set(actuales)
    d = {str(r).strip() for r in deseadas}
    if {r for r in a if _prefijo_de(r) == 32} != {r for r in d if _prefijo_de(r) == 32}:
        return False

    a_links = [r for r in a if _prefijo_de(r) < 32]
    d_links = [r for r in d if _prefijo_de(r) < 32]
    if not a_links or not d_links:
        return not a_links and not d_links

    def _contenida_en(red, cand):
        # 'red' es sub-red (o igual) de 'cand'
        return (_prefijo_de(red) >= _prefijo_de(cand)
                and _en_rango(_red_sin_prefijo(red), cand))

    # cada red actual debe estar contenida en alguna deseada (si no, el
    # paso 1 la sacaría) y cada deseada debe tener alguna actual dentro
    # (si no, el paso 1 activaría interfaces que hoy no están activas)
    if not all(any(_contenida_en(c, dd) for dd in d_links) for c in a_links):
        return False
    return all(any(_contenida_en(cc, dd) for cc in a_links) for dd in d_links)


def _ip_enlace(red, rid_a, rid_b, indice=0):
    """IP /30 del enlace 'red' que le toca a rid_a (simétrica).

    Regla determinista: ambos extremos la calculan solos sin coordinarse.
    Mayor router-id = .1 y menor = .2, así los dos routers siempre obtienen
    IPs distintas del mismo enlace aunque se configuren por separado.
    'indice' numera enlaces paralelos entre el mismo par (0, 1, 2...):
    cada uno ocupa su /30 dentro de la red compartida del YAML.
    """
    base, pref = _red_base(red)
    b = _base_red(base, pref)
    if b is None or pref > 31:
        return None
    a = _ip_a_int(_red_sin_prefijo(rid_a)) or 0
    otro = _ip_a_int(_red_sin_prefijo(rid_b)) if rid_b else None
    if pref == 31:  # enlace directo sin broadcast: se usan las dos IPs
        if indice:
            return None  # un /31 no admite enlaces paralelos
        b = b & 0xFFFFFFFE
        mi = b + (1 if (otro is not None and a > otro) else 0)
        return f"{_int_a_ip(mi)}/31"
    if indice >= (1 << (30 - pref)):  # se acabaron los /30 de esa red
        return None
    b = (b & 0xFFFFFFFC) + (indice << 2)
    mi = b + 1 if (otro is None or a > otro) else b + 2
    return f"{_int_a_ip(mi)}/30"


def _interfaz_de_gestion(api, host):
    """Interfaz por la que llega la sesión a este router.

    Se detecta buscando cuál tiene la IP de 'host'; así no se supone que
    es 'ether1' ni ninguna otra en particular (puede ser un bridge, otra
    ether o lo que sea: la detección es por dirección, no por nombre).
    """
    h = _ip_a_int(_red_sin_prefijo(str(host or "")))
    if h is None:
        return None
    for f in _filas(api, "/ip/address/print"):
        addr = _decod(f.get("address", ""))
        pref = _prefijo_de(addr)
        b = _base_red(_red_sin_prefijo(addr), pref)
        if b is None:
            continue
        tope = b if pref >= 32 else b + (1 << (32 - pref)) - 1
        if b <= h <= tope:
            return _decod(f.get("interface", ""))
    return None


def _interfaz_loopback(api, dir_loopback):
    """Interfaz que ya lleva el /32 del router-id (la que se creó antes o
    una que el usuario haya armado él mismo). None si todavía no existe."""
    if not dir_loopback:
        return None
    for f in _filas(api, "/ip/address/print"):
        if _decod(f.get("address", "")) == str(dir_loopback):
            return _decod(f.get("interface", ""))
    return None


def _area_ospf(api, area_id="0.0.0.0"):
    """Devuelve el nombre de un área OSPF cuyo area-id coincida (default backbone)."""
    for a in _filas(api, "/routing/ospf/area/print"):
        if _decod(a.get("area-id", "")) == str(area_id):
            return _decod(a.get("name", "")) or None
    return None


def _regenerar_redes_ospf(api, redes, bases, dir_loopback, itf_gestion,
                          area="0.0.0.0"):
    """Regenera /routing/ospf/network a partir de las interfaces REALES.

    Sigue a los cables: toma la base de cada IP gestionada que tiene un
    enlace (p. ej. 10.0.12.0/30) y los /32 del router-id o del YAML.
    Borra todo lo anterior, así que si se agregan o quitan placas o cables
    las redes OSPF quedan iguales a lo cableado. Si no hay ningún enlace
    con IP (p. ej. MNDP sin responder) conserva las previas.
    """
    msgs = []
    halladas = []
    itf_transito = []
    for f in _filas(api, "/ip/address/print"):
        addr = _decod(f.get("address", ""))
        itf = _decod(f.get("interface", ""))
        if not addr or not itf or itf == itf_gestion:
            continue
        base, pref = _red_base(addr)
        if addr == dir_loopback or (pref == 32 and addr in redes):
            halladas.append(f"{base}/32")
        elif base in bases:
            halladas.append(f"{base}/{pref}")
            itf_transito.append(itf)
    if not itf_transito:
        msgs.append("Sin enlaces con IP: se conservan las redes OSPF existentes")
        return msgs
    dir_redes = sorted(set(halladas))
    v7 = _version_mayor(api) >= 7

    # Comparar con lo que hay: si ya es igual y los enlaces ya son
    # point-to-point, no se toca nada (así re-ejecutar no reinicia OSPF).
    # Solo se reconstruye si difiere, si alguna entrada quedó 'invalid' o
    # si falta poner algún enlace como point-to-point.
    actuales = _leer_redes_ospf(api)
    if (set(actuales) == set(dir_redes) and not any(actuales.values())
            and _ptp_activo(api, v7, itf_transito)):
        msgs.append(f"redes OSPF ya sincronizadas: {', '.join(dir_redes)}")
        return msgs

    area_nombre = _area_ospf(api, area)
    menu = _menu_redes_ospf(api)
    campo = _campo_red_ospf(api)
    for n in _filas(api, menu + "/print"):
        try:
            list(api(menu + "/remove", **{".id": n.get(".id")}))
        except Exception as e:  # noqa: BLE001
            msgs.append(f"red vieja {_decod(n.get(campo, ''))}: {e}")
    if not v7:
        # v6: las interfaces estaticas ptp se crean ANTES del network, que
        # es el que les asigna el area (el menu interface de v6 no tiene area).
        for f in _filas(api, "/routing/ospf/interface/print"):
            if f.get("dynamic") in (True, "true"):
                continue
            try:
                list(api("/routing/ospf/interface/remove", **{".id": f.get(".id")}))
            except Exception as e:  # noqa: BLE001
                msgs.append(f"interfaz OSPF vieja: {e}")
        for itf in sorted(set(itf_transito)):
            try:
                list(api("/routing/ospf/interface/add",
                         **{"interface": itf, "network-type": "point-to-point"}))
            except Exception as e:  # noqa: BLE001
                msgs.append(f"{itf}: no se pudo poner point-to-point: {e}")
    for red in dir_redes:
        try:
            _agregar_red_ospf(api, red, area_nombre or "")
        except Exception as e:  # noqa: BLE001
            msgs.append(f"red {red}: {e}")
    msgs.append(f"redes OSPF desde los cables: {', '.join(dir_redes)}")
    return msgs


def configurar_p2p(api, router_id, networks, peerdatos, host=None,
                   area="0.0.0.0"):
    """Paso 2: interfaces de TODAS las placas según cómo estén cableadas.

    En cada interfaz descubre el vecino (MNDP/LLDP), halla la única red
    que ese par comparte en el YAML y le pone una IP /30 (o /31) de esa
    red. No hay lista de interfaces ni de routers: recorre lo que haya,
    de modo que agregar o quitar placas/cables y re-ejecutar queda
    sincronizado (las IPs viejas que ya no corresponden se quitan).

    Varios enlaces paraleles entre el mismo par también funcionan: cada
    uno recibe su /30 y el orden es igual en los dos extremos porque la
    clave del enlace es el menor MAC de ambos lados (algo que ambos
    calculan con la misma información).

    'peerdatos' es {identity: {redes, router-id}} de los equipos del YAML.
    'host' es la IP de gestión de este equipo (para no tocar esa interfaz).
    """
    msgs = []
    redes = [str(r).strip() for r in (networks or [])]
    bases = {_red_base(r)[0] for r in redes if _prefijo_de(r) < 32}
    dir_loopback = f"{_red_sin_prefijo(router_id)}/32"
    itf_gestion = _interfaz_de_gestion(api, host)
    itf_loopback = _interfaz_loopback(api, dir_loopback)

    macs_propias = {}
    for f in _filas(api, "/interface/print"):
        macs_propias[_decod(f.get("name", ""))] = (_decod(f.get("mac-address", "")) or "").lower()

    # 1) interfaces con vecino, agrupadas por el equipo de enfrente
    grupos = {}
    for itf, datos in vecinos_interfaz(api).items():
        if itf in (itf_gestion, itf_loopback):
            continue
        ident = datos.get("identity")
        if not ident:
            continue
        mi_mac = macs_propias.get(itf, "") or ""
        su_mac = (datos.get("mac") or "").lower()
        grupos.setdefault(ident, []).append({
            "itf": itf,
            "clave": min(mi_mac, su_mac) if mi_mac and su_mac else itf.lower(),
        })

    # 2) por cada vecino: la red compartida del YAML y qué /30 le toca
    enlaces = {}
    for ident, grupo in grupos.items():
        if ident not in peerdatos:
            for e in grupo:
                msgs.append(f"{e['itf']}: vecino '{ident}' no está en el YAML "
                            "(agregalo ahí para configurar ese enlace)")
            continue
        suyas = {str(r).strip() for r in (peerdatos[ident].get("redes") or [])}
        compartidas = [r for r in (set(redes) & suyas) if _prefijo_de(r) < 32]
        if len(compartidas) != 1:
            for e in grupo:
                motivo = (f"{len(compartidas)} redes en común" if len(compartidas) > 1
                          else "ninguna red en común")
                msgs.append(f"{e['itf']}: enlace con {ident} sin red única en el YAML ({motivo})")
            continue
        red = compartidas[0]
        rid_peer = peerdatos[ident].get("router-id") or ""
        claves = sorted({e["clave"] for e in grupo})
        for e in grupo:
            ip = _ip_enlace(red, router_id, rid_peer, claves.index(e["clave"]))
            if not ip:
                msgs.append(f"{e['itf']}: se acabaron los /30 de {red} (con {ident})")
                continue
            enlaces[e["itf"]] = {"ip": ip, "ident": ident, "red": red}

    # 3) resincronizar direcciones: sacar las que ya no corresponden al cable
    #    (incluye redes de enlaces viejos que ya no están en el YAML, siempre
    #    que la interfaz siga cableada; si no, la red ya no se anuncia igual)
    for f in _filas(api, "/ip/address/print"):
        addr = _decod(f.get("address", ""))
        itf = _decod(f.get("interface", ""))
        if itf in (itf_gestion, itf_loopback):
            continue
        if addr == enlaces.get(itf, {}).get("ip"):
            continue
        if _red_base(addr)[0] not in bases and itf not in enlaces:
            continue
        try:
            list(api("/ip/address/remove", **{".id": f.get(".id")}))
            msgs.append(f"{itf}: quitada {addr} (ya no corresponde al cable)")
        except Exception as e:  # noqa: BLE001
            msgs.append(f"{itf}: no se pudo quitar {addr}: {e}")

    # 4) poner la IP de cada enlace detectado
    for itf, info in enlaces.items():
        ip = info["ip"]
        ya_puesta = False
        en_otra = None
        for f in _filas(api, "/ip/address/print"):
            if _decod(f.get("address", "")) != ip:
                continue
            if _decod(f.get("interface", "")) == itf:
                ya_puesta = True
            else:
                en_otra = _decod(f.get("interface", ""))
        if ya_puesta:
            continue
        if en_otra:
            msgs.append(f"{itf}: la IP {ip} ya está puesta en {en_otra} "
                        "(¿dos enlaces con la misma red en el YAML?)")
            continue
        try:
            list(api("/ip/address/add", **{"address": ip, "interface": itf}))
            msgs.append(f"{itf} <- {ip} (con {info['ident']})")
        except Exception as e:  # noqa: BLE001
            msgs.append(f"{itf}: no se pudo poner {ip}: {e}")

    # 5) redes OSPF = lo que quedó cableado
    try:
        msgs.extend(_regenerar_redes_ospf(api, redes, bases, dir_loopback,
                                          itf_gestion, area=area))
    except Exception as e:  # noqa: BLE001
        msgs.append(f"redes OSPF: {e}")
    return msgs


def configurar_ospf(api, router_id, networks, area="0.0.0.0", redistribute=True,
                    loopback=None):
    """Paso 1: levanta OSPF sin depender de interfaces (todo desde el YAML).

    - crea (o reutiliza) la interfaz virtual con el /32 del router-id,
    - setea router-id y redistribute-connected en la instancia default,
    - sincroniza /routing/ospf/network con las redes del YAML: borra las
      que ya no estén en él y agrega las nuevas (re-ejecutar resincroniza).
    Las IPs de los enlaces las asigna el paso 2 (configurar_p2p), que es
    el que mira los cables.
    Devuelve lista de mensajes (info/errores) para reportar a la UI.
    """
    msgs = []
    loop_net = str(loopback).strip() if loopback else f"{_red_sin_prefijo(router_id)}/32"

    # 1) interfaz virtual para el router-id (loopback v7 o bridge v6)
    try:
        itf = _interfaz_loopback(api, loop_net) or _crear_loopback(api)
        _asignar_ip_a_interfaz(api, itf, loop_net)
        # sacar /32 viejos del router-id que hayan quedado en el loopback
        # (si cambió la numeración, si no quedan rutas conectadas fantasma)
        for f in _filas(api, "/ip/address/print"):
            if _decod(f.get("interface", "")) != itf:
                continue
            addr = _decod(f.get("address", ""))
            if addr != loop_net and _prefijo_de(addr) == 32:
                list(api("/ip/address/remove", **{".id": f.get(".id")}))
                msgs.append(f"loopback: quitada {addr} (router-id viejo)")
    except Exception as e:  # noqa: BLE001
        msgs.append(f"interfaz virtual: {e}")

    # 2) instancia OSPF
    try:
        err = _set_instancia_ospf(api, router_id, redistribute)
        if err:
            msgs.append(err)
    except Exception as e:  # noqa: BLE001
        msgs.append(f"instancia OSPF: {e}")

    # 3) redes OSPF = exactamente las del YAML, con el NOMBRE del area
    #    (no el area-id ni el .id; ver _area_ospf). Si ya coincide no se
    #    toca nada, para que re-ejecutar no reinicie OSPF.
    deseadas = {str(red).strip() for red in (networks or [])}
    actuales = _leer_redes_ospf(api)
    if _redes_equivalentes(actuales, deseadas):
        return msgs
    area_nombre = _area_ospf(api, area)
    menu = _menu_redes_ospf(api)
    campo = _campo_red_ospf(api)
    for n in _filas(api, menu + "/print"):
        try:
            list(api(menu + "/remove", **{".id": n.get(".id")}))
        except Exception as e:  # noqa: BLE001
            msgs.append(f"red vieja {_decod(n.get(campo, ''))}: {e}")
    for red in sorted(deseadas):
        try:
            _agregar_red_ospf(api, red, area_nombre or "")
        except Exception as e:  # noqa: BLE001
            msgs.append(f"red {red}: {e}")
    return msgs


def _fijar_clave(api, usuario, clave):
    """Cambia la clave del usuario indicado (por API). True si lo encontró."""
    if clave is None:
        return False
    for f in _filas(api, "/user/print"):
        if _decod(f.get("name", "")) == usuario:
            list(api("/user/set", **{".id": f.get(".id"), "password": str(clave)}))
            return True
    return False


def _fijar_identidad(api, nombre):
    """Setea /system/identity name (RouterOS usa 'name', no 'identity')."""
    list(api("/system/identity/set", **{"name": str(nombre)}))


def _macs_por_numero_gns3(gns3_host=None, timeout=4):
    """Mapea MAC de interfaz -> numero del nodo CHR, leyendo la API de GNS3.

    Sirve para que R<n> coincida con MikroTikCHR...-n del proyecto de GNS3,
    asi la topologia que muestra la app es la misma que la del canvas.
    Devuelve {} si GNS3 no responde o no hay nodos CHR.

    El host se toma de la variable de entorno GNS3_HOST
    (por defecto http://localhost:3080).
    """
    import os
    import re
    import json
    import urllib.request

    host = (gns3_host or os.environ.get("GNS3_HOST")
            or "http://localhost:3080").rstrip("/")

    def _get(path):
        with urllib.request.urlopen(host + path, timeout=timeout) as r:
            return json.load(r)

    try:
        proyectos = _get("/v2/projects")
    except Exception:  # noqa: BLE001
        return {}

    # primero el proyecto abierto/en ejecucion (el lab que se esta usando)
    proyectos.sort(key=lambda p: 0 if p.get("status") in ("opened", "started") else 1)
    for proy in proyectos:
        pid = proy.get("project_id")
        if not pid:
            continue
        try:
            nodos = _get(f"/v2/projects/{pid}/nodes")
        except Exception:  # noqa: BLE001
            continue
        mapa = {}
        for nodo in nodos:
            if nodo.get("node_type") != "qemu":
                continue
            m = re.search(r"-(\d+)$", nodo.get("name", ""))
            if not m:
                continue
            numero = int(m.group(1))
            for puerto in nodo.get("ports") or []:
                mac = (puerto.get("mac_address") or "").lower()
                if mac:
                    mapa[mac] = numero
        if mapa:
            return mapa
    return {}


def generar_inventario_ospf(hosts, usuario="admin", password="123",
                            passwords=None, fijar_identidad=True,
                            forzar_identidad=False, fijar_clave=None,
                            base="10.0", puerto=8728):
    """Arma el inventario OSPF (ospf.yml) leyendo la topología real por MNDP.

    No hay que cargar equipos ni redes a mano: se conecta a cada router,
    mira en cada interfaz qué vecino hay (MNDP/LLDP), deduce quién está
    cableado con quién, numera los routers R1..Rn por orden de IP y crea
    una red /24 por enlace (base.<a><b>.0/24) más el /32 de cada router-id.

    - 'passwords': claves a probar por equipo (por defecto [password, ''],
      por si alguno todavía tiene la clave de fábrica vacía).
    - 'fijar_identidad': deja cada equipo como R<n>. Es necesario para que
      el paso 2 reconozca los vecinos: si todos se llaman 'MikroTik' no se
      pueden distinguir.
    - 'fijar_clave': si no es None y difiere de la clave de fábrica, además
      normaliza la clave del usuario a ese valor (y lo refleja en el YAML).

    Devuelve {'ospf', 'yaml', 'equipos', 'enlaces', 'mensajes'}. Lanza
    ErrorMikroTik si no se pudo leer ningún equipo.
    """
    claves = list(passwords) if passwords else [password, ""]
    mensajes = []
    routers = {}
    mac_a_host = {}

    def _macs(api):
        macs = {}
        for f in _filas(api, "/interface/print"):
            if _decod(f.get("type", "")) != "ether":
                continue
            mac = (_decod(f.get("mac-address", "")) or "").lower()
            if mac:
                macs[_decod(f.get("name", ""))] = mac
        return macs

    for host in hosts:
        api = None
        clave = ""
        for intento in claves:
            try:
                api = conectar(host, usuario, intento, puerto=puerto)
                clave = intento
                break
            except ErrorMikroTik:
                api = None
        if not api:
            mensajes.append(f"{host}: sin acceso (API no responde o credenciales)")
            continue
        try:
            routers[host] = {
                "host": host,
                "identidad": identidad(api),
                "macs": _macs(api),
                "gestion": _interfaz_de_gestion(api, host),
                "vecinos": vecinos_interfaz(api),
                "password": clave,
                "api": api,
            }
        except ErrorMikroTik as e:
            mensajes.append(f"{host}: {e}")
            try:
                api.close()
            except Exception:  # noqa: BLE001
                pass
            continue
        for mac in routers[host]["macs"].values():
            mac_a_host[mac] = host

    if not routers:
        raise ErrorMikroTik("No se pudo leer ningún equipo de la red.")

    # número estable: si el lab corre en GNS3, R<n> = MikroTikCHR...-n para que
    # la topología de la app coincida con el canvas; si no, por orden de IP.
    mapa_gns3 = _macs_por_numero_gns3()
    numero = {}
    if mapa_gns3:
        for host, info in routers.items():
            for mac in info["macs"].values():
                if mac in mapa_gns3:
                    numero[host] = mapa_gns3[mac]
                    break
    if (len(numero) == len(routers)
            and len(set(numero.values())) == len(routers)
            and all(n >= 1 for n in numero.values())):
        orden = sorted(routers, key=lambda h: numero[h])
        mensajes.append("numeración por nodo GNS3 (R<n> = MikroTikCHR...-n)")
    else:
        orden = sorted(routers, key=lambda h: _ip_a_int(h) or 0)
        numero = {h: i + 1 for i, h in enumerate(orden)}

    # enlaces por MNDP: vecinos en interfaces que NO son la de gestión
    enlaces = {}
    for host, info in routers.items():
        for itf, vec in info["vecinos"].items():
            if itf == info["gestion"]:
                continue
            peer = mac_a_host.get((vec.get("mac") or "").lower())
            if not peer or peer == host:
                continue
            enlaces.setdefault(frozenset({host, peer}), {"a": host, "b": peer})

    # una red /24 por enlace: base.<n_a><n_b>.0/24 (como el ejemplo)
    usados = set()
    for en in enlaces.values():
        na, nb = sorted((numero[en["a"]], numero[en["b"]]))
        octeto = f"{na}{nb}"
        while octeto in usados:
            octeto = str(int(octeto) + 1)
        usados.add(octeto)
        en["red"] = f"{base}.{octeto}.0/24"

    # identidad y clave (opcional) antes de emitir el YAML
    if fijar_clave is not None:
        for host in orden:
            info = routers[host]
            if info["password"] == str(fijar_clave):
                continue
            try:
                if _fijar_clave(info["api"], usuario, fijar_clave):
                    info["password"] = str(fijar_clave)
                    mensajes.append(f"{host}: clave normalizada a {usuario}/{fijar_clave}")
            except Exception as e:  # noqa: BLE001
                mensajes.append(f"{host}: no se pudo fijar la clave: {e}")
    fabrica = {"", "mikrotik", "routeros", "sin nombre"}
    if fijar_identidad or forzar_identidad:
        for host in orden:
            info = routers[host]
            nuevo = f"R{numero[host]}"
            actual = (info["identidad"] or "").strip()
            if actual == nuevo:
                continue
            if not forzar_identidad and actual.lower() not in fabrica:
                # ya tiene un nombre propio (p. ej. Router-XX): no lo pisamos
                continue
            try:
                _fijar_identidad(info["api"], nuevo)
                info["identidad"] = nuevo
                mensajes.append(f"{host}: identidad -> {nuevo}")
            except Exception as e:  # noqa: BLE001
                mensajes.append(f"{host}: no se pudo fijar identidad: {e}")

    for info in routers.values():
        try:
            info["api"].close()
        except Exception:  # noqa: BLE001
            pass

    # redes por equipo = sus enlaces + su /32 de router-id
    redes_de = {h: [] for h in routers}
    for en in enlaces.values():
        redes_de[en["a"]].append(en["red"])
        redes_de[en["b"]].append(en["red"])

    equipos = []
    for host in orden:
        info = routers[host]
        n = numero[host]
        rid = f"{n}.{n}.{n}.{n}"
        equipos.append({
            "host": host,
            "usuario": usuario,
            "password": info["password"],
            "router-id": rid,
            "networks": sorted(set(redes_de[host] + [f"{rid}/32"])),
            "identidad": info["identidad"],
            "numero": n,
        })

    ospf = {"area": "0.0.0.0", "redistribute-connected": False, "equipos": equipos}
    lineas = ["ospf:", "  area: 0.0.0.0", "  redistribute-connected: false", "  equipos:"]
    for e in equipos:
        lineas.append(f"    - host: {e['host']}")
        lineas.append(f"      usuario: {e['usuario']}")
        lineas.append(f'      password: "{e["password"]}"')
        lineas.append(f"      router-id: {e['router-id']}")
        lineas.append("      networks:")
        for red in e["networks"]:
            lineas.append(f"        - {red}")

    lista_enlaces = sorted(
        ({"a": en["a"], "b": en["b"], "ra": numero[en["a"]],
          "rb": numero[en["b"]], "red": en["red"]} for en in enlaces.values()),
        key=lambda x: x["red"])

    return {"ospf": ospf, "yaml": "\n".join(lineas) + "\n",
            "equipos": equipos, "enlaces": lista_enlaces, "mensajes": mensajes}


def interfaces_con_trafico(api):
    """Interfaces ethernet con bytes y paquetes rx/tx (para monitoreo).

    Tambien dynamic/running/link-downs para saber si el enlace subio o si
    alguien cambió el cable.
    """
    filas = []
    for f in _filas(api, "/interface/print"):
        filas.append({
            "nombre": _decod(f.get("name", "")),
            "tipo": _decod(f.get("type", "")),
            "running": _decod(f.get("running", "")),
            "disabled": _decod(f.get("disabled", "")),
            "mac": _decod(f.get("mac-address", "")),
            "rx": _decod(f.get("rx-byte", "0")),
            "tx": _decod(f.get("tx-byte", "0")),
            "rx-packet": _decod(f.get("rx-packet", "0")),
            "tx-packet": _decod(f.get("tx-packet", "0")),
            "link-downs": _decod(f.get("link-downs", "0")),
        })
    return filas


def identidad(api):
    """Nombre (identity) del router en una sola consulta.

    En RouterOS la propiedad de /system/identity es "name" (no "identity").
    """
    fila = _primero(api, "/system/identity/print") or {}
    return _decod(fila.get("name", "") or fila.get("identity", ""))


def ospf_interfaces_lista(api):
    """Interfaces OSPF: costo, estado, DR y cantidad de vecinos.

    Las filas dinámicas (dynamic) nacen solas cuando la red forma parte de
    OSPF y no se pueden editar; las estáticas son las que el usuario creó
    para pisar esa métrica.
    """
    filas = []
    for f in _filas(api, "/routing/ospf/interface/print"):
        dinamica = bool(f.get("dynamic"))
        filas.append({
            "id": f.get(".id", ""),
            "interfaz": _decod(f.get("interface", "")),
            "costo": _decod(f.get("cost", "")),
            "estado": _decod(f.get("state", "")),
            "direccion": _decod(f.get("ip-address", "")),
            "vecinos": _decod(f.get("neighbors", "")),
            "adyacentes": _decod(f.get("adjacent-neighbors", "")),
            "dr": _decod(f.get("designated-router", "")),
            "tipo-red": _decod(f.get("network-type", "")),
            "dinamica": dinamica,
            "estatico": not dinamica,
            "pasiva": _decod(f.get("passive", "")),
            "instancia": _decod(f.get("instance", "")),
        })
    return filas


def fijar_costo_ospf(api, interfaz, costo):
    """Pone el costo OSPF de una interfaz (o lo restaura al dinámico con None).

    RouterOS 6 no acepta `set` sobre las filas dinámicas (responde
    "no such item"), así que para forzar una métrica hay que crear una fila
    estática con el mismo nombre de interfaz, que pasa a pisar a la dinámica.
    Pasando costo=None se borra esa fila y vuelve el costo por defecto.

    Devuelve mensaje de error o None si todo quedó bien.
    """
    filas = _filas(api, "/routing/ospf/interface/print")
    propia = None
    dinamica = None
    for f in filas:
        if _decod(f.get("interface", "")) != interfaz:
            continue
        if f.get("dynamic"):
            dinamica = f
        else:
            propia = f

    if costo is None:
        if propia is None:
            return None
        try:
            list(api("/routing/ospf/interface/remove",
                     **{".id": propia.get(".id")}))
            return None
        except Exception as e:  # noqa: BLE001
            return f"no se pudo restaurar el costo dinámico de {interfaz}: {e}"

    valor = str(int(costo))
    if propia is not None:
        if str(propia.get("cost", "")) == valor:
            return None
        try:
            list(api("/routing/ospf/interface/set",
                     **{".id": propia.get(".id"), "cost": valor}))
            return None
        except Exception as e:  # noqa: BLE001
            return f"no se pudo poner costo {valor} en {interfaz}: {e}"

    if dinamica is not None and str(dinamica.get("cost", "")) == valor:
        return None

    try:
        list(api("/routing/ospf/interface/add", interface=interfaz, cost=valor))
        return None
    except Exception as e:  # noqa: BLE001
        return f"no se pudo fijar costo {valor} en {interfaz}: {e}"


if __name__ == "__main__":
    red, ip = _local_red()
    print("Red local:", red, "| IP:", ip)
    found, r, i = detectar_mikrotiks(timeout=0.5)
    print("MikroTiks detectados:", found)