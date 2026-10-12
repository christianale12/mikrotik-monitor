# Monitor MikroTik — Documentación

> De paso cero (instalación) hasta cómo resuelve internamente cada problema y
> cómo se usa, paso a paso.
>
> Proyecto: `~/Monitor MikroTik`
> Repositorio: `git@github.com:christianale12/mikrotik-monitor.git`
> Autor: Christian

---

## Índice

1. [Qué es la aplicación](#1-qué-es-la-aplicación)
2. [Historia del desarrollo (git)](#2-historia-del-desarrollo-git)
3. [Arquitectura de la app](#3-arquitectura-de-la-app)
4. [Requisitos e instalación](#4-requisitos-e-instalación)
5. [Cómo se ejecuta](#5-cómo-se-ejecuta)
6. [Uso paso a paso](#6-uso-paso-a-paso)
7. [Cómo resuelve (motor interno)](#7-cómo-resuelve-motor-interno)
8. [Endpoints de la API](#8-endpoints-de-la-api)
9. [Archivos de configuración](#9-archivos-de-configuración)
10. [Compilar el .exe](#10-compilar-el-exe)
11. [Solución de problemas](#11-solución-de-problemas)

---

## 1. Qué es la aplicación

**Monitor MikroTik** es una aplicación de escritorio (Python + Flask + WebView)
que:

- **Detecta** routers MikroTik (RouterOS) en la red local por el puerto API `8728`.
- **Se conecta** a uno o varios equipos a la vez por la API binaria de RouterOS.
- **Consulta** la configuración y el estado: interfaces, IPs/ARP/DHCP, rutas,
  firewall, VLANs, bridges, NAT, WiFi y OSPF.
- **Configura OSPF automáticamente** en toda la topología: descubre los cables
  por MNDP/LLDP, numera los routers `R1..Rn`, arma el inventario `ospf.yml`,
  y levanta OSPF e interfaces con un clic (paso 1 y paso 2).
- **Monitorea en vivo**: tráfico real (bps), topología con estado de enlaces,
  alarmas con acciones automáticas de costo OSPF, direccionamiento por horario
  y métricas OSPF editables.
- **Exporta / compara / restaura** la configuración del equipo en YAML
  (incluido un comparador con restauración selectiva de cambios).

---

## 2. Historia del desarrollo (git)

```
9545152  2026-10-10  Versión inicial Monitor MikroTik (código fuente)
9ef8ef9  2026-10-10  Alarmas: umbral con selector de unidades (b/s, kb/s, Mb/s, Gb/s) y "Reglas configuradas"
edb50b0  2026-10-10  Direccionamiento: identidades en el grafo, rol ruta/evitar, regla manual con prioridad y reconciliador de fondo con reset a dinámico
99bc858  2026-10-10  Alarmas: métrica agregada "Total de red (suma)"; Direccionamiento: ver regla en el mapa y aplicar al guardar
38ca739  2026-10-10  Sesión activa: mostrar el equipo seleccionado (host + identidad) y estilo oscuro del selector
8f3afc3  2026-10-10  Sesión: guardar/comparar/restaurar operan sobre el equipo activo
688d01e  2026-10-10  gitignore: ignorar exportaciones generadas (config_*.yaml)
91a7af2  2026-10-10  Direccionamiento: la regla vigente prioriza el horario, pre-aplica 30s antes y muestra la franja
54f630d  2026-10-11  Topología: panel "Reglas y alarmas activas" con franja + cuenta regresiva; caminos como "R1 (ip)"
```

Branch activa: `main`. Remote: `origin` → `christianale12/mikrotik-monitor`.

---

## 3. Arquitectura de la app

```
Monitor MikroTik/
├── app.py                  # Backend Flask: rutas /api/*, sesiones, diff y restauración
├── monitoreo.py            # Motor en vivo: muestreo, topología, alarmas, direccionamiento, costos OSPF
├── transporte_mikrotik.py  # Capa de acceso a RouterOS (librouteros): escaneo, conexión, lectura y configuración
├── app_desktop.py          # Lanzador de escritorio: levanta Flask y abre una ventana WebView2 (pywebview)
├── templates/index.html    # UI completa (HTML + CSS + JS) de una sola página
├── monitoreo.yml           # Estado persistente: alarmas, direccionamiento, capacidades, costos aplicados
├── ospf.yml                # Inventario OSPF (se genera solo con MNDP)
├── MonitorMikroTik.spec    # Receta de PyInstaller (empaqueta templates/ dentro del exe)
├── dist/MonitorMikroTik.exe# Ejecutable Windows compilado
└── .venv/                  # Entorno virtual (Flask, librouteros, pywebview, netaddr, PyYAML…)
```

### 3.1 Capas

| Capa | Archivo | Responsabilidad |
|---|---|---|
| Presentación | `templates/index.html` | Toda la interfaz (login, consultas, monitoreo, alarmas, dirección). |
| Servidor | `app.py` | API REST (`/api/...`), manejo de múltiples sesiones en memoria, exportar/comparar/restaurar. |
| Lógica de red en vivo | `monitoreo.py` | Tasas en bps, topología, motor de alarmas, reconciliación de costos OSPF. |
| Transporte | `transporte_mikrotik.py` | Escaneo de red, conexión API, lectura de tablas, configuración OSPF y direcciones /30. |
| Escritorio | `app_desktop.py` | Ventana nativa (sin navegador) y diálogos nativos "Guardar/abrir YAML". |

### 3.2 Modelo de sesiones

`app.py` mantiene `SESIONES = {host: {"api", "host", "usuario"}}` en memoria.
La API de RouterOS es un socket con una sola secuencia de respuestas, así que
`transporte_mikrotik._ApiSerial` **serializa cada uso con un candado** y
materializa las respuestas en lista (las funciones de librouteros son perezosas).
La UI permite elegir el **equipo activo** con un selector; los endpoints aceptan
`host` para operar sobre un equipo concreto cuando hay varias sesiones.

---

## 4. Requisitos e instalación

### 4.1 Requisitos

- Python 3.12 (probado con 3.12.3).
- Acceso de red al puerto **API 8728** de los MikroTik (servicio `api`
  habilitado en `/ip service`).
- En el laboratorio: GNS3/libvirt con CHR encendidos.

Dependencias clave (entorno `.venv`):

```
Flask==3.1.3
Werkzeug==3.1.9
Jinja2==3.1.2
librouteros==4.1.1
pywebview==6.2.1
netaddr==0.8.0
PyYAML==6.0.1
pyinstaller==6.22.3
```

### 4.2 Instalación desde cero

```bash
cd ~/"Monitor MikroTik"
python3 -m venv .venv
source .venv/bin/activate
pip install flask librouteros pywebview netaddr pyyaml pyinstaller
```

---

## 5. Cómo se ejecuta

### Modo navegador (servidor Flask)

```bash
cd ~/"Monitor MikroTik"
source .venv/bin/activate
python app.py
# Abre http://0.0.0.0:5010 en el navegador
```

### Modo ventana nativa (recomendado)

```bash
python app_desktop.py
```

- Levanta Flask en un puerto libre (`127.0.0.1`), espera a que responda y abre
  una ventana **WebView2** (pywebview) sin navegador.
- Expone diálogos nativos de Windows para **Guardar como** y **abrir YAML**
  (`ApiGuardar`), necesarios para exportar/comparar/restaurar archivos.

### Lanzador de escritorio (Linux)

`~/Escritorio/Monitor MikroTik.desktop` ejecuta
`.venv/bin/python "app_desktop.py"` con icono `network-wired`.

### Ejecutable Windows

`dist/MonitorMikroTik.exe` (13 MB) incluye la app y `templates/` (ver §11).

---

## 6. Uso paso a paso

### 6.1 Paso 1 — Detectar y conectar (pantalla de login)

1. **🔍 Escanear red local**: escanea todas las redes `/24` de las interfaces
   activas de esta PC buscando el puerto `8728` abierto. Por cada equipo
   detectado intenta leer identidad/versión (si el MikroTik no tiene
   credenciales por defecto, lo marca "🔒 Requiere credenciales").
2. **✏️ Poner IP a mano**: para escribir la IP directamente.
3. Seleccioná un equipo de la lista (o marcalos con la casilla) y escribí
   **Usuario** (`admin`) y **Contraseña**.
4. **🔓 Entrar con la clave** conecta un equipo; **🚀 Conectar los marcados**
   conecta en lote (`/api/conectar_multi`).
5. Al conectar se muestra el **estado general** (identidad, versión, board,
   uptime, CPU, memoria/disco) y aparece el **Paso 2**.

### 6.2 Paso 2 — Sesión activa y equipo activo

- El banner muestra "Conectado a \<equipo\>" y un **selector de equipo activo**.
- Con varias sesiones podés cambiar de equipo sin reconectar; cada consulta
  usa el equipo activo (se envía su `host`).
- **Cerrar sesión** desconecta el equipo activo (o todos).

### 6.3 Consultar información

Botones de consulta (equipo activo): **Interfaces**, **IPs/ARP/DHCP**,
**Rutas/Firewall**, **VLANs/Bridge**, **NAT**, **🌐 OSPF**, **📈 Tráfico**,
**Estado general**. Cada uno llama a `POST /api/datos` con su `categoria`.

### 6.4 OSPF automático (el flujo central)

**a) 🧩 Generar ospf.yml (auto)** → `POST /api/ospf_generar`

- Escanea la red (o usa las sesiones abiertas).
- Se conecta a cada router, lee **vecinos MNDP/LLDP por interfaz** y deduce
  quién está cableado con quién.
- Numera `R1..Rn` (si el lab está en GNS3, usa el número del nodo
  `MikroTikCHR...-n`; si no, por orden de IP).
- Fija **identidad** (`R<n>`) y opcionalmente la **clave**, y crea **una red
  `/24` por enlace** (`base.<a><b>.0/24`) más el `/32` de cada router-id.
- Muestra una **vista previa** y permite **💾 Guardar** el `ospf.yml`.

**b) 🚀 1) Levantar OSPF desde YAML** → `POST /api/ospf_levantar`

Por cada equipo del YAML:
- Crea/reutiliza la interfaz virtual del router-id
  (RouterOS 7: `/interface/loopback`; RouterOS 6: un `bridge` sin puertos).
- Configura la instancia OSPF (router-id + redistribución) y el área backbone.
- Sincroniza las **redes OSPF del YAML** (idempotente: si ya coinciden no toca
  nada → no reinicia OSPF).

**c) 🔌 2) Levantar interfaces (según cables)** → `POST /api/ospf_interfaces`

Por cada equipo:
- Descubre por **MNDP** qué vecino hay en cada interfaz.
- Busca la **única red en común** del par en el YAML y le asigna una **IP `/30`**
  (o `/31`) determinista.
- **Resincroniza**: quita direcciones que ya no corresponden al cable y
  regenera las redes OSPF a partir de lo realmente cableado.
- Se puede **re-ejecutar** si agregás/quitás placas, cables o routers.

### 6.5 Guardar / comparar / restaurar configuración

- **💾 Guardar configuración (YAML)**: exporta solo los bloques marcados
  (Equipo, Interfaces, IPs, Rutas, VLANs, Firewall, NAT, ARP, DHCP, Pools, DNS,
  Usuarios, Gateway). Diálogo nativo "Guardar como" → `config_<equipo>_<fecha>.yaml`.
- **🗂 Guardar configuración completa**: todos los bloques.
- **🔁 Comparar dos configuraciones**: elegís dos YAML; muestra diferencias
  (`agregado` / `eliminado` / `cambiado`) ignorando campos volátiles
  (hora, uptime, contadores, `.id`).
- **⬆️ Restaurar desde YAML**: devuelve el equipo a una configuración guardada.
  Compara el YAML deseado (A) contra el estado actual leído en vivo (B) y aplica
  los cambios restaurables. Restauración **selectiva**: en el comparador podés
  tildar solo los cambios que querés revertir.

### 6.6 Monitoreo en vivo

Se abre con **📈 Tráfico** o **moniAbrir**. Refresca cada 1/2/5/10 s (configurable
y persistido en `localStorage`), con botón **⏸ Pausar**.

**Pestaña 📈 Tráfico**
- Tarjetas: Tráfico total, RX, TX, Alarmas activas, Enlaces caídos.
- Por equipo e interfaz: RX/TX en bps, barra de uso vs capacidad, estado
  (`UP` / `DOWN` / severidad de alarma). Filtro por equipo.

**Pestaña 🕸 Topología**
- Grafo en SVG de nodos (routers y externos) y enlaces detectados, con estado
  (`full`, `degradado`, `caido`, `sin-ospf`, `saturado`) y reenvío.
- Panel "Reglas y alarmas activas" con franja horaria y cuenta regresiva.
- Cambia el **costo OSPF** de un enlace o lo restaura a dinámico desde el mapa.

**Pestaña 🚨 Alarmas**
- "Nueva regla": Nombre, Equipo (vacío = todos), Interfaz (patrón `ether*`),
  Métrica (`Total`, `Total de red (suma)`, `RX`, `TX`, `% saturación`),
  Comparar, Umbral (con selector b/s, kb/s, Mb/s, Gb/s), Severidad
  (info/alerta/crítico), Duración, Limpiar, Acción
  (ninguna / manual / **automática**) y Costo a aplicar (y "Costo normal").
- Tabla "Reglas configuradas" (editar, habilitar/deshabilitar, borrar).
- Tabla "Monitoreo por interfaz" (evaluación del último ciclo) y
  "Eventos recientes".

**Pestaña 🛣 Direccionamiento** (forzar caminos OSPF)
- **Modo manual** (se aplica con ▶ Aplicar) o **automático** (por franja
  horaria `HH:MM` desde/hasta, con días opcionales).
- Se arma el **camino con clics en el mapa** (router → enlaces) y se definen
  "Costo de la ruta" y "Costo a evitar" → 🚫 **Forzar este camino**.
- O se cargan entradas manuales (equipo · interfaz · costo · rol ruta/evitar).
- **⟲ Quitar regla manual** vuelve a dinámico; **🧹 Devolver TODO a costo
  dinámico** limpia todos los costos estáticos.

**Pestaña 📏 Métricas OSPF**
- Costo y estado OSPF por interfaz; cambiar costo individual o de enlace
  completo; configuración de capacidades por defecto y umbral de saturación.

### 6.7 Avisos

Toasts en pantalla, sonido (`moniBeep`) y notificaciones del navegador
(`moniNotificar`) cuando se dispara una alarma.

---

## 7. Cómo resuelve (motor interno)

### 7.1 Descubrimiento de equipos

`transporte_mikrotik.detectar_mikrotiks()`:
- Enumera las IPs de **todas** las interfaces locales (ioctl `SIOCGIFADDR` en
  Linux + `getaddrinfo`), arma las redes `/24`, y prueba el puerto `8728` con
  hilos (semáforo de 100). Devuelve `(ips, redes, ip_local)`.

### 7.2 Muestreo de tráfico (bps)

Los contadores `rx-byte`/`tx-byte` de RouterOS son **acumulados**. En
`monitoreo.muestrear()` se guarda la muestra anterior por interfaz y la tasa
sale de:

```
bps = (byte_actual − byte_anterior) × 8 / Δt
```

Si el contador baja (reinicio de interfaz) o `Δt > 60 s`, la tasa es 0.
`pct = max(rx_bps, tx_bps) × 100 / capacidad`.

### 7.3 Topología por MNDP + OSPF

`monitoreo._armar_topologia()` combina:
- Vecinos **MNDP/LLDP** (`/ip/neighbor/print`) para saber vecino por interfaz.
- Direcciones IP/red de cada interfaz y estado OSPF (`/routing/ospf/interface`
  y `/routing/ospf/neighbor`).
- Empareja extremos del cable por MAC (clave estable) y por vecino OSPF;
  mantiene **memoria** de routers/cables que dejan de responder (120 s) para
  no "borrar" un equipo caído de golpe.
- Marca enlaces `full/degradado/caido/sin-ospf/saturado` y calcula el
  **reenvío** (por qué camino sale hoy, según las rutas OSPF activas).

### 7.4 Compatibilidad RouterOS 6 y 7

`transporte_mikrotik` detecta la versión mayor y cambia de menú:
- Redes OSPF: v7 `/routing/ospf/interface-template` (`networks`, `type=ptp`);
  v6 `/routing/ospf/network` (`network`) + interfaces estáticas
  `/routing/ospf/interface` con `network-type=point-to-point`.
- Loopback: v7 `/interface/loopback`; v6 `bridge` sin puertos.
- Instancia: v7 se crea `default`; v6 ya existe.

### 7.5 Direccionamiento `/30` determinista (sin coordinación)

`_ip_enlace(red, rid_a, rid_b, indice)`:
- **Mayor router-id → `.1`**, menor → `.2` (o `.2`/`.1` con la misma regla).
- Cada extremo lo calcula solo, así ambos coinciden sin hablarse.
- Enlaces **paralelos** entre el mismo par: cada uno ocupa su `/30`
  (`indice`), y el orden es idéntico en ambos lados porque la clave es el
  **menor MAC** de los dos extremos.
- Soporta `/31` (enlace directo sin broadcast, sin paralelos).

### 7.6 Costo OSPF (dinámico vs estático)

`fijar_costo_ospf(api, interfaz, costo)`:
- RouterOS 6 **no** permite `set` sobre filas dinámicas (responde "no such item").
  Para forzar una métrica se crea una **fila estática** con el mismo nombre de
  interfaz, que pisa a la dinámica.
- `costo=None` borra la fila estática → vuelve el costo por defecto.

### 7.7 Motor de alarmas (`_evaluar_alarmas`)

- Por cada regla se calculan las interfaces que matchean su alcance
  (equipo/identidad + patrón `fnmatch`).
- Métrica `red-bps` = **suma de rx+tx de todas las interfaces del alcance**
  (igual número que la tarjeta "Tráfico total"); el resto se evalúa por interfaz.
- Se aplica **histéresis**: la alarma se activa tras `duracion-s` cumpliendo el
  umbral y se limpia tras `limpiar-s` por debajo.
- **Acción automática**: al activarse agrega un **efecto** (costo al enlace en
  ambos extremos) y recuerda el "costo normal" de respaldo; al limpiarse vuelve
  a la regla de direccionamiento vigente o al costo normal. Genera **eventos**
  (`activada` / `desactivada`) que la UI consume por `seq`.

### 7.8 Reconciliador de costos (prioridad)

`_reconciliar_costos()` lleva los costos al estado deseado con esta prioridad:

```
alarma activa  >  regla de direccionamiento vigente  >  costo "normal"  >  dinámico
```

- Solo envía a los equipos **la diferencia** contra lo ya aplicado (no reinicia
  OSPF en cada ciclo).
- Un **hilo de fondo** en `app.py` (`_hilo_reconciliador`, cada 3 s) mantiene el
  estado aunque la UI esté cerrada: si no hay regla vigente, devuelve a dinámico
  lo que el motor había cambiado (evita caminos "pegados").

### 7.9 Regla vigente y pre-aplicación

`regla_vigente()`:
- Manda la **primera regla con horario que cumple ahora** (modo `horario`).
- Si ninguna franja está activa, recién ahí la **elegida a mano**
  (`regla-activa`, modo `manual`).
- **`ANTICIPO_RECONVERGENCIA = 30 s`**: la franja que está por comenzar se
  pre-aplica 30 s antes, para que OSPF ya haya reconvergido cuando empiece.
- Soporta cruce de medianoche y días de la semana.

### 7.10 Comparador y restauración

`_flatten_diff(A, B)` recorre ambas estructuras y devuelve diferencias:
- Listas de filas (dicts) se emparejan por **clave natural**
  (nombre, dirección+prefijo, dst-address, etc.) para que agregar/eliminar un
  item no corra los índices de los demás.
- Ignora campos volátiles (`hora`, `uptime`, contadores, `.id`).
- `_aplicar_un_cambio()` revierte un cambio puntual:
  - campo cambiado → `/set` del valor de A;
  - fila eliminada (estaba en A, no en B) → `/add` (o regenerar ruta dinámica);
  - fila agregada (está en B, no en A) → `/remove`.
- Firewall/NAT se **reposicionan** tras recrear (el orden importa).
- Rutas/IP dinámicas no se crean ni borran a mano: se regeneran solas
  (para una ruta conectada, se vuelve a crear su IP origen).

### 7.11 Serialización de la API

`_ApiSerial` envuelve la conexión de librouteros con un `RLock`: cada llamada
se ejecuta y su resultado se materializa en lista dentro del candado. Evita que
dos consultas simultáneas (UI + monitoreo) mezclen paquetes y caigan la sesión.

---

## 8. Endpoints de la API

| Método | Ruta | Función |
|---|---|---|
| GET | `/` | Página principal. |
| POST | `/api/escanear` | Escaneo de red buscando puerto 8728. |
| POST | `/api/identificar` | Identidad/versión de un host (best-effort). |
| POST | `/api/conectar` | Conecta un equipo. |
| POST | `/api/conectar_multi` | Conecta varios (lista `equipos` o `yaml`). |
| GET/POST | `/api/equipos` | Equipos conectados y su estado. |
| POST | `/api/datos` | Consulta una categoría (`estado`, `interfaces`, `ip`, `rutas`, `vlanes`, `nat`, `wifi`, `ospf`, `trafico`). |
| POST | `/api/ospf_generar` | Genera `ospf.yml` por MNDP. |
| POST | `/api/ospf_levantar` | Paso 1: levanta OSPF desde YAML. |
| POST | `/api/ospf_interfaces` | Paso 2: IPs `/30` según cables. |
| POST | `/api/monitoreo` | Ciclo en vivo (tasas, alarmas, eventos `desde`). |
| POST | `/api/topologia` | Grafo de nodos y enlaces. |
| POST | `/api/alarmas` | Listar/guardar/borrar/restaurar reglas de alarma. |
| POST | `/api/direccionamiento` | Listar/guardar/borrar/activar/desactivar/restaurar reglas de camino. |
| POST | `/api/capacidades` | Capacidad por enlace y umbral de saturación. |
| POST | `/api/metricas` | Costos OSPF por interfaz y cambio manual. |
| POST | `/api/exportar` | Genera YAML de configuración del equipo. |
| POST | `/api/restaurar` | Restaura cambios seleccionados (selectiva). |
| POST | `/api/restaurar_completa` | Restaura una configuración completa. |
| POST | `/api/comparar` | Compara dos YAML. |
| POST | `/api/desconectar` | Cierra la sesión de un equipo o todas. |

---

## 9. Archivos de configuración

### 9.1 `monitoreo.yml` (estado persistente)

Se guarda junto al script/exe. Contiene:

```yaml
capacidad-default: 500000        # bps por defecto por interfaz
saturado-pct: 70                 # % a partir del cual se marca saturado
capacidades: {}                  # override por "host/interfaz"
alarmas: [...]                   # reglas de alarma
regla-activa: dir-xxxx           # regla manual vigente
direccionamiento: [...]          # reglas de camino (modo manual/auto)
aplicado: [...]                  # costos que el motor dejó puestos (para reconciliar)
```

### 9.2 `ospf.yml` (inventario OSPF)

```yaml
ospf:
  area: 0.0.0.0
  redistribute-connected: false
  equipos:
    - host: 192.168.122.246
      usuario: admin
      password: "123"
      router-id: 1.1.1.1
      networks: [1.1.1.1/32, 10.0.12.0/24]
```

### 9.3 `config_<equipo>_<fecha>.yaml` (exportado, ignorado por git)

Configuración completa del equipo por bloques (`mikrotik:` → `equipo`,
`interfaces`, `ip`, `rutas`, `vlanes`, `filtros`, `nat`, `arp`, `dhcp`, `pools`,
`dns`, `usuarios`, `gateway`).

---

## 10. Compilar el .exe

`MonitorMikroTik.spec` (PyInstaller) empaqueta `app_desktop.py` e incluye
`templates/`:

```bash
cd ~/"Monitor MikroTik"
source .venv/bin/activate
pyinstaller MonitorMikroTik.spec
# Salida: dist/MonitorMikroTik.exe
```

`app.py` prioriza `templates/` **junto al exe** (editable) y, si no existe, usa
la copia interna. `monitoreo.yml` se escribe junto al exe.

---

## 11. Solución de problemas

| Síntoma | Causa / solución |
|---|---|
| "No se encontró MikroTik en la red" | API deshabilitada (`/ip service set api disabled=no`), firewall, o red fuera del `/24` local. Usar "Poner IP a mano". |
| "Credenciales incorrectas" | Usuario/clave mal; probar `admin` / clave de fábrica vacía. |
| "Requiere credenciales" al escanear | El equipo no permite login con credenciales por defecto (normal). |
| OSPF no sube a `Full` | Revisar que las IPs `/30` estén puestas (paso 2) y que la red del enlace esté anunciada (paso 1). |
| Costos "pegados" tras cerrar la app | **🧹 Devolver TODO a costo dinámico** o `POST /api/direccionamiento {accion:"restaurar"}`. |
| Cambios no se restauran | La fila del YAML ya no existe en el router, o la sección no es editable/restaurable. |
| WebView no abre | Instalar pywebview/WebView2; o usar `python app.py` en el navegador. |

---

*Documento generado a partir del código fuente, el historial git y los archivos
de laboratorio del proyecto.*
