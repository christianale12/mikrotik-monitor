#!/usr/bin/env python3
"""
Monitor MikroTik - App de escritorio
====================================
Abre la interfaz web en una VENTANA NATIVA de Windows (WebView2 via pywebview),
sin abrir el navegador.

Uso:
    python app_desktop.py

Requiere:
    pip install pywebview flask librouteros netaddr
"""

import os
import socket
import sys
import threading
import time

import webview

import app as core

TITULO = "Monitor MikroTik - RouterOS"


def puerto_libre():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def esperar_servidor(host, puerto, timeout=15):
    limite = time.time() + timeout
    while time.time() < limite:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((host, puerto)) == 0:
                return True
        time.sleep(0.1)
    return False


class ApiGuardar:
    """Expone a la interfaz web un dialogo nativo 'Guardar como' de Windows
    (via pywebview) para que el usuario elija la carpeta y el nombre
    del archivo YAML de configuracion."""

    def __init__(self):
        self.ultima_ruta = None

    def guardar_yaml(self, contenido, nombre_sugerido="config_mikrotik.yaml"):
        if not webview.windows:
            return {"ok": False, "error": "No hay ventana activa."}
        win = webview.windows[0]
        ruta = win.create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=nombre_sugerido,
        )
        if not ruta:
            return {"ok": False, "cancelado": True}
        ruta = ruta if isinstance(ruta, str) else ruta[0]
        try:
            with open(ruta, "w", encoding="utf-8") as f:
                f.write(contenido)
            self.ultima_ruta = ruta
            return {"ok": True, "ruta": ruta}
        except OSError as e:
            return {"ok": False, "error": f"No se pudo escribir el archivo: {e}"}

    def abrir_yamls(self):
        """Abre dos archivos YAML (dialogo nativo) y devuelve sus contenidos."""
        if not webview.windows:
            return {"ok": False, "error": "No hay ventana activa."}
        win = webview.windows[0]
        rutas = win.create_file_dialog(
            webview.OPEN_DIALOG,
            allow_multiple=True,
            file_types=("YAML (*.yaml;*.yml)", "Todos los archivos (*.*)"),
        )
        if not rutas:
            return {"ok": False, "cancelado": True}
        if isinstance(rutas, str):
            rutas = [rutas]
        if len(rutas) < 2:
            return {"ok": False, "error": "Selecciona dos archivos YAML para comparar."}
        try:
            import yaml as _yaml
            docs = []
            for ruta in rutas[:2]:
                with open(ruta, "r", encoding="utf-8") as f:
                    docs.append((os.path.basename(ruta), f.read()))
        except (OSError, UnicodeDecodeError) as e:
            return {"ok": False, "error": f"No se pudo leer un archivo: {e}"}
        return {
            "ok": True,
            "archivo_a": docs[0][0],
            "yaml_a": docs[0][1],
            "archivo_b": docs[1][0],
            "yaml_b": docs[1][1],
        }

    def abrir_yaml(self):
        """Abre un solo archivo YAML (dialogo nativo) y devuelve su contenido."""
        if not webview.windows:
            return {"ok": False, "error": "No hay ventana activa."}
        win = webview.windows[0]
        rutas = win.create_file_dialog(
            webview.OPEN_DIALOG,
            file_types=("YAML (*.yaml;*.yml)", "Todos los archivos (*.*)"),
        )
        if not rutas:
            return {"ok": False, "cancelado": True}
        ruta = rutas if isinstance(rutas, str) else rutas[0]
        try:
            with open(ruta, "r", encoding="utf-8") as f:
                contenido = f.read()
        except (OSError, UnicodeDecodeError) as e:
            return {"ok": False, "error": f"No se pudo leer el archivo: {e}"}
        return {"ok": True, "archivo": os.path.basename(ruta), "yaml": contenido}


api_guardar = ApiGuardar()


def main():
    puerto = puerto_libre()
    host = "127.0.0.1"

    servidor = threading.Thread(
        target=lambda: core.app.run(host=host, port=puerto,
                                    debug=False, use_reloader=False),
        daemon=True,
    )
    servidor.start()

    if not esperar_servidor(host, puerto):
        print("No se pudo iniciar el servidor interno.", file=sys.stderr)
        raise SystemExit(1)

    webview.create_window(
        TITULO,
        f"http://{host}:{puerto}",
        width=1000,
        height=720,
        min_size=(700, 520),
        background_color="#060913",
        js_api=api_guardar,
    )
    webview.start()


if __name__ == "__main__":
    main()