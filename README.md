# fridump

Herramienta para volcado de memoria de procesos en Android, iOS y desktop vía Frida.

Reemplazo funcional de [fridump3](https://github.com/rootbsd/fridump3), compatible con **Frida 17.0.0+** (17.5 en adelante). El script original dejó de funcionar debido a los breaking changes introducidos en Frida 17 (mayo 2025):

- `Memory.readByteArray()` estático eliminado → `ptr().readByteArray()`
- `Process.enumerateRangesSync()` eliminado → `Process.enumerateRanges()`
- `script.exports` deprecado en Python → `script.exports_sync`

## Uso

```
python3 fridump.py <proceso|PID> -U
```

##### Opciones:

```
process               Nombre del proceso o PID a instrumentar

-U, --usb             Dispositivo conectado por USB
-H, --host HOST       Dispositivo conectado por IP[:puerto]
-o, --out DIR         Directorio de salida (def: dump)
-p, --perms PERMS     Permisos de memoria a volcar (def: rw-)
-r, --read-only       Volcar regiones de solo lectura (r--)
-s, --strings         Extraer strings de los dumps al finalizar
--max-size BYTES      Tamaño máximo por región antes de fragmentar (def: 20 MiB)
--spawn               Lanzar (spawn) el proceso en lugar de attach
--dry-run             Solo listar regiones, sin volcar a disco
-v, --verbose         Logging verbose
-d, --debug           Logging debug
```

##### Ejemplos:

```bash
# Volcado básico por USB
python3 fridump.py com.app.target -U

# Volcado con extracción de strings
python3 fridump.py com.app.target -U -s

# Spawn + solo lectura + strings
python3 fridump.py com.app.target -U --spawn -r -s

# Conexión remota
python3 fridump.py com.app.target -H 192.168.1.50

# Listar regiones sin volcar
python3 fridump.py com.app.target -U --dry-run
```

## Requisitos

| Componente     | Dónde       | Versión               |
| -------------- | ----------- | --------------------- |
| Python         | Host        | >= 3.10               |
| `frida`        | Host        | >= 17.0.0             |
| `frida-server` | Dispositivo | Misma major que Frida |
| ADB            | Host        | Cualquiera            |
| Root / Magisk  | Dispositivo | Requerido             |

## Agradecimientos

Este proyecto está basado en el trabajo de:

- [fridump](https://github.com/Nightbringer21/fridump) por [@Nightbringer21](https://github.com/Nightbringer21) — herramienta original de volcado de memoria vía Frida.
- [fridump3](https://github.com/rootbsd/fridump3) por [@rootbsd](https://github.com/rootbsd) — port a Python 3 y Frida moderno.

## Autor

- Federico Galarza - [@fedeScripts](https://github.com/fedeScripts)

[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/federico-galarza)
