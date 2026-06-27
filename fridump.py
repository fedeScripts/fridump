#!/usr/bin/env python3

# ----------
# fridump.py
# ----------
# Autor:        Federico Galarza
# Descripción:  Volcado de memoria de procesos vía Frida 17+
# Uso:          python3 fridump.py <proceso|PID> -U [-s] [--dry-run]
# Requisitos:   frida >= 17.0.0 (pip install frida), frida-server en el device
# Notas:        Reemplazo de fridump3, adaptado a breaking changes de Frida 17.
# -----------------------------------------------------------------------------

from __future__ import annotations

import argparse
import logging
import os
import re
import signal
import sys
import time
from pathlib import Path
from types import FrameType
from typing import Optional

# --- constantes ---
SCRIPT_NAME: str = "fridump"
VERSION: str = "1.0"

DEFAULT_MAX_SIZE: int = 20 * 1024 * 1024   # 20 MiB
DEFAULT_PERMS: str = "rw-"
DEFAULT_OUT_DIR: str = "dump"
MIN_STRING_LEN: int = 4

# --- codigos de salida ---
EXIT_OK: int = 0
EXIT_USAGE: int = 2
EXIT_NETWORK: int = 3
EXIT_PERMS: int = 4
EXIT_VALIDATION: int = 5
EXIT_UNEXPECTED: int = 6
EXIT_SIGINT: int = 130

# --- colores ---
_BOLD: str   = "\033[1m"
_RED: str    = f"{_BOLD}\033[31m"
_GREEN: str  = f"{_BOLD}\033[38;5;82m"
_PURPLE: str = f"{_BOLD}\033[38;2;175;0;255m"
_YELLOW: str = f"{_BOLD}\033[38;5;3m"
_RST: str    = "\033[0m"

_USE_COLOR: bool = sys.stderr.isatty() and not os.environ.get("NO_COLOR")

# --- logging ---
LOG_STEP: int = 25
LOG_SUCCESS: int = 26

logging.addLevelName(LOG_STEP, "STEP")
logging.addLevelName(LOG_SUCCESS, "OK")

logger: logging.Logger = logging.getLogger(SCRIPT_NAME)


class _ScriptFormatter(logging.Formatter):

    _TAG_MAP: dict[int, tuple[str, str]] = {
        logging.DEBUG:    (_YELLOW, "[DEBUG]"),
        logging.INFO:     (_PURPLE, "[i]"),
        LOG_STEP:         (_PURPLE, "[+]"),
        LOG_SUCCESS:      (_GREEN,  "[ok]"),
        logging.WARNING:  (_YELLOW, "[!]"),
        logging.ERROR:    (_RED,    "[X]"),
        logging.CRITICAL: (_RED,    "[X]"),
    }

    def format(self, record: logging.LogRecord) -> str:
        color, tag = self._TAG_MAP.get(record.levelno, ("", "[?]"))
        if _USE_COLOR and color:
            record.msg = f"{color}{tag}{_RST} {record.msg}"
        else:
            record.msg = f"{tag} {record.msg}"
        return super().format(record)


def _setup_logging(level: int) -> None:
    handler = logging.StreamHandler(sys.stderr)
    fmt: str = ("%(message)s  (%(funcName)s:%(lineno)d)"
                if level <= logging.DEBUG else "%(message)s")
    handler.setFormatter(_ScriptFormatter(fmt))
    logger.addHandler(handler)
    logger.setLevel(level)


# --- helper de log ---
_LOG_LEVELS: dict[str, int] = {
    "step":    LOG_STEP,
    "success": LOG_SUCCESS,
    "info":    logging.INFO,
    "warn":    logging.WARNING,
    "error":   logging.ERROR,
    "debug":   logging.DEBUG,
}


def log(level: str, msg: str = "", *args: object) -> None:
    if level == "list":
        sys.stderr.write(f"    {msg}\n")
        return
    if level == "ln":
        sys.stderr.write("\n")
        return
    lvl: Optional[int] = _LOG_LEVELS.get(level)
    if lvl is not None:
        logger.log(lvl, msg, *args, stacklevel=2)


# --- barra de progreso ---
def _progress(current: int, total: int, prefix: str = "Progreso",
              suffix: str = "", bar_len: int = 40) -> None:
    if total == 0:
        return
    filled: int = int(bar_len * current / total)
    pct: float = 100.0 * current / total
    bar: str = "#" * filled + "-" * (bar_len - filled)
    line: str = f"\r{prefix} [{bar}] {pct:5.1f}%"
    if suffix:
        line += f" {suffix}"
    sys.stderr.write(line)
    sys.stderr.flush()
    if current >= total:
        sys.stderr.write("\n")


# --- manejo de señales ---
_shutdown_requested: bool = False


def _signal_handler(signum: int, _frame: Optional[FrameType]) -> None:
    global _shutdown_requested
    _shutdown_requested = True
    sig_name: str = signal.Signals(signum).name
    log("warn", "Señal %s recibida — deteniendo volcado...", sig_name)


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# --- script JS (Frida >= 17.0.0) ---
AGENT_SOURCE: str = """\
'use strict';

rpc.exports = {
    enumerateRanges(prot) {
        return Process.enumerateRanges(prot);
    },
    readMemory(address, size) {
        return ptr(address).readByteArray(size);
    }
};
"""


# --- funciones de volcado ---
def dump_to_file(agent: object, base: str, size: int, out_dir: Path,
                 stats: dict[str, int]) -> None:
    if _shutdown_requested:
        return
    filepath: Path = out_dir / f"{base}_dump.data"
    try:
        data: Optional[bytes] = agent.read_memory(base, size)  # type: ignore[union-attr]
        if data is None:
            log("debug", "read_memory retornó None para %s (size=%d)", base, size)
            stats["errors"] += 1
            return
        filepath.write_bytes(data)
        stats["bytes"] += len(data)
        stats["files"] += 1
        log("debug", "Volcado: %s (%d bytes)", filepath.name, len(data))
    except Exception as exc:
        log("debug", "Error de acceso a memoria en %s: %s", base, exc)
        stats["errors"] += 1


def dump_region(agent: object, base: str, size: int, max_size: int,
                out_dir: Path, stats: dict[str, int]) -> None:
    if size <= max_size:
        dump_to_file(agent, base, size, out_dir, stats)
        return

    chunks: int = size // max_size
    remainder: int = size % max_size
    log("debug", "Región %s (%d bytes) → %d chunks",
              base, size, chunks + (1 if remainder else 0))

    cur_base: int = int(base, 16) if isinstance(base, str) else int(base)
    for _ in range(chunks):
        if _shutdown_requested:
            return
        dump_to_file(agent, hex(cur_base), max_size, out_dir, stats)
        cur_base += max_size

    if remainder and not _shutdown_requested:
        dump_to_file(agent, hex(cur_base), remainder, out_dir, stats)


# --- extracción de strings ---
def extract_strings(out_dir: Path, min_len: int = MIN_STRING_LEN) -> None:
    pattern: re.Pattern[bytes] = re.compile(
        rb"[\x20-\x7E]{%d,}" % min_len
    )
    strings_file: Path = out_dir / "strings.txt"
    dump_files: list[Path] = sorted(out_dir.glob("*_dump.data"))
    total: int = len(dump_files)

    if total == 0:
        log("warn", "No se encontraron archivos de volcado para extraer strings.")
        return

    log("step", "Extrayendo strings de %d archivos...", total)
    count: int = 0

    with open(strings_file, "w", encoding="utf-8", errors="replace") as sf:
        for idx, df in enumerate(dump_files, 1):
            if _shutdown_requested:
                break
            try:
                raw: bytes = df.read_bytes()
                for match in pattern.finditer(raw):
                    sf.write(match.group().decode("ascii", errors="replace")
                             + "\n")
                    count += 1
            except Exception as exc:
                log("debug", "Error leyendo %s: %s", df.name, exc)
            _progress(idx, total, prefix="Strings")

    log("success", "Strings extraídos: %d → %s", count, strings_file)


# --- normalización del proceso ---
def normalize_process(value: str) -> str | int:
    try:
        return int(value)
    except ValueError:
        return value


# --- conexión Frida ---
def get_session(process: str | int, usb: bool, host: Optional[str],
                spawn: bool) -> tuple:
    try:
        import frida  # type: ignore[import-untyped]
    except ImportError:
        log("error", "Paquete 'frida' no instalado. Ejecutar: pip install frida")
        sys.exit(EXIT_VALIDATION)

    frida_version: str = frida.__version__
    major: int = int(frida_version.split(".")[0])
    log("info", "Frida versión: %s", frida_version)

    if major < 17:
        log("warn", 
            "Script diseñado para Frida >= 17.0.0. Detectado: %s — "
            "pueden ocurrir errores.", frida_version
        )

    device = None
    try:
        if usb:
            log("info", "Conectando a dispositivo USB...")
            device = frida.get_usb_device(timeout=10)
        elif host:
            log("info", "Conectando a dispositivo remoto: %s", host)
            device = frida.get_device_manager().add_remote_device(host)
        else:
            log("info", "Conectando a proceso local...")
            device = frida.get_local_device()
    except Exception as exc:
        log("error", "No se pudo obtener el dispositivo: %s", exc)
        sys.exit(EXIT_NETWORK)

    log("info", "Dispositivo: %s (%s)", device.name, device.id)

    try:
        if spawn:
            if isinstance(process, int):
                log("error", "--spawn requiere nombre de paquete, no PID.")
                sys.exit(EXIT_USAGE)
            log("step", "Spawneando: %s", process)
            pid: int = device.spawn([process])
            session = device.attach(pid)
            device.resume(pid)
            log("info", "PID spawneado: %d", pid)
        else:
            log("step", "Adjuntando a: %s", process)
            session = device.attach(process)
    except Exception as exc:
        log("error", "No se pudo adjuntar a '%s': %s", process, exc)
        sys.exit(EXIT_NETWORK)

    return session, device


# --- validación de inputs ---
def validate_args(args: argparse.Namespace) -> None:
    if args.perms and args.read_only:
        log("error", "No combinar -p/--perms con -r/--read-only.")
        sys.exit(EXIT_USAGE)

    if args.read_only:
        args.perms = "r--"
    elif args.perms is None:
        args.perms = DEFAULT_PERMS

    if not re.match(r"^[r\-][w\-][x\-]$", args.perms):
        log("error", "Permisos inválidos: '%s'. Formato esperado: rwx|r--|rw-|etc.",
                  args.perms)
        sys.exit(EXIT_USAGE)

    if args.max_size <= 0:
        log("error", "--max-size debe ser > 0.")
        sys.exit(EXIT_USAGE)


# --- parsing de argumentos ---
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=SCRIPT_NAME,
        description=f"{SCRIPT_NAME} v{VERSION} — Volcado de memoria de "
                    "procesos vía Frida 17+. Reemplazo compatible de fridump3.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            f"  python3 {SCRIPT_NAME}.py com.app.target -U\n"
            f"  python3 {SCRIPT_NAME}.py 1234 -U -r -s\n"
            f"  python3 {SCRIPT_NAME}.py com.app.target -H 192.168.1.50\n"
            f"  python3 {SCRIPT_NAME}.py com.app.target -U --spawn --dry-run\n"
        ),
    )
    parser.add_argument("process", help="Nombre del proceso o PID a instrumentar")

    conn = parser.add_mutually_exclusive_group()
    conn.add_argument("-U", "--usb", action="store_true", help="Dispositivo conectado por USB")
    conn.add_argument("-H", "--host", type=str, default=None, metavar="HOST[:PORT]", help="Dispositivo conectado por IP (ej. 192.168.1.50)")

    parser.add_argument("-o", "--out", type=str, default=DEFAULT_OUT_DIR, metavar="DIR", help=f"Directorio de salida (def: {DEFAULT_OUT_DIR})")
    parser.add_argument("-p", "--perms", type=str, default=None, metavar="PERMS", help=f"Permisos a filtrar (def: {DEFAULT_PERMS})")
    parser.add_argument("-r", "--read-only", action="store_true", help="Volcar regiones de solo lectura (r--)")
    parser.add_argument("-s", "--strings", action="store_true", help="Extraer strings tras el volcado")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE, metavar="BYTES", help=f"Tamaño máximo por región (def: {DEFAULT_MAX_SIZE})")
    parser.add_argument("--spawn", action="store_true", help="Lanzar (spawn) el proceso en lugar de attach")
    parser.add_argument("--dry-run", action="store_true", help="Solo listar regiones, sin volcar a disco")

    log_grp = parser.add_argument_group("Logging")
    log_grp.add_argument("-v", "--verbose", action="store_true", help="Verbose: progreso + parámetros + métricas")
    log_grp.add_argument("-d", "--debug", action="store_true", help="Debug: verbose + trazas de ejecución")

    parser.add_argument("--version", action="version", version=f"{SCRIPT_NAME} {VERSION}")

    return parser

# --- banner ---
def _print_banner() -> None:
    title: str = f"{SCRIPT_NAME} v{VERSION} — Memory Dumper"
    width: int = 39
    padded: str = f"  {title}{' ' * (width - 2 - len(title))}"

    if _USE_COLOR:
        top = f"{_PURPLE}╔{'═' * width}╗{_RST}"
        mid = f"{_PURPLE}║{_RST}{padded}{_PURPLE}║{_RST}"
        bot = f"{_PURPLE}╚{'═' * width}╝{_RST}"
    else:
        top = f"╔{'═' * width}╗"
        mid = f"║{padded}║"
        bot = f"╚{'═' * width}╝"

    sys.stderr.write(f"{top}\n{mid}\n{bot}\n")


# --- cleanup de sesión ---
def _cleanup_session(script: object, session: object) -> None:
    try:
        script.unload()  # type: ignore[union-attr]
    except Exception:
        pass
    try:
        session.detach()  # type: ignore[union-attr]
    except Exception:
        pass


# --- dry-run: listado de regiones ---
def _print_regions(ranges: list[dict]) -> None:
    total_regions: int = len(ranges)
    total_mem: int = sum(r["size"] for r in ranges)

    log("ln")
    log("list", f"{'Base':>18s}  {'Tamaño':>12s}  {'Protección':>10s}")
    log("list", "-" * 44)
    for r in ranges:
        log("list", f"{r['base']:>18s}  {r['size']/1024:>9.1f} KB"
                 f"  {r['protection']:>10s}")
    log("ln")
    log("list", f"Total: {total_regions} regiones, "
             f"≈ {total_mem/(1024*1024):.2f} MiB")


# --- lógica principal ---
def main() -> int:
    parser: argparse.ArgumentParser = build_parser()
    args: argparse.Namespace = parser.parse_args()

    log_level: int = (logging.DEBUG if args.debug
                      else logging.INFO if args.verbose
                      else LOG_STEP)
    _setup_logging(log_level)
    validate_args(args)

    _print_banner()

    process: str | int = normalize_process(args.process)
    out_dir: Path = Path(args.out).resolve()
    perms: str = args.perms
    max_size: int = args.max_size

    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        log("info", "Directorio de salida: %s", out_dir)
    else:
        log("info", "Dry-run: no se escribirán archivos a disco.")

    session, _device = get_session(process, args.usb, args.host, args.spawn)

    def on_message(message: dict, data: Optional[bytes]) -> None:
        log("debug", "on_message: %s | data=%s", message, data)

    try:
        script = session.create_script(AGENT_SOURCE)
        script.on("message", on_message)
        script.load()
    except Exception as exc:
        log("error", "Error al cargar el script Frida: %s", exc)
        session.detach()
        return EXIT_UNEXPECTED

    agent = script.exports_sync

    log("info", "Enumerando regiones con permisos '%s'...", perms)
    try:
        ranges: list[dict] = agent.enumerate_ranges(perms)
    except Exception as exc:
        log("error", "Error enumerando rangos de memoria: %s", exc)
        _cleanup_session(script, session)
        return EXIT_UNEXPECTED

    total_regions: int = len(ranges)
    total_mem: int = sum(r["size"] for r in ranges)
    log("info", "Regiones encontradas: %d (≈ %.2f MiB)",
             total_regions, total_mem / (1024 * 1024))

    if total_regions == 0:
        log("warn", "Sin regiones con permisos '%s'.", perms)
        _cleanup_session(script, session)
        return EXIT_OK

    if args.dry_run:
        _print_regions(ranges)
        _cleanup_session(script, session)
        return EXIT_OK

    # volcado
    stats: dict[str, int] = {"bytes": 0, "files": 0, "errors": 0}
    t_start: float = time.monotonic()

    log("ln")
    log("step", "Volcando %d regiones de memoria...", total_regions)
    for idx, region in enumerate(ranges, 1):
        if _shutdown_requested:
            break
        dump_region(agent, region["base"], region["size"],
                    max_size, out_dir, stats)
        _progress(idx, total_regions)

    elapsed: float = time.monotonic() - t_start

    # resumen
    log("ln")
    if _shutdown_requested:
        log("warn", "Volcado interrumpido en %.1fs", elapsed)
    else:
        log("success", "Volcado completado en %.1fs", elapsed)

    log("list", f"Archivos: {stats['files']}  |  "
             f"Bytes: {stats['bytes']/(1024*1024):.2f} MiB  |  "
             f"Errores: {stats['errors']}")

    if args.strings and not _shutdown_requested:
        extract_strings(out_dir)

    _cleanup_session(script, session)
    return EXIT_SIGINT if _shutdown_requested else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
