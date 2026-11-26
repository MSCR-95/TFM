#!/usr/bin/env python3
"""Descarga la última versión de las cuatro fuentes de datos.

Uso:
    python3 bajar_fuentes.py [carpeta]        # por defecto ./fuentes

Resultado en la carpeta:
    top-pypi-packages.min.json   ranking de proyectos (último mes publicado)
    osv-PyPI.zip                 vulnerabilidades de PyPI
    epss-current.csv.gz          probabilidad de explotación por CVE
    kev.json                     catálogo de vulnerabilidades explotadas
    manifiesto.json              URL, fecha de descarga y tamaño de cada fichero

Cada fichero se escribe primero con un nombre temporal y se renombra al terminar, así que una 
interrupción no deja un fichero a medias con el nombre bueno.

FUENTES
=======

1. Top PyPI Packages (hugovk/top-pypi-packages)
   Qué ofrece: los 15.000 proyectos de PyPI más descargados en los últimos 30 días, ordenados de más a
   menos. Es el MARCO del que se eligen los proyectos. Las descargas incluyen CI, cachés y espejos:
   ordenan, pero no miden uso real. Se actualiza una vez al mes.
   Formato: un JSON.
       {
         "last_update": "2026-05-01 06:34:08",
         "source": "ClickHouse",
         "total_rows": 15000,
         "rows": [ {"project": "boto3", "download_count": 2672873026}, ... ],
         "meta": [...], "statistics": {...}, "rows_before_limit_at_least": 814190
       }
   De cada proyecto solo da el nombre y las descargas: versiones, fechas, dependencias y repositorio
   hay que pedírselos a la API JSON de PyPI.

2. OSV, ecosistema PyPI (Open Source Vulnerabilities, Google)
   Qué ofrece: los avisos de seguridad que afectan a paquetes de PyPI, con las versiones afectadas y las
   que los corrigen. Se usa para saber qué dependencias instaladas son vulnerables y qué versiones
   posteriores arreglan cada aviso, es decir, de dónde salen las acciones. Cambia a diario.
   Formato: un ZIP plano (sin subcarpetas) con un JSON por aviso, llamado <id>.json, en el esquema OSV
   (https://ossf.github.io/osv-schema/). Siempre presentes: "schema_version", "id", "published",
   "modified", "details" y "affected"; el resto es opcional.
       {
         "schema_version": "1.x.x",
         "id": "PYSEC-..." | "GHSA-..." | "MAL-..." | "OSV-...",
         "aliases": ["CVE-2024-xxxxx", "PYSEC-...", ...],   # opcional; el CVE, si existe, viene aquí
         "related": [...],                                    # opcional
         "published": "...", "modified": "...",
         "withdrawn": "...",                                  # opcional: aviso retirado
         "summary": "...",                                    # opcional
         "details": "...",
         "severity": [...], "references": [...], "credits": [...], "database_specific": {...},  # opcionales
         "affected": [
           {
             "package": {"ecosystem": "PyPI", "name": "urllib3", "purl": "pkg:pypi/urllib3"},
             "ranges": [                                      # opcional
               {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.2"}]},
               {"type": "GIT", "repo": "https://github.com/...", "events": [{"introduced": "<commit>"}, ...]}
             ],
             "versions": ["1.0", "1.1", ...],                 # opcional: lista explícita de versiones afectadas
             "database_specific": {...},
             "ecosystem_specific": {...}                      # opcional
           }
         ]
       }
   La afectación de una versión de PyPI se decide por la lista "versions" o por los rangos de tipo
   "ECOSYSTEM" (eventos "introduced", "fixed", "last_affected").
   Lo que hay en el fichero además de vulnerabilidades de PyPI:
     - Prefijos de "id": PYSEC, GHSA, MAL, OSV. Los MAL-… (45 %) son paquetes
       maliciosos publicados en PyPI, no vulnerabilidades de un paquete legítimo: no se corrigen actualizando.
     ...
3. EPSS (Exploit Prediction Scoring System, FIRST)
   Qué ofrece: para cada CVE, la probabilidad estimada de que se observe actividad de explotación en los
   próximos 30 días. Es el PESO de cada vulnerabilidad en el problema (EPSS x 1000). No mide impacto
   económico ni demuestra que exista un exploit (https://www.first.org/epss/faq). Cambia a diario.
   Formato: CSV comprimido con gzip. La primera línea es un comentario con la versión del modelo y la fecha
   de puntuación; después, cabecera y una fila por CVE, sin CVE repetidos:
       #model_version:v2026.06.15,score_date:2026-11-22T12:03:04Z
       cve,epss,percentile
       CVE-1999-0001,0.04753,0.92097
   "epss" está entre 0 y 1; "percentile" es su posición frente a todos los CVE (411.249 en la descarga
   del 2026-11-23).
   Ojo: EPSS se indexa por CVE, mientras que OSV usa sus propios identificadores; el CVE de un aviso OSV
   está en "aliases". Un aviso sin CVE no tiene EPSS.

4. KEV (Known Exploited Vulnerabilities, CISA)
   Qué ofrece: las vulnerabilidades con explotación confirmada. En el problema son OBLIGATORIAS: si un CVE
   está en KEV, la cartera tiene que corregirlo con alguna de sus acciones (regla "politica_kev").
   Cambia cuando CISA añade entradas, varias veces por semana.
   Formato: un JSON; "count" coincide con el número de entradas. Todas las entradas tienen los 12 campos.
   
       {
         "title": "...", "catalogVersion": "2026.11.20", "dateReleased": "2026-11-20T17:48:39.1516Z",
         "count": 1790,
         "vulnerabilities": [
           {"cveID": "CVE-2021-44228", "vendorProject": "...", "product": "...",
            "vulnerabilityName": "...", "dateAdded": "2021-12-10", "dueDate": "...",
            "requiredAction": "...", "knownRansomwareCampaignUse": "Known" | "Unknown",
            "forensicTriage": "Yes" | ...,
            "shortDescription": "...", "notes": "...", "cwes": ["CWE-502", ...]}
         ]
       }
   KEV cubre productos de todo tipo (Apache, Microsoft, Cisco...): solo importan los CVE que aparecen en
   avisos OSV de paquetes de PyPI.
"""

import gzip
import json
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

AGENTE = "descarga-fuentes/1.0"  # User-Agent genérico: no identifica a nadie

FUENTES = {
    "top-pypi-packages.min.json": "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json",
    "osv-PyPI.zip": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "epss-current.csv.gz": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "kev.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}


def descargar(url: str, fichero: Path) -> int:
    """Descarga a un fichero temporal y lo renombra solo si termina bien. Devuelve el tamaño en bytes."""
    temporal = fichero.with_name(fichero.name + ".parcial")
    total = 0
    peticion = urllib.request.Request(url, headers={"User-Agent": AGENTE})
    with urllib.request.urlopen(peticion, timeout=120) as respuesta, temporal.open("wb") as salida:
        if respuesta.status != 200:
            raise RuntimeError(f"{url}: el servidor respondió {respuesta.status}")
        while bloque := respuesta.read(1 << 20):
            salida.write(bloque)
            total += len(bloque)
    temporal.replace(fichero)
    return total


# Resúmenes: abren cada fichero para comprobar que tiene el formato esperado.

def resumen_ranking(fichero: Path) -> str:
    datos = json.loads(fichero.read_text())
    primero = datos["rows"][0]
    return (f"{len(datos['rows'])} proyectos, actualizado {datos['last_update']} ({datos['source']}); "
            f"primero: {primero['project']} con {primero['download_count']:,} descargas")


def resumen_osv(fichero: Path) -> str:
    with zipfile.ZipFile(fichero) as zip_:
        avisos = [n for n in zip_.namelist() if n.endswith(".json")]
        ejemplo = json.loads(zip_.read(avisos[0]))
    return f"{len(avisos)} avisos; ejemplo: {ejemplo['id']} (alias: {', '.join(ejemplo.get('aliases', [])) or 'ninguno'})"


def resumen_epss(fichero: Path) -> str:
    with gzip.open(fichero, "rt") as texto:
        comentario = texto.readline().strip()
        cabecera = texto.readline().strip()
        filas = sum(1 for _ in texto)
    return f"{filas} CVE; columnas: {cabecera}; {comentario.lstrip('#')}"


def resumen_kev(fichero: Path) -> str:
    datos = json.loads(fichero.read_text())
    return f"{len(datos['vulnerabilities'])} vulnerabilidades, catálogo {datos['catalogVersion']}"


RESUMENES = {
    "top-pypi-packages.min.json": resumen_ranking,
    "osv-PyPI.zip": resumen_osv,
    "epss-current.csv.gz": resumen_epss,
    "kev.json": resumen_kev,
}


def main() -> int:
    destino = Path(sys.argv[1] if len(sys.argv) > 1 else "fuentes")
    destino.mkdir(parents=True, exist_ok=True)
    manifiesto, errores = {}, 0

    for nombre, url in FUENTES.items():
        fichero = destino / nombre
        print(f"\n[{nombre}] {url}")
        try:
            tamano = descargar(url, fichero)
        except Exception as error:  # una fuente que falla no impide intentar las demás
            print(f"  ERROR al descargar: {error}", file=sys.stderr)
            errores += 1
            continue

        manifiesto[nombre] = {
            "url": url,
            "descargado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "bytes": tamano,
        }
        print(f"  {tamano:,} bytes")
        try:
            print(f"  {RESUMENES[nombre](fichero)}")
        except Exception as error:
            print(f"  AVISO: no tiene el formato esperado: {error}", file=sys.stderr)
            errores += 1

    (destino / "manifiesto.json").write_text(json.dumps(manifiesto, indent=2, ensure_ascii=False) + "\n")
    print(f"\nManifiesto en {destino / 'manifiesto.json'}; {len(manifiesto)} de {len(FUENTES)} fuentes descargadas.")
    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())
