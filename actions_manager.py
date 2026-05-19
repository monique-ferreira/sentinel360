"""
actions_manager.py — Operações sobre arquivos detectados pelo Sentinel360

Usado principalmente pela CLI (main.py).
"""

import os
import csv
from datetime import datetime


def export_to_csv(data: list[dict], filename: str = "relatorio_final_sentinel.csv") -> bool:
    """Exporta resultados para CSV com separador ponto-e-vírgula (Excel-friendly)."""
    if not data:
        return False
    fields = ["nome", "caminho", "inativo", "riscos", "tamanho_mb", "last_scan"]
    try:
        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fields, delimiter=";", extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)
        print(f"[CSV] Relatório exportado: {filename}")
        return True
    except OSError as e:
        print(f"[ERRO] Falha ao exportar CSV: {e}")
        return False


def delete_files(file_list: list[dict]) -> tuple[int, int]:
    """Remove fisicamente os arquivos da lista. Retorna (sucessos, erros)."""
    success = 0
    errors  = 0
    for item in file_list:
        path = item.get("caminho", "")
        try:
            os.remove(path)
            print(f"  [OK] Removido: {path}")
            success += 1
        except OSError as e:
            print(f"  [!] Falha ao remover {path}: {e}")
            errors += 1
    return success, errors


def summarize(data: list[dict]) -> dict:
    """Gera resumo estatístico dos resultados de scan."""
    total    = len(data)
    inativos = sum(1 for i in data if i.get("inativo") == "SIM")
    risky    = sum(1 for i in data if i.get("riscos") not in ("NENHUM", "", None))
    total_mb = sum(float(i.get("tamanho_mb", 0) or 0) for i in data)

    risk_types: dict[str, int] = {}
    for item in data:
        for r in (item.get("riscos") or "").split(","):
            r = r.strip()
            if r and r != "NENHUM":
                risk_types[r] = risk_types.get(r, 0) + 1

    return {
        "total":      total,
        "inativos":   inativos,
        "com_risco":  risky,
        "total_mb":   round(total_mb, 2),
        "risk_types": risk_types,
        "data_scan":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
