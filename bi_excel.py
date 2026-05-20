"""
bi_excel.py — Gera relatório BI como arquivo Excel (.xlsx) para o Sentinel360.

O .xlsx pode ser aberto diretamente no Power BI Desktop via "Obter Dados > Excel".
Uso:
    workbook_bytes = bi_excel.generate(cloud_items, scan_history)
"""

from __future__ import annotations

import io
from datetime import datetime

import openpyxl
from openpyxl.styles import (
    Font, PatternFill, Alignment, Border, Side, GradientFill
)
from openpyxl.utils import get_column_letter
from openpyxl.chart import BarChart, PieChart, LineChart, Reference
from openpyxl.chart.series import DataPoint
from collections import Counter


# ── Paleta ────────────────────────────────────────────────────────────────────

DARK_BG   = "0D1117"
HEADER_BG = "161B22"
ACCENT    = "3FB950"   # verde sentinel
BLUE      = "58A6FF"
RED       = "F85149"
YELLOW    = "D29922"
PURPLE    = "BC8CFF"
TEXT_MAIN = "E6EDF3"
TEXT_MUTED= "8B949E"


def _fill(hex_color: str) -> PatternFill:
    return PatternFill("solid", fgColor=hex_color)


def _font(bold=False, color=TEXT_MAIN, size=10) -> Font:
    return Font(name="Segoe UI", bold=bold, color=color, size=size)


def _border() -> Border:
    side = Side(style="thin", color="30363D")
    return Border(left=side, right=side, top=side, bottom=side)


def _header_row(ws, row: int, values: list[str], bg: str = HEADER_BG, fg: str = TEXT_MUTED):
    for col, val in enumerate(values, 1):
        c = ws.cell(row=row, column=col, value=val)
        c.fill  = _fill(bg)
        c.font  = _font(bold=True, color=fg, size=9)
        c.alignment = Alignment(horizontal="left", vertical="center")
        c.border = _border()


def _data_row(ws, row: int, values: list, alt: bool = False):
    bg = "161B22" if not alt else "0D1117"
    for col, val in enumerate(values, 1):
        c = ws.cell(row=row, column=col, value=val)
        c.fill  = _fill(bg)
        c.font  = _font()
        c.alignment = Alignment(horizontal="left", vertical="center", wrap_text=False)
        c.border = _border()


def _set_col_widths(ws, widths: list[int]):
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


def _title_row(ws, row: int, title: str, span: int):
    ws.cell(row=row, column=1, value=title).font = _font(bold=True, color=ACCENT, size=12)
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=span)


def generate(cloud_items: list[dict], scan_history: list[dict]) -> bytes:
    wb = openpyxl.Workbook()
    generated_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # ── Sheet 1: Resumo / KPIs ────────────────────────────────────────────────
    ws_kpi = wb.active
    ws_kpi.title = "Resumo"
    ws_kpi.sheet_properties.tabColor = ACCENT

    _set_col_widths(ws_kpi, [28, 20, 20, 20, 20, 20])

    ws_kpi["A1"] = "SENTINEL360 — RELATÓRIO BI"
    ws_kpi["A1"].font = _font(bold=True, color=ACCENT, size=14)
    ws_kpi["A2"] = f"Gerado em: {generated_at}"
    ws_kpi["A2"].font = _font(color=TEXT_MUTED, size=9)

    total     = len(cloud_items)
    inativos  = sum(1 for i in cloud_items if i.get("inativo") == "SIM")
    com_risco = sum(1 for i in cloud_items if i.get("riscos") not in ("NENHUM", "", None))
    total_mb  = sum(float(i.get("tamanho_mb", 0) or 0) for i in cloud_items)

    kpi_data = [
        ("Total de arquivos",       total,             BLUE),
        ("Arquivos inativos",       inativos,          YELLOW),
        ("Com risco / sensíveis",   com_risco,         RED),
        ("Armazenamento total (MB)", round(total_mb, 2), ACCENT),
    ]

    for col, (label, value, color) in enumerate(kpi_data, 1):
        lc = ws_kpi.cell(row=4, column=col, value=label)
        lc.fill  = _fill(HEADER_BG)
        lc.font  = _font(color=TEXT_MUTED, size=9)
        lc.alignment = Alignment(horizontal="center")
        lc.border = _border()

        vc = ws_kpi.cell(row=5, column=col, value=value)
        vc.fill  = _fill(DARK_BG)
        vc.font  = Font(name="Segoe UI", bold=True, color=color, size=18)
        vc.alignment = Alignment(horizontal="center", vertical="center")
        vc.border = _border()
        ws_kpi.row_dimensions[5].height = 36

    # Risk breakdown
    risk_counter: Counter = Counter()
    for item in cloud_items:
        for r in (item.get("riscos") or "").split(","):
            r = r.strip()
            if r and r not in ("NENHUM", ""):
                risk_counter[r] += 1

    ws_kpi.cell(row=7, column=1, value="Categoria de Risco").font = _font(bold=True, color=ACCENT)
    ws_kpi.cell(row=7, column=2, value="Quantidade").font = _font(bold=True, color=ACCENT)
    for i, (label, count) in enumerate(risk_counter.most_common(), 1):
        ws_kpi.cell(row=7 + i, column=1, value=label).font = _font()
        ws_kpi.cell(row=7 + i, column=2, value=count).font = _font()

    # ── Sheet 2: Todos os arquivos ────────────────────────────────────────────
    ws_files = wb.create_sheet("Arquivos")
    ws_files.sheet_properties.tabColor = BLUE
    _set_col_widths(ws_files, [35, 50, 20, 25, 12, 20, 18])

    _title_row(ws_files, 1, "Resultados de Varredura", 7)
    _header_row(ws_files, 2, ["Nome", "Caminho / URL", "Origem", "Riscos", "Inativo", "Tamanho (MB)", "Último Scan"])

    for i, item in enumerate(cloud_items):
        _data_row(ws_files, i + 3, [
            item.get("nome", ""),
            item.get("caminho", ""),
            item.get("origem", ""),
            item.get("riscos", "NENHUM"),
            item.get("inativo", "NÃO"),
            item.get("tamanho_mb", 0),
            item.get("last_scan", ""),
        ], alt=i % 2 == 1)

        # Color-code risk cells
        risk_cell = ws_files.cell(row=i + 3, column=4)
        if item.get("riscos") not in ("NENHUM", "", None):
            risk_cell.font = _font(color=RED)
        inactive_cell = ws_files.cell(row=i + 3, column=5)
        if item.get("inativo") == "SIM":
            inactive_cell.font = _font(color=YELLOW)

    # ── Sheet 3: Arquivos de risco ────────────────────────────────────────────
    ws_risk = wb.create_sheet("Risco")
    ws_risk.sheet_properties.tabColor = RED
    _set_col_widths(ws_risk, [35, 50, 20, 25, 12, 18])

    risky = [i for i in cloud_items if i.get("riscos") not in ("NENHUM", "", None)]
    _title_row(ws_risk, 1, f"Arquivos de Alto Risco ({len(risky)} itens)", 6)
    _header_row(ws_risk, 2, ["Nome", "Caminho / URL", "Origem", "Riscos", "Inativo", "Último Scan"])

    for i, item in enumerate(risky):
        _data_row(ws_risk, i + 3, [
            item.get("nome", ""),
            item.get("caminho", ""),
            item.get("origem", ""),
            item.get("riscos", ""),
            item.get("inativo", ""),
            item.get("last_scan", ""),
        ], alt=i % 2 == 1)
        ws_risk.cell(row=i + 3, column=4).font = _font(color=RED, bold=True)
        if item.get("inativo") == "SIM":
            ws_risk.cell(row=i + 3, column=5).font = _font(color=YELLOW)

    # ── Sheet 4: Histórico de scans ───────────────────────────────────────────
    ws_hist = wb.create_sheet("Histórico")
    ws_hist.sheet_properties.tabColor = PURPLE
    _set_col_widths(ws_hist, [22, 20, 20, 14, 14])

    _title_row(ws_hist, 1, "Histórico de Varreduras", 5)
    _header_row(ws_hist, 2, ["Data / Hora", "Tipo", "Arquivos Analisados", "Com Risco", "Inativos"])

    for i, h in enumerate(scan_history[:50]):
        _data_row(ws_hist, i + 3, [
            h.get("data", ""),
            h.get("tipo", ""),
            h.get("total_arquivos", 0),
            h.get("com_risco", 0),
            h.get("inativos", 0),
        ], alt=i % 2 == 1)
        if h.get("com_risco", 0) > 0:
            ws_hist.cell(row=i + 3, column=4).font = _font(color=RED)
        if h.get("inativos", 0) > 0:
            ws_hist.cell(row=i + 3, column=5).font = _font(color=YELLOW)

    # ── Sheet 5: Gráficos ─────────────────────────────────────────────────────
    ws_charts = wb.create_sheet("Gráficos")
    ws_charts.sheet_properties.tabColor = ACCENT

    # Populate data for charts (hidden helper columns)
    # Risk breakdown data (cols G-H from row 2)
    risk_list = list(risk_counter.most_common(8))
    if risk_list:
        ws_charts["G1"] = "Categoria"
        ws_charts["H1"] = "Qtd"
        for r_i, (label, count) in enumerate(risk_list, 2):
            ws_charts[f"G{r_i}"] = label
            ws_charts[f"H{r_i}"] = count

        pie = PieChart()
        pie.title = "Categorias de Risco"
        pie.style = 10
        pie.width  = 14
        pie.height = 10
        data_ref   = Reference(ws_charts, min_col=8, min_row=1, max_row=len(risk_list) + 1)
        labels_ref = Reference(ws_charts, min_col=7, min_row=2, max_row=len(risk_list) + 1)
        pie.add_data(data_ref, titles_from_data=True)
        pie.set_categories(labels_ref)
        ws_charts.add_chart(pie, "A1")

    # History bar chart (cols J-L from row 2)
    hist_slice = list(reversed(scan_history[:10]))
    if hist_slice:
        ws_charts["J1"] = "Data"
        ws_charts["K1"] = "Total"
        ws_charts["L1"] = "Com Risco"
        for h_i, hh in enumerate(hist_slice, 2):
            ws_charts[f"J{h_i}"] = hh.get("data", "")[:10]
            ws_charts[f"K{h_i}"] = hh.get("total_arquivos", 0)
            ws_charts[f"L{h_i}"] = hh.get("com_risco", 0)

        bar = BarChart()
        bar.type    = "col"
        bar.title   = "Histórico de Scans"
        bar.y_axis.title = "Arquivos"
        bar.x_axis.title = "Data"
        bar.style   = 10
        bar.width   = 18
        bar.height  = 10
        data_ref    = Reference(ws_charts, min_col=11, max_col=12, min_row=1, max_row=len(hist_slice) + 1)
        cats_ref    = Reference(ws_charts, min_col=10, min_row=2, max_row=len(hist_slice) + 1)
        bar.add_data(data_ref, titles_from_data=True)
        bar.set_categories(cats_ref)
        ws_charts.add_chart(bar, "A20")

    # Hide helper columns
    for col in ["G", "H", "I", "J", "K", "L"]:
        ws_charts.column_dimensions[col].hidden = True

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
