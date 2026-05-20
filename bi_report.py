"""
bi_report.py — Gerador de relatório BI HTML auto-contido para o Sentinel360.

Uso:
    html = bi_report.generate(local_items, cloud_items, scan_history)
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime


def _count_risks(items: list[dict]) -> dict[str, int]:
    counter: Counter = Counter()
    for item in items:
        for r in (item.get("riscos") or "").split(","):
            r = r.strip()
            if r and r not in ("NENHUM", ""):
                counter[r] += 1
    return dict(counter)


def _top_dirs(items: list[dict], n: int = 8) -> tuple[list[str], list[int]]:
    counter: Counter = Counter()
    for item in items:
        path = item.get("caminho", "")
        parts = path.replace("\\", "/").split("/")
        if len(parts) >= 2:
            counter["/".join(parts[:2])] += 1
        elif parts:
            counter[parts[0]] += 1
    top = counter.most_common(n)
    if not top:
        return [], []
    labels, values = zip(*top)
    return list(labels), list(values)


def generate(
    local_items: list[dict],
    cloud_items: list[dict],
    scan_history: list[dict],
) -> str:
    all_items   = local_items + cloud_items
    total       = len(all_items)
    inativos    = sum(1 for i in all_items if i.get("inativo") == "SIM")
    com_risco   = sum(1 for i in all_items if i.get("riscos") not in ("NENHUM", "", None))
    total_mb    = sum(float(i.get("tamanho_mb", 0) or 0) for i in all_items)
    local_count = len(local_items)
    cloud_count = len(cloud_items)

    risk_counts = _count_risks(all_items)
    risk_labels = json.dumps(list(risk_counts.keys()))
    risk_values = json.dumps(list(risk_counts.values()))

    dir_labels, dir_values = _top_dirs(all_items)
    dir_labels_js = json.dumps(dir_labels)
    dir_values_js = json.dumps(dir_values)

    # History chart (last 10 scans)
    hist = list(reversed(scan_history[:10]))
    hist_labels = json.dumps([h.get("data", "")[:10] for h in hist])
    hist_total  = json.dumps([h.get("total_arquivos", 0) for h in hist])
    hist_risco  = json.dumps([h.get("com_risco", 0) for h in hist])

    # Status/source pie
    source_labels = json.dumps(["Local", "SharePoint/OneDrive"])
    source_values = json.dumps([local_count, cloud_count])

    generated_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Sentinel360 — Relatório BI</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0d1117; color: #e6edf3; min-height: 100vh; padding: 32px 24px; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  header {{ display: flex; justify-content: space-between; align-items: flex-end;
    margin-bottom: 32px; padding-bottom: 20px; border-bottom: 1px solid rgba(240,246,252,.1); }}
  header h1 {{ font-size: 22px; font-weight: 700; letter-spacing: -.3px; }}
  header h1 span {{ color: #3fb950; }}
  header p {{ font-size: 12px; color: #8b949e; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 16px; margin-bottom: 28px; }}
  .kpi {{ background: #161b22; border: 1px solid rgba(240,246,252,.1);
    border-radius: 12px; padding: 20px; }}
  .kpi .label {{ font-size: 11px; color: #8b949e; text-transform: uppercase;
    letter-spacing: .6px; margin-bottom: 8px; }}
  .kpi .value {{ font-size: 32px; font-weight: 700; line-height: 1; }}
  .kpi .sub {{ font-size: 11px; color: #8b949e; margin-top: 6px; }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }}
  .charts.wide {{ grid-template-columns: 1fr; }}
  .chart-card {{ background: #161b22; border: 1px solid rgba(240,246,252,.1);
    border-radius: 12px; padding: 20px; }}
  .chart-title {{ font-size: 13px; font-weight: 600; margin-bottom: 16px; color: #c9d1d9; }}
  canvas {{ max-height: 280px; }}
  .table-card {{ background: #161b22; border: 1px solid rgba(240,246,252,.1);
    border-radius: 12px; overflow: hidden; margin-bottom: 28px; }}
  .table-card h3 {{ font-size: 13px; font-weight: 600; color: #c9d1d9;
    padding: 16px 20px; border-bottom: 1px solid rgba(240,246,252,.1); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ text-align: left; padding: 10px 16px; color: #8b949e; font-size: 11px;
    font-weight: 500; text-transform: uppercase; letter-spacing: .5px;
    background: rgba(255,255,255,.02); }}
  td {{ padding: 9px 16px; border-top: 1px solid rgba(240,246,252,.06); color: #c9d1d9; }}
  tr:hover td {{ background: rgba(255,255,255,.02); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 20px;
    font-size: 10px; font-weight: 600; }}
  .badge-risk {{ background: rgba(248,81,73,.12); color: #f85149; border: 1px solid rgba(248,81,73,.2); }}
  .badge-ok {{ background: rgba(63,185,80,.12); color: #3fb950; border: 1px solid rgba(63,185,80,.2); }}
  .badge-warn {{ background: rgba(210,153,34,.12); color: #d29922; border: 1px solid rgba(210,153,34,.2); }}
  footer {{ text-align: center; font-size: 11px; color: #484f58; padding-top: 16px;
    border-top: 1px solid rgba(240,246,252,.06); }}
  @media (max-width: 700px) {{ .charts {{ grid-template-columns: 1fr; }} }}
  @media print {{ body {{ background: #fff; color: #111; }}
    .chart-card, .table-card, .kpi {{ background: #f9f9f9; border-color: #ddd; }} }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1><span>Sentinel</span>360 — Relatório BI</h1>
      <p>Análise consolidada de arquivos locais e cloud</p>
    </div>
    <p>Gerado em {generated_at}</p>
  </header>

  <!-- KPIs -->
  <div class="kpi-grid">
    <div class="kpi">
      <div class="label">Total de itens</div>
      <div class="value" style="color:#58a6ff">{total:,}</div>
      <div class="sub">Local + Cloud</div>
    </div>
    <div class="kpi">
      <div class="label">Arquivos inativos</div>
      <div class="value" style="color:#d29922">{inativos:,}</div>
      <div class="sub">{round(inativos/total*100 if total else 0, 1)}% do total</div>
    </div>
    <div class="kpi">
      <div class="label">Com risco / sensíveis</div>
      <div class="value" style="color:#f85149">{com_risco:,}</div>
      <div class="sub">{round(com_risco/total*100 if total else 0, 1)}% do total</div>
    </div>
    <div class="kpi">
      <div class="label">Armazenamento total</div>
      <div class="value" style="color:#3fb950">{round(total_mb/1024, 2) if total_mb >= 1024 else round(total_mb, 1)}</div>
      <div class="sub">{'GB' if total_mb >= 1024 else 'MB'}</div>
    </div>
    <div class="kpi">
      <div class="label">Arquivos locais</div>
      <div class="value">{local_count:,}</div>
      <div class="sub">Sistema de arquivos</div>
    </div>
    <div class="kpi">
      <div class="label">Arquivos cloud</div>
      <div class="value">{cloud_count:,}</div>
      <div class="sub">SharePoint / OneDrive</div>
    </div>
  </div>

  <!-- Charts row 1 -->
  <div class="charts">
    <div class="chart-card">
      <div class="chart-title">Categorias de Risco</div>
      <canvas id="riskPie"></canvas>
    </div>
    <div class="chart-card">
      <div class="chart-title">Origem dos Arquivos</div>
      <canvas id="sourcePie"></canvas>
    </div>
  </div>

  <!-- Top dirs bar -->
  <div class="charts wide">
    <div class="chart-card">
      <div class="chart-title">Top Diretórios / Locais com mais achados</div>
      <canvas id="dirBar"></canvas>
    </div>
  </div>

  <!-- History line -->
  <div class="charts wide">
    <div class="chart-card">
      <div class="chart-title">Histórico de Scans</div>
      <canvas id="histLine"></canvas>
    </div>
  </div>

  <!-- High-risk table -->
  <div class="table-card">
    <h3>Itens de Alto Risco (top 50)</h3>
    <table>
      <thead><tr>
        <th>Nome</th><th>Origem</th><th>Riscos</th><th>Inativo</th><th>Tamanho</th>
      </tr></thead>
      <tbody>
        {"".join(
            f'<tr>'
            f'<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{item.get("caminho","")}">{item.get("nome","")}</td>'
            f'<td style="color:#8b949e;font-size:11px">{item.get("origem", item.get("caminho",""))[:50]}</td>'
            f'<td><span class="badge badge-risk">{item.get("riscos","")[:60]}</span></td>'
            f'<td><span class="badge {"badge-warn" if item.get("inativo")=="SIM" else "badge-ok"}">'
            f'{"SIM" if item.get("inativo")=="SIM" else "NÃO"}</span></td>'
            f'<td style="color:#8b949e">{item.get("tamanho_mb","0")} MB</td>'
            f'</tr>'
            for item in sorted(
                [i for i in all_items if i.get("riscos") not in ("NENHUM","",None)],
                key=lambda x: x.get("dias_sem_acesso", 0), reverse=True
            )[:50]
        ) or '<tr><td colspan="5" style="text-align:center;color:#484f58;padding:24px">Nenhum item de risco encontrado.</td></tr>'}
      </tbody>
    </table>
  </div>

  <!-- Scan history table -->
  <div class="table-card">
    <h3>Histórico de Varreduras</h3>
    <table>
      <thead><tr>
        <th>Data / Hora</th><th>Tipo</th><th>Arquivos analisados</th><th>Com risco</th><th>Inativos</th>
      </tr></thead>
      <tbody>
        {"".join(
            f'<tr>'
            f'<td>{h.get("data","—")}</td>'
            f'<td><span class="badge" style="background:rgba(88,166,255,.1);color:#58a6ff;border:1px solid rgba(88,166,255,.2)">{h.get("tipo","—")}</span></td>'
            f'<td>{h.get("total_arquivos",0):,}</td>'
            f'<td><span style="color:#f85149">{h.get("com_risco",0):,}</span></td>'
            f'<td><span style="color:#d29922">{h.get("inativos",0):,}</span></td>'
            f'</tr>'
            for h in scan_history[:20]
        ) or '<tr><td colspan="5" style="text-align:center;color:#484f58;padding:24px">Nenhum histórico de scan encontrado.</td></tr>'}
      </tbody>
    </table>
  </div>

  <footer>Sentinel360 Cyber Defense Platform &nbsp;·&nbsp; Relatório gerado automaticamente em {generated_at}</footer>
</div>

<script>
const COLORS = ['#3fb950','#58a6ff','#f85149','#d29922','#bc8cff','#79c0ff','#ffa657','#ff7b72'];
const gridColor = 'rgba(240,246,252,0.06)';
const tickColor = '#8b949e';
const font = {{ family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", size: 11 }};

Chart.defaults.color = tickColor;
Chart.defaults.font  = font;

new Chart(document.getElementById('riskPie'), {{
  type: 'doughnut',
  data: {{ labels: {risk_labels}, datasets: [{{ data: {risk_values},
    backgroundColor: COLORS, borderColor: '#161b22', borderWidth: 2, hoverOffset: 6 }}] }},
  options: {{ plugins: {{ legend: {{ position: 'right', labels: {{ font, boxWidth: 12, padding: 14 }} }} }},
    cutout: '62%', maintainAspectRatio: true }},
}});

new Chart(document.getElementById('sourcePie'), {{
  type: 'doughnut',
  data: {{ labels: {source_labels}, datasets: [{{ data: {source_values},
    backgroundColor: ['#58a6ff','#bc8cff'], borderColor: '#161b22', borderWidth: 2 }}] }},
  options: {{ plugins: {{ legend: {{ position: 'right', labels: {{ font, boxWidth: 12, padding: 14 }} }} }},
    cutout: '62%', maintainAspectRatio: true }},
}});

new Chart(document.getElementById('dirBar'), {{
  type: 'bar',
  data: {{ labels: {dir_labels_js}, datasets: [{{ label: 'Arquivos encontrados', data: {dir_values_js},
    backgroundColor: '#3fb95066', borderColor: '#3fb950', borderWidth: 1, borderRadius: 4 }}] }},
  options: {{ indexAxis: 'y', plugins: {{ legend: {{ display: false }} }},
    scales: {{ x: {{ grid: {{ color: gridColor }}, ticks: {{ color: tickColor }} }},
               y: {{ grid: {{ color: 'transparent' }}, ticks: {{ color: tickColor, font: {{ size: 10 }} }} }} }},
    maintainAspectRatio: false }},
}});
document.getElementById('dirBar').style.maxHeight = '300px';

new Chart(document.getElementById('histLine'), {{
  type: 'line',
  data: {{ labels: {hist_labels}, datasets: [
    {{ label: 'Total', data: {hist_total}, borderColor: '#58a6ff', backgroundColor: '#58a6ff18',
      fill: true, tension: .35, pointRadius: 4 }},
    {{ label: 'Com risco', data: {hist_risco}, borderColor: '#f85149', backgroundColor: '#f8514920',
      fill: true, tension: .35, pointRadius: 4 }},
  ] }},
  options: {{ plugins: {{ legend: {{ labels: {{ font, boxWidth: 12 }} }} }},
    scales: {{ x: {{ grid: {{ color: gridColor }}, ticks: {{ color: tickColor }} }},
               y: {{ grid: {{ color: gridColor }}, ticks: {{ color: tickColor }} }} }},
    maintainAspectRatio: false }},
}});
document.getElementById('histLine').style.maxHeight = '240px';
</script>
</body>
</html>"""
