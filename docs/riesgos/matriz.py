"""Genera la matriz 5x5 (inherente vs residual) como PNG."""
import sys
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Patch
from riesgos import RIESGOS, nivel

# Paleta de estado (good / warning / serious / critical) aclarada al 35% para el fondo
STATUS = {"Bajo": "#0ca30c", "Medio": "#fab219", "Alto": "#ec835a", "Crítico": "#d03b3b"}
INK, MUTED, GRID = "#0b0b0b", "#5f5e58", "#ffffff"

def tint(hexc, a=0.32):
    r, g, b = (int(hexc[i:i + 2], 16) for i in (1, 3, 5))
    return tuple((a * c + (1 - a) * 255) / 255 for c in (r, g, b))

def panel(ax, title, pos):
    cells = defaultdict(list)
    for r in RIESGOS:
        p, i = (r[3], r[4]) if pos == 0 else (r[6], r[7])
        cells[(p, i)].append(r[0])
    for p in range(1, 6):
        for i in range(1, 6):
            lv = nivel(p, i)
            ax.add_patch(FancyBboxPatch((i - 0.5 + 0.03, p - 0.5 + 0.03), 0.94, 0.94,
                         boxstyle="round,pad=0,rounding_size=0.06", fc=tint(STATUS[lv]), ec=GRID, lw=2))
            ax.text(i + 0.4, p - 0.4, str(p * i), ha="right", va="bottom", fontsize=8, color=MUTED)
            ids = cells.get((p, i), [])
            for k, rid in enumerate(ids):
                row, col = divmod(k, 3)
                n_cols = min(3, len(ids))
                x = i + (col - (n_cols - 1) / 2) * 0.3
                y = p + 0.2 - row * 0.3
                ax.text(x, y, rid, ha="center", va="center", fontsize=8, fontweight="bold", color=INK,
                        bbox=dict(boxstyle="round,pad=0.25", fc="white", ec=STATUS[nivel(p, i)], lw=1.4))
    ax.set_xlim(0.5, 5.5); ax.set_ylim(0.5, 5.5); ax.set_aspect("equal")
    ax.set_xticks(range(1, 6), ["1\nInsignif.", "2\nMenor", "3\nModerado", "4\nMayor", "5\nCatastróf."], fontsize=8.5, color=INK)
    ax.set_yticks(range(1, 6), ["1 Rara", "2 Improbable", "3 Posible", "4 Probable", "5 Casi segura"], fontsize=8.5, color=INK)
    ax.set_xlabel("Impacto", fontsize=10, color=INK); ax.set_ylabel("Probabilidad", fontsize=10, color=INK)
    ax.set_title(title, fontsize=12, fontweight="bold", color=INK, loc="left")
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)

fig, axes = plt.subplots(1, 2, figsize=(13, 6.4), dpi=170)
panel(axes[0], "Riesgo inherente (sin controles)", 0)
panel(axes[1], "Riesgo residual (con mitigaciones)", 1)
fig.legend(handles=[Patch(fc=tint(c), ec=c, label=f"{k}  ({rng})") for (k, c), rng in
                    zip(STATUS.items(), ["1–4", "5–9", "10–16", "20–25"])],
           loc="lower center", ncol=4, frameon=False, fontsize=10, title="Nivel = probabilidad × impacto", title_fontsize=10)
fig.tight_layout(rect=(0, 0.08, 1, 0.97))
fig.savefig(sys.argv[1] if len(sys.argv) > 1 else "matriz-riesgos.png", facecolor="white")
