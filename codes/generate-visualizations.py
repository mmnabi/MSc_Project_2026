#!/usr/bin/env python3
"""
Generate Visualizations (Story 4.5)

Produces ATT&CK Navigator JSON layers (one per method, one overlay) and
bar charts for tactic-level coverage comparison. All outputs are thesis-ready.

ATT&CK Navigator layers:
    The Navigator (https://mitre-attack.github.io/attack-navigator/) uses a
    JSON layer format. Each layer contains technique entries with scores and
    colors. The overlay layer uses color to distinguish agreement/divergence.

Usage:
    python generate-visualizations.py --input data/coding/reconciled-final.csv --output-dir visualizations
    python generate-visualizations.py --input data/coding/reconciled-final.csv --dry-run
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("Error: 'pandas' package required. Install with: pip install pandas")
    sys.exit(1)

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend for file output
except ImportError:
    print("Error: 'matplotlib' package required. Install with: pip install matplotlib")
    sys.exit(1)

try:
    import seaborn as sns
except ImportError:
    sns = None
    print("Warning: 'seaborn' not available. Using matplotlib defaults.")

# Navigator layer template
NAVIGATOR_VERSION = "4.9"
ATTCK_VERSION = "15"

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Colors for overlay layer
COLOR_BOTH = "#31a354"      # Green: identified by both methods
COLOR_TRAD_ONLY = "#3182bd" # Blue: traditional only
COLOR_LLM_ONLY = "#e6550d"  # Orange: LLM only
COLOR_NEITHER = "#ffffff"   # White: not identified


def build_navigator_layer(
    name: str,
    description: str,
    df: pd.DataFrame,
    match_column: str,
    color: str = "#ff6666",
) -> dict:
    """
    Build an ATT&CK Navigator layer JSON for a single method.

    Techniques with match=1 get score=1 and the specified color.
    Techniques with match=0 get score=0 and white/transparent.
    """
    techniques = []
    for _, row in df.iterrows():
        match = int(row.get(match_column, 0))
        entry = {
            "techniqueID": row["technique_id"],
            "tactic": row["tactic"],
            "score": match,
            "color": color if match == 1 else "",
            "comment": "",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
        }
        techniques.append(entry)

    layer = {
        "name": name,
        "versions": {
            "attack": ATTCK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "SaaS", "IaaS", "Network"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True, "showAggregateScores": False, "countUnscored": False},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", color], "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "Identified", "color": color},
            {"label": "Not identified", "color": "#ffffff"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }

    return layer


def build_overlay_layer(df: pd.DataFrame) -> dict:
    """
    Build an overlay Navigator layer showing agreement/divergence between
    traditional and LLM-structured methods.
    """
    techniques = []
    for _, row in df.iterrows():
        trad = int(row.get("traditional_match", 0))
        llm = int(row.get("llm_structured_match", 0))

        if trad == 1 and llm == 1:
            color = COLOR_BOTH
            score = 3
        elif trad == 1 and llm == 0:
            color = COLOR_TRAD_ONLY
            score = 2
        elif trad == 0 and llm == 1:
            color = COLOR_LLM_ONLY
            score = 1
        else:
            color = COLOR_NEITHER
            score = 0

        entry = {
            "techniqueID": row["technique_id"],
            "tactic": row["tactic"],
            "score": score,
            "color": color,
            "comment": "",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
        }
        techniques.append(entry)

    layer = {
        "name": "Overlay: Traditional vs LLM-Structured",
        "versions": {
            "attack": ATTCK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": "Comparison overlay showing agreement and divergence between traditional (ISO 27005) and LLM-structured threat identification methods.",
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "SaaS", "IaaS", "Network"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True, "showAggregateScores": False, "countUnscored": False},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": [COLOR_NEITHER, COLOR_BOTH], "minValue": 0, "maxValue": 3},
        "legendItems": [
            {"label": "Both methods", "color": COLOR_BOTH},
            {"label": "Traditional only", "color": COLOR_TRAD_ONLY},
            {"label": "LLM-Structured only", "color": COLOR_LLM_ONLY},
            {"label": "Neither method", "color": COLOR_NEITHER},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }

    return layer


def generate_tactic_bar_chart(df: pd.DataFrame, output_path: str, methods_info: dict):
    """Generate a grouped bar chart comparing tactic-level coverage across methods.

    methods_info: dict mapping column_name -> (label, color)
    """
    methods = {col: label for col, (label, color) in methods_info.items()}
    colors_list = [color for col, (label, color) in methods_info.items()]

    tactic_data = []
    for tactic in TACTIC_ORDER:
        t_df = df[df["tactic"] == tactic]
        total = len(t_df)
        if total == 0:
            continue
        for col, label in methods.items():
            count = t_df[col].sum() if col in t_df.columns else 0
            pct = 100 * count / total
            tactic_data.append({"tactic": tactic, "method": label, "coverage_pct": pct})

    plot_df = pd.DataFrame(tactic_data)

    if sns:
        sns.set_theme(style="whitegrid")

    n_methods = len(methods)
    fig, ax = plt.subplots(figsize=(max(14, n_methods * 3), 7))

    tactics = [t for t in TACTIC_ORDER if t in plot_df["tactic"].values]
    x_pos = range(len(tactics))
    width = 0.8 / n_methods  # Divide available space among methods

    for i, ((col, label), color) in enumerate(zip(methods.items(), colors_list)):
        method_data = plot_df[plot_df["method"] == label]
        values = [
            method_data[method_data["tactic"] == t]["coverage_pct"].iloc[0]
            if len(method_data[method_data["tactic"] == t]) > 0
            else 0
            for t in tactics
        ]
        ax.bar([x + i * width for x in x_pos], values, width, label=label, color=color)

    ax.set_xlabel("ATT&CK Tactic", fontsize=12)
    ax.set_ylabel("Coverage (%)", fontsize=12)
    ax.set_title("Threat Identification Coverage by ATT&CK Tactic", fontsize=14)
    ax.set_xticks([x + width * (n_methods - 1) / 2 for x in x_pos])
    ax.set_xticklabels([t.replace("-", "\n") for t in tactics], rotation=45, ha="right", fontsize=9)
    ax.legend(fontsize=9, loc="upper right")
    ax.set_ylim(0, 105)
    ax.axhline(y=50, color="gray", linestyle="--", alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Bar chart saved: {output_path}")


def generate_prompt_sensitivity_chart(output_path: str, sensitivity_csv: str):
    """
    Generate a horizontal diverging bar chart showing per-tactic gains and
    losses when moving from the baseline to the structured LLM prompt.

    Gains extend rightward (orange), losses extend leftward (blue-gray).
    Tactics are ordered by ATT&CK lifecycle from top to bottom.
    """
    sens_df = pd.read_csv(sensitivity_csv)

    # Ensure lifecycle ordering (reversed so top of chart = first tactic)
    tactic_order_reversed = list(reversed(TACTIC_ORDER))
    sens_df["tactic"] = pd.Categorical(
        sens_df["tactic"], categories=tactic_order_reversed, ordered=True
    )
    sens_df = sens_df.sort_values("tactic")

    if sns:
        sns.set_theme(style="whitegrid")

    fig, ax = plt.subplots(figsize=(9, 7))

    y_pos = range(len(sens_df))
    tactic_labels = [
        t.replace("-", " ").title() for t in sens_df["tactic"]
    ]

    # Losses (leftward, negative) -- blue-gray
    losses = [-v for v in sens_df["lost"]]
    ax.barh(
        y_pos, losses, height=0.6,
        color="#6baed6", edgecolor="#4292c6", linewidth=0.5,
        label="Lost", zorder=3,
    )

    # Gains (rightward, positive) -- orange
    gains = list(sens_df["gained"])
    ax.barh(
        y_pos, gains, height=0.6,
        color="#e6550d", edgecolor="#a63603", linewidth=0.5,
        label="Gained", zorder=3,
    )

    # Annotate bar tips with net values
    for i, (g, l, net) in enumerate(
        zip(sens_df["gained"], sens_df["lost"], sens_df["net_change"])
    ):
        if net > 0:
            ax.text(g + 0.15, i, f"+{net}", va="center", ha="left", fontsize=9, fontweight="bold")
        elif net < 0:
            ax.text(-l - 0.15, i, f"{net}", va="center", ha="right", fontsize=9, fontweight="bold")
        else:
            # Zero net change -- annotate at right edge
            ax.text(max(g, 0.3) + 0.15, i, "0", va="center", ha="left", fontsize=9, color="gray")

    # Zero line
    ax.axvline(x=0, color="black", linewidth=0.8, zorder=4)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(tactic_labels, fontsize=10)
    ax.set_xlabel("Techniques", fontsize=11)
    ax.set_title(
        "Prompt Sensitivity: Techniques Gained and Lost\n(Baseline -> Structured)",
        fontsize=13,
    )

    # Symmetric x-axis
    max_val = max(max(gains), max([-v for v in losses]) if any(losses) else 0)
    ax.set_xlim(-max_val - 1.5, max_val + 1.5)

    # Summary annotation
    total_gained = sum(gains)
    total_lost = sum(sens_df["lost"])
    total_net = total_gained - total_lost
    ax.text(
        0.98, 0.02,
        f"Total: +{total_gained} gained, -{total_lost} lost, net +{total_net}",
        transform=ax.transAxes, ha="right", va="bottom",
        fontsize=9, fontstyle="italic",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="wheat", alpha=0.5),
    )

    ax.legend(loc="lower left", fontsize=9)
    ax.grid(axis="x", alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Prompt sensitivity chart saved: {output_path}")


def generate_upset_plot(df: pd.DataFrame, output_path: str, methods_info: dict):
    """
    Generate an UpSet-style plot showing intersection regions across all
    active methods. Uses unique technique_ids (not rows) to avoid
    double-counting techniques that appear in multiple tactics.

    methods_info: dict mapping column_name -> (label, color)
    """
    from itertools import product as iter_product

    method_cols = list(methods_info.keys())
    method_labels = [label for label, _ in methods_info.values()]
    n_methods = len(method_cols)

    # Short labels for display
    SHORT_LABELS = {
        "traditional_match": "Trad",
        "llm_baseline_match": "Base",
        "llm_structured_match": "Claude",
        "gemini_structured_match": "Gemini",
        "openai_structured_match": "GPT-4o",
    }
    short_names = [SHORT_LABELS.get(col, col.replace("_match", "")) for col in method_cols]

    # Compute per-technique membership (max across tactic rows)
    agg_dict = {col: (col, "max") for col in method_cols}
    tech_membership = df.groupby("technique_id").agg(**agg_dict).reset_index()

    # Programmatically generate all 2^N - 1 non-empty intersections
    all_combos = list(iter_product([0, 1], repeat=n_methods))
    all_combos = [c for c in all_combos if sum(c) > 0]  # Exclude all-zero

    # Color palette for different intersection sizes
    COMBO_COLORS = {
        1: ["#3182bd", "#fdae6b", "#e6550d", "#2ca02c", "#9467bd"],  # Singles
        2: "#9ecae1",   # Pairs
        3: "#756bb1",   # Triples
        4: "#fd8d3c",   # Quads
        5: "#31a354",   # All five
    }

    counts = []
    for combo in all_combos:
        n_active = sum(combo)
        mask = True
        for i, val in enumerate(combo):
            mask = mask & (tech_membership[method_cols[i]] == val)
        count = mask.sum()
        if count == 0:
            continue

        # Label: join active method short names
        active_names = [short_names[i] for i, v in enumerate(combo) if v == 1]
        label = " + ".join(active_names) if n_active < n_methods else "All"

        # Color
        if n_active == 1:
            idx = [i for i, v in enumerate(combo) if v == 1][0]
            color = methods_info[method_cols[idx]][1]
        elif n_active == n_methods:
            color = "#31a354"
        else:
            color = COMBO_COLORS.get(n_active, "#888888")

        counts.append((label, count, combo, color))

    counts.sort(key=lambda x: -x[1])

    n_cols = len(counts)
    labels = [c[0] for c in counts]
    values = [c[1] for c in counts]
    memberships = [c[2] for c in counts]
    colors = [c[3] for c in counts]

    if sns:
        sns.set_theme(style="whitegrid")

    fig = plt.figure(figsize=(max(10, n_cols * 1.0), max(6.5, n_methods * 0.8 + 4)))
    gs = fig.add_gridspec(
        2, 1, height_ratios=[3, max(1, n_methods * 0.4)], hspace=0.05,
    )
    ax_bars = fig.add_subplot(gs[0])
    ax_dots = fig.add_subplot(gs[1])

    x_pos = range(n_cols)

    # Top panel: bar chart
    ax_bars.bar(x_pos, values, color=colors, edgecolor="white", linewidth=0.8, zorder=3)
    for i, v in enumerate(values):
        ax_bars.text(i, v + 0.5, str(v), ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax_bars.set_ylabel("Technique Count", fontsize=11)
    ax_bars.set_title("Method Overlap: Technique Set Intersections", fontsize=13)
    ax_bars.set_xticks([])
    ax_bars.set_xlim(-0.6, n_cols - 0.4)
    ax_bars.set_ylim(0, max(values) + 5)
    ax_bars.grid(axis="y", alpha=0.3)

    # Bottom panel: dot matrix
    for row_idx in range(n_methods):
        for col_idx in x_pos:
            member = memberships[col_idx][row_idx]
            dot_color = "#333333" if member else "#d9d9d9"
            size = 120 if member else 60
            ax_dots.scatter(col_idx, row_idx, s=size, c=dot_color, zorder=4)

    # Connect filled dots vertically
    for col_idx in x_pos:
        active = [i for i in range(n_methods) if memberships[col_idx][i] == 1]
        if len(active) > 1:
            ax_dots.plot(
                [col_idx, col_idx], [min(active), max(active)],
                color="#333333", linewidth=2, zorder=3,
            )

    ax_dots.set_yticks(range(n_methods))
    ax_dots.set_yticklabels(short_names, fontsize=10)
    ax_dots.set_xticks([])
    ax_dots.set_xlim(-0.6, n_cols - 0.4)
    ax_dots.set_ylim(-0.5, n_methods - 0.5)
    ax_dots.invert_yaxis()
    ax_dots.grid(False)
    ax_dots.set_facecolor("white")

    for spine in ax_dots.spines.values():
        spine.set_visible(False)
    for y in [i + 0.5 for i in range(n_methods - 1)]:
        ax_dots.axhline(y=y, color="#e0e0e0", linewidth=0.5)

    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  UpSet plot saved: {output_path}")


def generate_radar_chart(output_path: str, coverage_csv: str):
    """
    Generate a radar (spider) chart showing per-tactic coverage profiles
    for all three methods, with 14 axes in ATT&CK lifecycle order.
    """
    import numpy as np

    cov_df = pd.read_csv(coverage_csv)
    # Filter out OVERALL rows
    cov_df = cov_df[cov_df["tactic"] != "OVERALL"]

    # Auto-detect method names from the coverage CSV
    ALL_METHOD_COLORS = {
        "Traditional": "#3182bd",
        "LLM Base (Claude)": "#fdae6b",
        "LLM Struct (Claude)": "#e6550d",
        "LLM Struct (Gemini)": "#2ca02c",
        "LLM Struct (GPT-4o)": "#9467bd",
        # Legacy labels (backward compat)
        "LLM Baseline": "#fdae6b",
        "LLM Structured": "#e6550d",
    }
    LINE_STYLES = ["-", "-", "-", "--", "-."]

    available_methods = sorted(cov_df["method"].unique())
    methods = {}
    for m in available_methods:
        methods[m] = ALL_METHOD_COLORS.get(m, "#888888")

    # Short tactic labels for readability
    tactic_labels = {
        "reconnaissance": "Recon",
        "resource-development": "Resource\nDev",
        "initial-access": "Initial\nAccess",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "Priv\nEscalation",
        "defense-evasion": "Defense\nEvasion",
        "credential-access": "Credential\nAccess",
        "discovery": "Discovery",
        "lateral-movement": "Lateral\nMovement",
        "collection": "Collection",
        "command-and-control": "C2",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }

    n_tactics = len(TACTIC_ORDER)
    # Compute angles for each tactic
    angles = np.linspace(0, 2 * np.pi, n_tactics, endpoint=False).tolist()
    angles += angles[:1]  # Close the polygon

    if sns:
        sns.set_theme(style="white")

    fig, ax = plt.subplots(figsize=(9, 9), subplot_kw=dict(polar=True))

    for idx, (method_name, color) in enumerate(methods.items()):
        values = []
        for tactic in TACTIC_ORDER:
            row = cov_df[
                (cov_df["tactic"] == tactic) & (cov_df["method"] == method_name)
            ]
            if len(row) > 0:
                values.append(row["coverage_pct"].iloc[0])
            else:
                values.append(0)
        values += values[:1]  # Close polygon

        ls = LINE_STYLES[idx % len(LINE_STYLES)]
        ax.plot(angles, values, marker="o", linewidth=2, markersize=4, color=color,
                linestyle=ls, label=method_name)
        ax.fill(angles, values, alpha=0.08, color=color)

    # Configure axes
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(
        [tactic_labels.get(t, t) for t in TACTIC_ORDER],
        fontsize=9,
    )

    # Radial gridlines
    ax.set_yticks([20, 40, 60, 80])
    ax.set_yticklabels(["20%", "40%", "60%", "80%"], fontsize=8, color="gray")
    ax.set_ylim(0, 100)

    ax.set_title(
        "Per-Tactic Coverage Profiles by Method",
        fontsize=13, pad=25,
    )
    ax.legend(loc="upper right", bbox_to_anchor=(1.25, 1.1), fontsize=10)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Radar chart saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate ATT&CK Navigator layers and comparison charts."
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to reconciled coding CSV.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="visualizations",
        help="Output directory for visualization files.",
    )
    parser.add_argument(
        "--sensitivity-csv",
        type=str,
        default=None,
        help="Path to prompt-sensitivity.csv (for prompt sensitivity chart).",
    )
    parser.add_argument(
        "--coverage-csv",
        type=str,
        default=None,
        help="Path to coverage-ratios.csv (for radar chart).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate and display summary without writing files.",
    )
    args = parser.parse_args()

    # Load data
    path = Path(args.input)
    if not path.exists():
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    df = pd.read_csv(args.input)

    # All possible method columns and metadata
    ALL_METHODS = {
        "traditional_match":        ("Traditional",              "#3182bd"),
        "llm_baseline_match":       ("LLM Baseline (Claude)",    "#fdae6b"),
        "llm_structured_match":     ("LLM Structured (Claude)",  "#e6550d"),
        "gemini_structured_match":  ("LLM Structured (Gemini)",  "#2ca02c"),
        "openai_structured_match":  ("LLM Structured (GPT-4o)",  "#9467bd"),
    }

    # Detect which columns are present
    active_methods = {}
    for col, (label, color) in ALL_METHODS.items():
        if col in df.columns:
            df[col] = df[col].fillna(0).astype(int)
            active_methods[col] = (label, color)

    print(f"Loaded: {args.input} ({len(df)} rows)")
    print(f"Active methods: {', '.join(label for label, _ in active_methods.values())}")

    output_dir = Path(args.output_dir)
    figures_dir = output_dir / "figures"

    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        figures_dir.mkdir(parents=True, exist_ok=True)

    # Generate Navigator layers dynamically from active methods
    LAYER_FILENAMES = {
        "traditional_match": "heatmap-traditional.json",
        "llm_baseline_match": "heatmap-llm-baseline.json",
        "llm_structured_match": "heatmap-llm-structured.json",
        "gemini_structured_match": "heatmap-gemini-structured.json",
        "openai_structured_match": "heatmap-openai-structured.json",
    }

    layers = []
    for column, (label, color) in active_methods.items():
        filename = LAYER_FILENAMES.get(column, f"heatmap-{column.replace('_match', '')}.json")
        desc = f"Techniques identified via {label} threat identification."
        layers.append((filename, label, desc, column, color))

    print("\nGenerating ATT&CK Navigator layers...")
    for filename, name, description, column, color in layers:
        layer = build_navigator_layer(name, description, df, column, color)
        tech_count = sum(1 for t in layer["techniques"] if t["score"] == 1)
        print(f"  {filename}: {tech_count} techniques highlighted")

        if not args.dry_run:
            filepath = output_dir / filename
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(layer, f, indent=2)

    # Overlay layer
    print("\nGenerating overlay layer...")
    overlay = build_overlay_layer(df)
    both = sum(1 for t in overlay["techniques"] if t["score"] == 3)
    trad_only = sum(1 for t in overlay["techniques"] if t["score"] == 2)
    llm_only = sum(1 for t in overlay["techniques"] if t["score"] == 1)
    print(f"  Both: {both}, Traditional-only: {trad_only}, LLM-only: {llm_only}")

    if not args.dry_run:
        filepath = output_dir / "heatmap-overlay.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(overlay, f, indent=2)

    # Generate bar chart
    print("\nGenerating tactic coverage bar chart...")
    chart_path = str(figures_dir / "tactic-coverage-comparison.png")
    if args.dry_run:
        print(f"  [DRY RUN] Would save chart to: {chart_path}")
    else:
        generate_tactic_bar_chart(df, chart_path, active_methods)

    # Generate prompt sensitivity diverging bar chart (Figure 6)
    sensitivity_csv = args.sensitivity_csv
    if sensitivity_csv is None:
        # Auto-detect from default location relative to input
        default_sens = Path(args.input).parent.parent / "analysis" / "prompt-sensitivity.csv"
        if default_sens.exists():
            sensitivity_csv = str(default_sens)

    if sensitivity_csv and Path(sensitivity_csv).exists():
        print("\nGenerating prompt sensitivity chart...")
        sens_path = str(figures_dir / "prompt-sensitivity.png")
        if args.dry_run:
            print(f"  [DRY RUN] Would save chart to: {sens_path}")
        else:
            generate_prompt_sensitivity_chart(sens_path, sensitivity_csv)
    else:
        print("\nSkipping prompt sensitivity chart (CSV not found).")

    # Generate UpSet plot for method overlap (Figure 7)
    print("\nGenerating UpSet plot for method overlap...")
    upset_path = str(figures_dir / "method-overlap-upset.png")
    if args.dry_run:
        print(f"  [DRY RUN] Would save chart to: {upset_path}")
    else:
        generate_upset_plot(df, upset_path, active_methods)

    # Generate radar chart for coverage profiles (Figure 8)
    coverage_csv = args.coverage_csv
    if coverage_csv is None:
        default_cov = Path(args.input).parent.parent / "analysis" / "coverage-ratios.csv"
        if default_cov.exists():
            coverage_csv = str(default_cov)

    if coverage_csv and Path(coverage_csv).exists():
        print("\nGenerating radar chart for coverage profiles...")
        radar_path = str(figures_dir / "coverage-radar.png")
        if args.dry_run:
            print(f"  [DRY RUN] Would save chart to: {radar_path}")
        else:
            generate_radar_chart(radar_path, coverage_csv)
    else:
        print("\nSkipping radar chart (coverage CSV not found).")

    if args.dry_run:
        print(f"\n[DRY RUN] No files written.")
    else:
        print(f"\nAll visualizations written to: {args.output_dir}")


if __name__ == "__main__":
    main()
