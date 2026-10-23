import os
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

# Output directory for poster assets
OUT_DIR = r"c:\wamp64\www\soc-chess\poster_assets"
os.makedirs(OUT_DIR, exist_ok=True)

# Set high-res font and style settings
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#333333'
plt.rcParams['axes.linewidth'] = 1.2
plt.rcParams['font.size'] = 11

# Load metrics.json
with open(r"c:\wamp64\www\soc-chess\ml\models\network\metrics.json", "r") as f:
    metrics = json.load(f)

# -------------------------------------------------------------
# GRAPH 1: Model Performance Comparison Bar Chart
# -------------------------------------------------------------
def generate_model_comparison():
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    
    models = ['Network RF\n(Batch Champion)', 'Network XGBoost\n(Secondary)', '3-Layer MLP\n(Real-Time Stream)', 'Security Log RF\n(Splunk Model)']
    accuracies = [99.39, 99.37, 98.20, 91.86]
    f1_scores = [99.39, 99.37, 98.10, 91.03]
    roc_aucs = [99.91, 99.88, 99.20, 95.40]
    
    x = np.arange(len(models))
    width = 0.25
    
    rects1 = ax.bar(x - width, accuracies, width, label='Accuracy (%)', color='#2b5c8f', edgecolor='black', linewidth=0.8)
    rects2 = ax.bar(x, f1_scores, width, label='Weighted F1 (%)', color='#2a9d8f', edgecolor='black', linewidth=0.8)
    rects3 = ax.bar(x + width, roc_aucs, width, label='ROC-AUC (%)', color='#e76f51', edgecolor='black', linewidth=0.8)
    
    ax.set_ylabel('Score (%)', fontsize=12, fontweight='bold')
    ax.set_title('Figure 1: Benchmark Comparison Across Detection Engines', fontsize=14, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=10, fontweight='bold')
    ax.set_ylim(85, 103)
    ax.legend(loc='lower right', frameon=True, facecolor='#f8f9fa', edgecolor='#cccccc', fontsize=10)
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.2f}%',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=8, fontweight='bold')
            
    autolabel(rects1)
    autolabel(rects2)
    autolabel(rects3)
    
    plt.tight_layout()
    out_path = os.path.join(OUT_DIR, "fig1_model_comparison.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[OK] Saved {out_path}")

# -------------------------------------------------------------
# GRAPH 2: Neural Network Loss Convergence Curve
# -------------------------------------------------------------
def generate_loss_curve():
    loss_curve = metrics["loss_curve"]
    epochs = list(range(1, len(loss_curve) + 1))
    
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
    ax.plot(epochs, loss_curve, marker='o', markersize=4, color='#1d3557', linewidth=2.2, label='Training Loss (Cross-Entropy)')
    
    ax.set_title('Figure 2: 3-Layer MLP Neural Network Loss Convergence', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Epochs / Optimization Iterations (Adam Optimizer)', fontsize=11, fontweight='bold')
    ax.set_ylabel('Loss Value', fontsize=11, fontweight='bold')
    ax.grid(True, linestyle='--', alpha=0.6)
    
    # Highlight final convergence
    final_loss = loss_curve[-1]
    ax.annotate(f'Converged Loss: {final_loss:.4f}\n(24 Iterations, 27.1s)',
                xy=(epochs[-1], final_loss), xytext=(epochs[-6], final_loss + 0.08),
                arrowprops=dict(facecolor='#e63946', shrink=0.08, width=1.5, headwidth=6),
                bbox=dict(boxstyle="round,pad=0.4", fc="#fff3b0", ec="#e63946", lw=1.2),
                fontsize=9, fontweight='bold')
    
    ax.legend(loc='upper right', frameon=True, facecolor='#f8f9fa')
    plt.tight_layout()
    out_path = os.path.join(OUT_DIR, "fig2_neural_loss_curve.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[OK] Saved {out_path}")

# -------------------------------------------------------------
# GRAPH 3: Feature Importance Bar Chart
# -------------------------------------------------------------
def generate_feature_importance():
    raw_feats = metrics["feature_importance"]
    # Filter features with non-zero importance and sort top 10
    active_feats = [f for f in raw_feats if f["percentage"] > 0]
    active_feats.sort(key=lambda x: x["percentage"], reverse=True)
    top_10 = active_feats[:10]
    
    names = [f["feature"] for f in top_10]
    scores = [f["percentage"] for f in top_10]
    
    # Reverse for horizontal chart display
    names.reverse()
    scores.reverse()
    
    fig, ax = plt.subplots(figsize=(8, 5.2), dpi=300)
    bars = ax.barh(names, scores, color='#457b9d', edgecolor='black', linewidth=0.8, height=0.65)
    
    ax.set_xlabel('Relative Importance Score (%)', fontsize=11, fontweight='bold')
    ax.set_title('Figure 3: Top 10 Canonical Features in Network Threat Detection', fontsize=13, fontweight='bold', pad=15)
    ax.grid(axis='x', linestyle='--', alpha=0.5)
    
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.3, bar.get_y() + bar.get_height()/2, f'{w:.2f}%',
                ha='left', va='center', fontsize=9, fontweight='bold', color='#1d3557')
        
    ax.set_xlim(0, max(scores) + 3)
    plt.tight_layout()
    out_path = os.path.join(OUT_DIR, "fig3_feature_importance.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[OK] Saved {out_path}")

# -------------------------------------------------------------
# GRAPH 4: Multi-Class Confusion Matrix Heatmap
# -------------------------------------------------------------
def generate_confusion_matrix():
    cm = np.array(metrics["confusion_matrix"])
    classes = metrics["classes"]
    
    # Filter classes that have actual samples in test set
    active_indices = [i for i in range(len(classes)) if cm[i].sum() > 0 or cm[:, i].sum() > 0]
    filtered_cm = cm[np.ix_(active_indices, active_indices)]
    filtered_classes = [classes[i] for i in active_indices]
    
    fig, ax = plt.subplots(figsize=(7.5, 6), dpi=300)
    
    # Log scale normalization for visual clarity since counts range from 1 to 7458
    norm_cm = np.log1p(filtered_cm)
    cax = ax.matshow(norm_cm, cmap=plt.cm.Blues, alpha=0.85)
    
    # Add colorbar
    cbar = fig.colorbar(cax, shrink=0.8)
    cbar.set_label('Log1p(Event Count)', rotation=270, labelpad=15, fontweight='bold')
    
    for i in range(filtered_cm.shape[0]):
        for j in range(filtered_cm.shape[1]):
            val = filtered_cm[i, j]
            color = "white" if norm_cm[i, j] > norm_cm.max() / 2 else "black"
            ax.text(j, i, f"{val:,}", ha='center', va='center', color=color, fontweight='bold', fontsize=10)
            
    ax.set_xticks(range(len(filtered_classes)))
    ax.set_yticks(range(len(filtered_classes)))
    ax.set_xticklabels(filtered_classes, rotation=35, ha='left', fontweight='bold')
    ax.set_yticklabels(filtered_classes, fontweight='bold')
    
    ax.set_xlabel('Predicted Attack Class', fontsize=11, fontweight='bold', labelpad=10)
    ax.set_ylabel('True Attack Class (Ground Truth)', fontsize=11, fontweight='bold')
    ax.set_title('Figure 4: Confusion Matrix (Real-Time Test Evaluation)', fontsize=13, fontweight='bold', pad=25)
    
    plt.tight_layout()
    out_path = os.path.join(OUT_DIR, "fig4_confusion_matrix.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[OK] Saved {out_path}")

# -------------------------------------------------------------
# GRAPH 5: System Block Architecture Infographic
# -------------------------------------------------------------
def generate_architecture_diagram():
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=300)
    ax.axis('off')
    
    # Define blocks
    boxes = [
        {"x": 0.05, "y": 0.65, "w": 0.25, "h": 0.25, "title": "1. Telemetry Ingestion", "desc": "• Wireshark / TShark (Live)\n• Splunk REST API (:8089)\n• 12 Raw Log Parsers", "color": "#dbeafe", "ec": "#1e40af"},
        {"x": 0.38, "y": 0.65, "w": 0.25, "h": 0.25, "title": "2. Big Data Streaming", "desc": "• Apache Spark 3.5.3\n• 19 Canonical Features\n• Log1p & StandardScaler", "color": "#dcfce7", "ec": "#166534"},
        {"x": 0.71, "y": 0.65, "w": 0.25, "h": 0.25, "title": "3. Dual-Tier ML Engine", "desc": "• Tier 1: 3-Layer MLP (<1.2ms)\n• Tier 2: Random Forest\n• 99.39% Detection Accuracy", "color": "#fef3c7", "ec": "#92400e"},
        {"x": 0.18, "y": 0.15, "w": 0.30, "h": 0.28, "title": "4. Risk & SOAR Engine", "desc": "• Normalized Risk (0-100)\n• MITRE ATT&CK Tagger\n• Auto Firewall Containment\n  (iptables / Windows netsh)", "color": "#fee2e2", "ec": "#991b1b"},
        {"x": 0.58, "y": 0.15, "w": 0.30, "h": 0.28, "title": "5. Presentation & Reports", "desc": "• React 18 + TS Glassmorphic UI\n• Real-Time WebSocket Feeds\n• Multi-Format Forensic Export\n  (PDF, DOC, CSV, TXT, JSON)", "color": "#f3e8ff", "ec": "#6b21a8"}
    ]
    
    for b in boxes:
        rect = plt.Rectangle((b["x"], b["y"]), b["w"], b["h"], facecolor=b["color"], edgecolor=b["ec"], linewidth=2, linestyle='solid', transform=ax.transAxes, zorder=2, clip_on=False)
        ax.add_patch(rect)
        ax.text(b["x"] + b["w"]/2, b["y"] + b["h"] - 0.05, b["title"], ha='center', va='top', fontsize=11, fontweight='bold', color=b["ec"], transform=ax.transAxes, zorder=3)
        ax.text(b["x"] + 0.02, b["y"] + b["h"] - 0.09, b["desc"], ha='left', va='top', fontsize=9, color='#1f2937', transform=ax.transAxes, zorder=3, linespacing=1.3)
        
    # Draw interconnecting arrows
    arrow_props = dict(facecolor='#475569', edgecolor='#334155', width=2.5, headwidth=8, headlength=7, shrink=0.08)
    
    # 1 -> 2
    ax.annotate('', xy=(0.38, 0.77), xytext=(0.30, 0.77), textcoords=ax.transAxes, xycoords=ax.transAxes, arrowprops=arrow_props)
    # 2 -> 3
    ax.annotate('', xy=(0.71, 0.77), xytext=(0.63, 0.77), textcoords=ax.transAxes, xycoords=ax.transAxes, arrowprops=arrow_props)
    # 3 -> 4
    ax.annotate('', xy=(0.48, 0.35), xytext=(0.75, 0.65), textcoords=ax.transAxes, xycoords=ax.transAxes, arrowprops=arrow_props)
    # 4 -> 5
    ax.annotate('', xy=(0.58, 0.29), xytext=(0.48, 0.29), textcoords=ax.transAxes, xycoords=ax.transAxes, arrowprops=arrow_props)
    
    ax.set_title('Figure 5: SOC CHESS High-Level End-to-End System Architecture', fontsize=14, fontweight='bold', pad=15)
    plt.tight_layout()
    out_path = os.path.join(OUT_DIR, "fig5_system_architecture.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"[OK] Saved {out_path}")

if __name__ == "__main__":
    generate_model_comparison()
    generate_loss_curve()
    generate_feature_importance()
    generate_confusion_matrix()
    generate_architecture_diagram()
    print("\n[SUCCESS] All poster figures successfully generated in 300 DPI!")
