#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import argparse
import os
import glob
from matplotlib.backends.backend_pdf import PdfPages

# Parse command line arguments
parser = argparse.ArgumentParser(description='Generate performance comparison plots from benchmark results')
parser.add_argument('--input', '-i', default='.',
                    help='Path to the directory containing test result files (default: current directory)')
parser.add_argument('--output', '-o', default='performance_comparison.pdf',
                    help='Path to save the output PDF (default: performance_comparison.pdf)')
args = parser.parse_args()

# Check if input directory exists
if not os.path.exists(args.input):
    print(f"Error: Input directory '{args.input}' not found")
    exit(1)

if not os.path.isdir(args.input):
    print(f"Error: Input path '{args.input}' is not a directory")
    exit(1)

# Find all test result files
pattern = os.path.join(args.input, "test_results_*.csv")
result_files = glob.glob(pattern)

if not result_files:
    print(f"Error: No files matching 'test_results_*.csv' found in '{args.input}'")
    exit(1)

# Sort files for consistent ordering
result_files.sort()

print(f"Found {len(result_files)} test result files:")
for file in result_files:
    print(f"  - {os.path.basename(file)}")

def get_title_from_filename(filepath):
    """Extract title from filename by removing 'test_results_' prefix and '.csv' suffix"""
    filename = os.path.basename(filepath)
    if filename.startswith('test_results_'):
        title = filename[13:]  # Remove 'test_results_' prefix
        if title.endswith('.csv'):
            title = title[:-4]  # Remove '.csv' suffix
        return title
    return filename

def create_performance_table(ax, baseline_data, ig_data):
    """Create a formatted table with performance metrics"""
    rps_values = baseline_data['rps'].values
    baseline_cpu = baseline_data['%cpu'].values
    ig_cpu = ig_data['%cpu'].values
    baseline_cpu_ci = baseline_data['cpu_ci'].values
    ig_cpu_ci = ig_data['cpu_ci'].values
    baseline_mem = baseline_data['mem(MB)'].values
    ig_mem = ig_data['mem(MB)'].values
    baseline_mem_ci = baseline_data['mem_ci'].values
    ig_mem_ci = ig_data['mem_ci'].values
    ig_lost = ig_data['lost'].values

    # Get IG process specific data
    ig_process_cpu = ig_data['ig_cpu_mean'].values
    ig_process_cpu_ci = ig_data['ig_cpu_ci'].values
    ig_process_mem = ig_data['ig_mem_mean'].values
    ig_process_mem_ci = ig_data['ig_mem_ci'].values

    # Prepare table data
    table_data = []

    # Header row
    table_data.append(['RPS', 'Total CPU (avg)', 'Confidence Interval', 'Overhead (%)', 'IG Process CPU', 'CI', 'Total Mem (avg)', 'CI', 'Overhead (MB)', 'IG Process Mem', 'CI', 'Lost Events'])

    # Data rows for each RPS configuration
    for i, rps in enumerate(rps_values):
        cpu_overhead_pct = ((ig_cpu[i] - baseline_cpu[i]) / baseline_cpu[i]) * 100
        mem_overhead_mb = ig_mem[i] - baseline_mem[i]

        table_data.append([
            f'{rps}',
            f'{ig_cpu[i]:.2f}%',
            f'±{ig_cpu_ci[i]:.2f}%',
            f'{cpu_overhead_pct:.1f}%',
            f'{ig_process_cpu[i]:.2f}%',
            f'±{ig_process_cpu_ci[i]:.2f}%',
            f'{ig_mem[i]:.0f}MB',
            f'±{ig_mem_ci[i]:.0f}MB',
            f'{mem_overhead_mb:.0f}MB',
            f'{ig_process_mem[i]:.0f}MB',
            f'±{ig_process_mem_ci[i]:.0f}MB',
            f'{int(ig_lost[i])}'
        ])

    # Average row
    avg_ig_cpu = np.mean(ig_cpu)
    avg_ig_cpu_ci = np.mean(ig_cpu_ci)
    avg_cpu_overhead_pct = np.mean(((ig_cpu - baseline_cpu) / baseline_cpu) * 100)
    avg_ig_process_cpu = np.mean(ig_process_cpu)
    avg_ig_process_cpu_ci = np.mean(ig_process_cpu_ci)
    avg_ig_mem = np.mean(ig_mem)
    avg_ig_mem_ci = np.mean(ig_mem_ci)
    avg_mem_overhead_mb = np.mean(ig_mem - baseline_mem)
    avg_ig_process_mem = np.mean(ig_process_mem)
    avg_ig_process_mem_ci = np.mean(ig_process_mem_ci)
    avg_lost = np.mean(ig_lost)

    table_data.append([
        'Average',
        f'{avg_ig_cpu:.2f}%',
        f'±{avg_ig_cpu_ci:.2f}%',
        f'{avg_cpu_overhead_pct:.1f}%',
        f'{avg_ig_process_cpu:.2f}%',
        f'±{avg_ig_process_cpu_ci:.2f}%',
        f'{avg_ig_mem:.0f}MB',
        f'±{avg_ig_mem_ci:.0f}MB',
        f'{avg_mem_overhead_mb:.0f}MB',
        f'{avg_ig_process_mem:.0f}MB',
        f'±{avg_ig_process_mem_ci:.0f}MB',
        f'{int(avg_lost)}'
    ])

    # Create table
    table = ax.table(cellText=table_data[1:], colLabels=table_data[0],
                    cellLoc='center', loc='center')

    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(8)  # Reduced font size to fit more columns
    table.scale(1, 1.5)

    # Color the header row
    for i in range(len(table_data[0])):
        table[(0, i)].set_facecolor('#4CAF50')
        table[(0, i)].set_text_props(weight='bold', color='white')

    # Color the average row (last row)
    avg_row = len(table_data) - 2  # -2 because we exclude header and convert to 0-based index
    for i in range(len(table_data[0])):
        table[(avg_row, i)].set_facecolor('#E3F2FD')
        table[(avg_row, i)].set_text_props(weight='bold')

    # Remove axis
    ax.axis('off')

    return table

def create_plots_for_file(filepath):
    """Create plots for a single test result file"""
    # Read the CSV file
    df = pd.read_csv(filepath)

    # Separate baseline and ig data
    baseline_data = df[df['Name'] == 'baseline']
    ig_data = df[df['Name'] == 'ig']

    if len(baseline_data) == 0 or len(ig_data) == 0:
        print(f"Warning: Missing baseline or ig data in {filepath}")
        return None, None

    # Set up the figure with better proportions for PDF
    fig = plt.figure(figsize=(16, 12))

    # Create a grid layout with title space and table (3 plots in top row)
    gs = fig.add_gridspec(4, 3, height_ratios=[0.08, 1, 0.6, 0.05], hspace=0.3, wspace=0.3)

    # Add main title
    title = get_title_from_filename(filepath)
    fig.suptitle(f'Performance Results: {title}', fontsize=16, fontweight='bold', y=0.97)

    # Create subplots in the middle row
    ax1 = fig.add_subplot(gs[1, 0])
    ax2 = fig.add_subplot(gs[1, 1])
    ax3 = fig.add_subplot(gs[1, 2])

    # Plot 1: Bar chart showing CPU overhead with error bars
    rps_values = baseline_data['rps'].values
    baseline_cpu = baseline_data['%cpu'].values
    ig_cpu = ig_data['%cpu'].values
    baseline_cpu_ci = baseline_data['cpu_ci'].values
    ig_cpu_ci = ig_data['cpu_ci'].values

    # Get IG process specific CPU data
    ig_process_cpu = ig_data['ig_cpu_mean'].values
    ig_process_cpu_ci = ig_data['ig_cpu_ci'].values

    x = np.arange(len(rps_values))
    width = 0.25  # Reduced width to fit 3 bars

    bars1 = ax1.bar(x - width, baseline_cpu, width, label='Baseline', alpha=0.8,
                    yerr=baseline_cpu_ci, capsize=5)
    bars2 = ax1.bar(x, ig_cpu, width, label='IG Total', alpha=0.8,
                    yerr=ig_cpu_ci, capsize=5)
    bars2_ig = ax1.bar(x + width, ig_process_cpu, width, label='IG Process Only', alpha=0.8,
                       yerr=ig_process_cpu_ci, capsize=5, color='orange')

    ax1.set_xlabel('RPS (Requests per Second)', fontsize=11)
    ax1.set_ylabel('CPU Usage (%)', fontsize=11)
    ax1.set_title('CPU Usage Comparison (with 95% CI)', fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(rps_values)
    ax1.legend()
    ax1.grid(True, alpha=0.3, axis='y')

    # Add value labels on CPU bars
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.2f}%', ha='center', va='bottom', fontsize=8)

    for bar in bars2:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.2f}%', ha='center', va='bottom', fontsize=8)

    for bar in bars2_ig:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.2f}%', ha='center', va='bottom', fontsize=8)

    # Plot 2: Bar chart showing Memory overhead with error bars
    baseline_mem = baseline_data['mem(MB)'].values
    ig_mem = ig_data['mem(MB)'].values
    baseline_mem_ci = baseline_data['mem_ci'].values
    ig_mem_ci = ig_data['mem_ci'].values

    # Get IG process specific memory data
    ig_process_mem = ig_data['ig_mem_mean'].values
    ig_process_mem_ci = ig_data['ig_mem_ci'].values

    bars3 = ax2.bar(x - width, baseline_mem, width, label='Baseline', alpha=0.8,
                    yerr=baseline_mem_ci, capsize=5)
    bars4 = ax2.bar(x, ig_mem, width, label='IG Total', alpha=0.8,
                    yerr=ig_mem_ci, capsize=5)
    bars4_ig = ax2.bar(x + width, ig_process_mem, width, label='IG Process Only', alpha=0.8,
                       yerr=ig_process_mem_ci, capsize=5, color='orange')

    ax2.set_xlabel('RPS (Requests per Second)', fontsize=11)
    ax2.set_ylabel('Memory Usage (MB)', fontsize=11)
    ax2.set_title('Memory Usage Comparison (with 95% CI)', fontsize=12, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(rps_values)
    ax2.legend()
    ax2.grid(True, alpha=0.3, axis='y')

    # Adjust Y-axis range to show differences more clearly
    all_mem_values = np.concatenate([baseline_mem, ig_mem, ig_process_mem])
    mem_min, mem_max = np.min(all_mem_values), np.max(all_mem_values)
    mem_range = mem_max - mem_min
    # Add some padding and focus on the range of variation
    #padding = mem_range * 0.1
    padding = 1024
    ax2.set_ylim(mem_min - padding, mem_max + padding)

    # Add value labels on Memory bars
    for bar in bars3:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.0f}MB', ha='center', va='bottom', fontsize=8)

    for bar in bars4:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.0f}MB', ha='center', va='bottom', fontsize=8)

    for bar in bars4_ig:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.0f}MB', ha='center', va='bottom', fontsize=8)

    # Plot 3: Bar chart showing Lost events (only for IG)
    ig_lost = ig_data['lost'].values

    bars5 = ax3.bar(x, ig_lost, width, label='IG (with tracer)', alpha=0.8, color='red')

    ax3.set_xlabel('RPS (Requests per Second)', fontsize=11)
    ax3.set_ylabel('Lost Events', fontsize=11)
    ax3.set_title('Lost Events (IG only)', fontsize=12, fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels(rps_values)
    ax3.legend()
    ax3.grid(True, alpha=0.3, axis='y')

    # Add value labels on Lost bars
    for bar in bars5:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height,
                 f'{int(height)}', ha='center', va='bottom', fontsize=9)

    # Add performance table spanning all three columns
    ax_table = fig.add_subplot(gs[2, :])
    create_performance_table(ax_table, baseline_data, ig_data)

    # Add some summary statistics at the bottom
    avg_cpu_overhead = np.mean(ig_cpu - baseline_cpu)
    avg_mem_overhead = np.mean(ig_mem - baseline_mem)
    avg_lost = np.mean(ig_lost)

    return fig, df

# Create PDF with all plots
with PdfPages(args.output) as pdf:
    for filepath in result_files:
        print(f"\nProcessing: {os.path.basename(filepath)}")
        try:
            fig, df = create_plots_for_file(filepath)
            if fig is not None:
                pdf.savefig(fig, bbox_inches='tight', pad_inches=0.5)
                plt.close(fig)  # Close figure to free memory
            else:
                print(f"Skipping {filepath} due to data issues")
        except Exception as e:
            print(f"Error processing {filepath}: {e}")
            continue

print(f"\nAll plots saved to: {args.output}")
print(f"Processed {len(result_files)} files successfully")
