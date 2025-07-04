#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import argparse
import os

# Parse command line arguments
parser = argparse.ArgumentParser(description='Generate performance comparison plots from benchmark results')
parser.add_argument('--input', '-i', default='test_results.csv',
                    help='Path to the CSV file with benchmark results (default: test_results.csv)')
parser.add_argument('--output', '-o', default='performance_comparison.png',
                    help='Path to save the output image (default: performance_comparison.png)')
args = parser.parse_args()

# Check if input file exists
if not os.path.exists(args.input):
    print(f"Error: Input file '{args.input}' not found")
    exit(1)

# Read the CSV file
df = pd.read_csv(args.input)

# Separate baseline and ig data
baseline_data = df[df['Name'] == 'baseline']
ig_data = df[df['Name'] == 'ig']

# Create the plot with 1x2 subplots
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

# Plot 1: Bar chart showing CPU overhead with error bars
rps_values = baseline_data['rps'].values
baseline_cpu = baseline_data['%cpu'].values
ig_cpu = ig_data['%cpu'].values
baseline_cpu_ci = baseline_data['cpu_ci'].values
ig_cpu_ci = ig_data['cpu_ci'].values

x = np.arange(len(rps_values))
width = 0.35

bars1 = ax1.bar(x - width/2, baseline_cpu, width, label='Baseline', alpha=0.8,
                yerr=baseline_cpu_ci, capsize=5)
bars2 = ax1.bar(x + width/2, ig_cpu, width, label='IG (with tracer)', alpha=0.8,
                yerr=ig_cpu_ci, capsize=5)

ax1.set_xlabel('RPS (Requests per Second)')
ax1.set_ylabel('CPU Usage (%)')
ax1.set_title('CPU Usage Comparison (with 95% CI)')
ax1.set_xticks(x)
ax1.set_xticklabels(rps_values)
ax1.legend()
ax1.grid(True, alpha=0.3, axis='y')

# Add value labels on CPU bars
for bar in bars1:
    height = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2., height,
             f'{height:.2f}%', ha='center', va='bottom')

for bar in bars2:
    height = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2., height,
             f'{height:.2f}%', ha='center', va='bottom')

# Plot 2: Bar chart showing Memory overhead with error bars
baseline_mem = baseline_data['mem(MB)'].values
ig_mem = ig_data['mem(MB)'].values
baseline_mem_ci = baseline_data['mem_ci'].values
ig_mem_ci = ig_data['mem_ci'].values

bars3 = ax2.bar(x - width/2, baseline_mem, width, label='Baseline', alpha=0.8,
                yerr=baseline_mem_ci, capsize=5)
bars4 = ax2.bar(x + width/2, ig_mem, width, label='IG (with tracer)', alpha=0.8,
                yerr=ig_mem_ci, capsize=5)

ax2.set_xlabel('RPS (Requests per Second)')
ax2.set_ylabel('Memory Usage (MB)')
ax2.set_title('Memory Usage Comparison (with 95% CI)')
ax2.set_xticks(x)
ax2.set_xticklabels(rps_values)
ax2.legend()
ax2.grid(True, alpha=0.3, axis='y')

# Adjust Y-axis range to show differences more clearly
all_mem_values = np.concatenate([baseline_mem, ig_mem])
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
             f'{height:.0f}MB', ha='center', va='bottom')

for bar in bars4:
    height = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2., height,
             f'{height:.0f}MB', ha='center', va='bottom')

plt.tight_layout()
plt.savefig(args.output, dpi=300, bbox_inches='tight')
plt.show()

# Print some statistics
print("=== Performance Analysis ===")
print(f"Input file: {args.input}")
print(f"Data points: {len(df)} configurations")
print(f"Runs per configuration: {baseline_data['runs'].iloc[0]}")
print("\nCPU Usage Summary:")
print(f"{'RPS':<10} {'Baseline':<15} {'IG':<15} {'Overhead':<15} {'Overhead %':<12}")
print("-" * 75)

for i, rps in enumerate(rps_values):
    baseline_val = baseline_cpu[i]
    baseline_ci = baseline_cpu_ci[i]
    ig_val = ig_cpu[i]
    ig_ci = ig_cpu_ci[i]
    overhead = ig_val - baseline_val
    overhead_pct = (overhead / baseline_val) * 100
    print(f"{rps:<10} {baseline_val:.2f}±{baseline_ci:.2f}%{'':<4} {ig_val:.2f}±{ig_ci:.2f}%{'':<4} {overhead:<10.2f}%{'':<4} {overhead_pct:<12.1f}")

print(f"\nAverage CPU overhead: {np.mean(ig_cpu - baseline_cpu):.2f}% CPU")
print(f"Average CPU overhead percentage: {np.mean((ig_cpu - baseline_cpu) / baseline_cpu * 100):.1f}%")

print("\nMemory Usage Summary:")
print(f"{'RPS':<10} {'Baseline':<20} {'IG':<20} {'Overhead':<15} {'Overhead %':<12}")
print("-" * 85)

for i, rps in enumerate(rps_values):
    baseline_val = baseline_mem[i]
    baseline_ci = baseline_mem_ci[i]
    ig_val = ig_mem[i]
    ig_ci = ig_mem_ci[i]
    overhead = ig_val - baseline_val
    overhead_pct = (overhead / baseline_val) * 100
    print(f"{rps:<10} {baseline_val:.2f}±{baseline_ci:.2f}MB{'':<5} {ig_val:.2f}±{ig_ci:.2f}MB{'':<5} {overhead:<10.2f}MB{'':<4} {overhead_pct:<12.2f}")

print(f"\nAverage memory overhead: {np.mean(ig_mem - baseline_mem):.2f} MB")
print(f"Average memory overhead percentage: {np.mean((ig_mem - baseline_mem) / baseline_mem * 100):.2f}%")
