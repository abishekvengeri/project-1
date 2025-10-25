import pandas as pd
import os
import matplotlib.pyplot as plt

# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def visualize_alerts(alerts_file=os.path.join(PROJECT_ROOT, "data", "alerts.csv")):
    """Generate a bar chart of alerts by severity."""
    try:
        df = pd.read_csv(alerts_file)
        if df.empty:
            print("No alerts found in", alerts_file)
            return
        # Count alerts by severity
        severity_counts = df['severity'].value_counts()
        # Create bar chart
        plt.figure(figsize=(8, 6))
        severity_counts.plot(kind='bar', color=['#ff4c4c', '#ffd700'])
        plt.title('Ransomware Alerts by Severity')
        plt.xlabel('Severity')
        plt.ylabel('Number of Alerts')
        plt.xticks(rotation=0)
        output_file = os.path.join(PROJECT_ROOT, "screenshots", "alerts_plot.png")
        plt.savefig(output_file)
        plt.close()
        print(f"Bar chart saved to {output_file}")
    except FileNotFoundError:
        print(f"Error: {alerts_file} not found")
    except Exception as e:
        print(f"Error generating visualization: {e}")

if __name__ == "__main__":
    visualize_alerts()
