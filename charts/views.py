import matplotlib.pyplot as plt
import os
from django.conf import settings
from django.shortcuts import render

def     generate_bar_chart(request):
    # Data for the chart
    categories = ['Category A', 'Category B', 'Category C']
    values = [20, 35, 50]
    
    # Generate the bar chart
    plt.figure(figsize=(10, 6))
    plt.bar(categories, values, color='skyblue')
    plt.xlabel('Categories')
    plt.ylabel('Values')
    plt.title('Bar Chart Example')

    # Save the chart to the media directory
    chart_path = os.path.join(settings.MEDIA_ROOT, 'charts')
    os.makedirs(chart_path, exist_ok=True)
    file_path = os.path.join(chart_path, 'bar_chart.png')
    plt.savefig(file_path)
    plt.close()  # Close the plot to free memory

    # Pass the file URL to the template
    chart_url = '/media /bar_charts.png'
    return render(request, 'bar_charts.html', {'chart_url': chart_url})