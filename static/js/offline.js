document.addEventListener('DOMContentLoaded', function () {
    let fullData = [];
    const importantColumns = [
        'Destination Port',
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Flow IAT Mean',
        'Label'
    ];

    const fileInput = document.getElementById('dataset_upload');
    const severityFilter = document.getElementById('severity_filter');
    const analysisTableBody = document.querySelector('#analysis_details tbody');
    const analysisTable = document.getElementById('analysis_details');
    const analysisTableHead = document.querySelector('#analysis_details thead');

    // Update table headers dynamically
    const headerRow = document.createElement('tr');
    importantColumns.forEach(colName => {
        const th = document.createElement('th');
        th.textContent = colName;
        headerRow.appendChild(th);
    });
    analysisTableHead.innerHTML = '';
    analysisTableHead.appendChild(headerRow);

    fileInput.addEventListener('change', function () {
        const file = fileInput.files[0];
        if (file) {
            Papa.parse(file, {
                header: true,
                transformHeader: function(header) {
                    return header.trim();
                },
                complete: function (results) {
                    fullData = results.data.filter(row => {
                        // Filter out empty rows if any
                        return importantColumns.some(col => row[col] && row[col].trim() !== '');
                    });
                    populateSeverityFilter(fullData);
                    renderTable(fullData);
                    generateChart(fullData);
                }
            });
        } else {
            alert('Please select a CSV file to analyze.');
        }
    });

    severityFilter.addEventListener('change', function () {
        const selectedSeverity = severityFilter.value;
        if (selectedSeverity === 'all') {
            renderTable(fullData);
        } else {
            const filteredData = fullData.filter(row => row.Label === selectedSeverity);
            renderTable(filteredData);
        }
    });

    function populateSeverityFilter(data) {
        const severityLevels = [...new Set(data.map(row => row.Label).filter(label => label))];
        severityFilter.innerHTML = '<option value="all">All</option>';
        severityLevels.forEach(level => {
            if (level) {
                const option = document.createElement('option');
                option.value = level;
                option.textContent = level;
                severityFilter.appendChild(option);
            }
        });
    }

    function renderTable(data) {
        analysisTableBody.innerHTML = '';
        if (data.length === 0) {
            analysisTableBody.innerHTML = `<tr><td colspan="${importantColumns.length}" class="text-center">No data to display.</td></tr>`;
            return;
        }

        data.forEach(row => {
            const tr = document.createElement('tr');
            importantColumns.forEach(col => {
                const td = document.createElement('td');
                td.textContent = row[col] || '';
                tr.appendChild(td);
            });
            analysisTableBody.appendChild(tr);
        });
    }

    function generateChart(data) {
        const portCounts = {};
        data.forEach(row => {
            const port = row['Destination Port'];
            if (port) {
                portCounts[port] = (portCounts[port] || 0) + 1;
            }
        });

        const chartLabels = Object.keys(portCounts);
        const chartData = Object.values(portCounts);

        const ctx = document.getElementById('myChart').getContext('2d');
        if (window.myChart instanceof Chart) {
            window.myChart.destroy();
        }
        window.myChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: chartLabels,
                datasets: [{
                    label: 'Destination Port Activity',
                    data: chartData,
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
});