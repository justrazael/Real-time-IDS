$(document).ready(function(){
    // Helper function to format a Unix timestamp (in seconds) to a readable string
    function formatTimestamp(timestamp) {
        if (!timestamp || typeof timestamp !== 'number') return timestamp;
        
        // Assuming the timestamp is in seconds, multiply by 1000 for milliseconds
        const date = new Date(timestamp * 1000); 
        
        // Format as YYYY-MM-DD HH:MM:SS
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }
    
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    var messages_received = [];
    var all_messages = []; // Store all messages for client-side filtering
    var filtered_logs = []; // Store filtered logs for export
    var ctx = document.getElementById("myChart");
    var myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.2)',
                    'rgba(54, 162, 235, 0.2)',
                    'rgba(255, 206, 86, 0.2)',
                    'rgba(75, 192, 192, 0.2)',
                    'rgba(153, 102, 255, 0.2)'
                ],
                borderColor: [
                    'rgba(255,99,132,1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            legend: {
                display: true,
                position: 'top'
            },
            scales: {
    
                yAxes: [{
                    ticks: {
                        beginAtZero:true
                    }
                }]
            }
        }
    });
    var pieCtx = document.getElementById("pieChart").getContext('2d');
    var pieChart = new Chart(pieCtx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.2)',
                    'rgba(54, 162, 235, 0.2)',
                    'rgba(255, 206, 86, 0.2)',
                    'rgba(75, 192, 192, 0.2)',
                    'rgba(153, 102, 255, 0.2)'
                ],
                borderColor: [
                    'rgba(255,99,132,1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            legend: {
                position: 'top',
                display: true
            },
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });

    // Event listener for exporting pie chart
    $('#export-pie-chart').on('click', function() {
        var a = document.createElement('a');
        a.href = pieChart.toBase64Image();
        a.download = 'prediction-types.png';
        a.click();
    });

    $('#export-bar-chart').on('click', function() {
        var a = document.createElement('a');
        a.href = myChart.toBase64Image();
        a.download = 'source-ip-activity.png';
        a.click();
    });

    // Event listener for exporting live log
    $('#export-live-log').on('click', function() {
        if (messages_received.length === 0) {
            alert("No live flow data to export.");
            return;
        }

        const headers = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Start time', 'Flow last seen', 'App name', 'PID', 'Prediction', 'Prob', 'Risk'];
        
        let csvRows = [];
        csvRows.push(headers.join(',')); // Add header row

        messages_received.forEach(function(row) {
            let newRow = [...row]; // Create a copy to modify

            // Clean up IP columns (remove HTML)
            newRow[1] = String(newRow[1]).replace(/<.*?>/g, ''); // Src IP
            newRow[3] = String(newRow[3]).replace(/<.*?>/g, ''); // Dst IP

            // Format timestamps
            newRow[6] = formatTimestamp(newRow[6]); // Start time
            newRow[7] = formatTimestamp(newRow[7]); // Flow last seen

            // Clean up Risk column (extract text from HTML)
            newRow[12] = $(newRow[12]).text();

            // Handle potential commas in data by quoting
            const processedRow = newRow.map(cell => {
                let cellData = String(cell).replace(/"/g, '""'); // Escape double quotes
                if (cellData.includes(',')) {
                    return `"${cellData}"`;
                }
                return cellData;
            });
            
            csvRows.push(processedRow.join(','));
        });

        const csvString = csvRows.join('\r\n');
        const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
        
        var link = document.createElement("a");
        if (link.download !== undefined) { // feature detection
            // Browsers that support HTML5 download attribute
            var url = URL.createObjectURL(blob);
            link.setAttribute("href", url);
            link.setAttribute("download", "live_flow_capture.csv");
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    });

    // Event listener for exporting filtered log
    $('#export-filtered-log').on('click', function() {
        if (filtered_logs.length === 0) {
            alert("No filtered data to export. Please apply a filter first.");
            return;
        }

        const headers = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Start time', 'Flow last seen', 'App name', 'PID', 'Prediction', 'Prob', 'Risk'];
        
        let csvRows = [];
        csvRows.push(headers.join(',')); // Add header row

        filtered_logs.forEach(function(row) {
            let newRow = [...row]; // Create a copy to modify

            // Clean up IP columns (remove HTML)
            newRow[1] = String(newRow[1]).replace(/<.*?>/g, ''); // Src IP
            newRow[3] = String(newRow[3]).replace(/<.*?>/g, ''); // Dst IP

            // Format timestamps
            newRow[6] = formatTimestamp(newRow[6]); // Start time
            newRow[7] = formatTimestamp(newRow[7]); // Flow last seen

            // Clean up Risk column (extract text from HTML)
            newRow[12] = $(newRow[12]).text();

            // Handle potential commas in data by quoting
            const processedRow = newRow.map(cell => {
                let cellData = String(cell).replace(/"/g, '""'); // Escape double quotes
                if (cellData.includes(',')) {
                    return `"${cellData}"`;
                }
                return cellData;
            });
            
            csvRows.push(processedRow.join(','));
        });

        const csvString = csvRows.join('\r\n');
        const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
        
        var link = document.createElement("a");
        if (link.download !== undefined) { // feature detection
            // Browsers that support HTML5 download attribute
            var url = URL.createObjectURL(blob);
            link.setAttribute("href", url);
            link.setAttribute("download", "filtered_flow_capture.csv");
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    });

    //receive details from server
    socket.on('newresult', function(msg) {
        console.log("Received result" + msg.result);
        //maintain a list of ten messages
        if (messages_received.length >= 10){
            messages_received.shift()
        }            
        messages_received.push(msg.result);
        all_messages.push(msg.result); // Store all logs for filtering
        
        updateFilterOptions(all_messages); // Update filter options with all unique values

        messages_string = '<tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Start time</th><th>Flow last seen</th><th>App name</th><th>PID</th><th>Prediction</th><th>Prob</th><th>Risk</th></tr>';

        for (var i = messages_received.length-1 ; i >= 0; i--){
            messages_string = messages_string + '<tr>';
            for (var j = 0; j <messages_received[i].length; j++){
                var cellValue = messages_received[i][j];

                // Check if the current column is 'Start time' (index 6) or 'Flow last seen' (index 7)
                if (j === 6 || j === 7) { 
                    cellValue = formatTimestamp(cellValue); 
                } else {
                    cellValue = cellValue.toString();
                }
                
                messages_string = messages_string + '<td>' + cellValue + '</td>'; 
            }
            messages_string = messages_string + '</tr>';

        }
        $('#details').html(messages_string);

        for (var i=0; i < msg.ips.length; i++) {
            myChart.data.datasets[0].data[i] =msg.ips[i].count;
            myChart.data.labels[i] =msg.ips[i].SourceIP;

        }

        myChart.update();
        myChart.update();

        var predictionCounts = {};
        all_messages.forEach(function(log) {
            var prediction = log[10];
            predictionCounts[prediction] = (predictionCounts[prediction] || 0) + 1;
        });

        pieChart.data.labels = Object.keys(predictionCounts);
        pieChart.data.datasets[0].data = Object.values(predictionCounts);
        pieChart.update();
    })

    function updateFilterOptions(data) {
        var predictions = new Set();
        var risks = new Set();

        data.forEach(function(row) {
            predictions.add(row[10]); // Prediction is at index 10
            
            // Extract text from <p> tag for risk
            var riskHtml = row[12]; // Risk is at index 12
            var riskText = $(riskHtml).text();
            if (riskText) {
                risks.add(riskText);
            }
        });

        var predictionMenu = $('#prediction-filter-values');
        predictionMenu.empty();
        predictions.forEach(function(value) {
            predictionMenu.append('<li><a href="#" class="filter-option" data-filter-by="prediction" data-filter-value="' + value + '">' + value + '</a></li>');
        });

        var riskMenu = $('#risk-filter-values');
        riskMenu.empty();
        risks.forEach(function(value) {
            riskMenu.append('<li><a href="#" class="filter-option" data-filter-by="risk" data-filter-value="' + value + '">' + value + '</a></li>');
        });
    }

    $(document).on('click', '.filter-option', function(e) {
        e.preventDefault();
        var filterBy = $(this).data('filter-by');
        var filterValue = $(this).data('filter-value');
        console.log('Client-side filtering by ' + filterBy + ' = ' + filterValue);

        filtered_logs = all_messages.filter(function(log) {
            if (filterBy === 'prediction') {
                return log[10] === filterValue;
            } else if (filterBy === 'risk') {
                var riskHtml = log[12];
                var riskText = $(riskHtml).text();
                return riskText === filterValue;
            }
            return false;
        });

        var filtered_messages_string = '<thead><tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Start time</th><th>Flow last seen</th><th>App name</th><th>PID</th><th>Prediction</th><th>Prob</th><th>Risk</th></tr></thead><tbody>';
        if (filtered_logs.length > 0) {
            for (var i = 0; i < filtered_logs.length; i++) {
                filtered_messages_string += '<tr>';
                var row = filtered_logs[i];
                for (var j = 0; j < row.length; j++) {
                    var cellValue = row[j];
                    if (j === 6 || j === 7) { // Start time and Last seen
                        cellValue = formatTimestamp(cellValue);
                    } else {
                        cellValue = String(cellValue);
                    }
                    filtered_messages_string += '<td>' + cellValue + '</td>';
                }
                filtered_messages_string += '</tr>';
            }
        } else {
            filtered_messages_string += '<tr><td colspan="13" class="text-center">No logs match the filter.</td></tr>';
        }
        filtered_messages_string += '</tbody>';
        $('#filtered-details').html(filtered_messages_string);
    });

    $('#clear-filter-btn').on('click', function() {
        console.log('Clearing filter');
        $('#filtered-details tbody').html('<tr><td colspan="13" class="text-center">Select a filter to view logs.</td></tr>');
        filtered_logs = []; // Clear the stored filtered logs
    });

    $('#start-button').on('click', function() {
        console.log('Start button clicked');
        socket.emit('start_sniffing');
        $('#start-button').hide();
        $('#stop-button').show();
    });

    $('#stop-button').on('click', function() {
        console.log('Stop button clicked');
        socket.emit('stop_sniffing');
        $('#stop-button').hide();
        $('#start-button').show();
    });
});