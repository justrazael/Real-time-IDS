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
                  display: false
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
    });

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

        var filtered_logs = all_messages.filter(function(log) {
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