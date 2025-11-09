$(document).ready(function(){
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    var messages_received = [];

    var ctx = document.getElementById("myChart");
    var myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    // 'rgba(255, 99, 132, 0.2)',
                    // 'rgba(54, 162, 235, 0.2)',
                    // 'rgba(255, 206, 86, 0.2)',
                    // 'rgba(75, 192, 192, 0.2)',
                    // 'rgba(153, 102, 255, 0.2)'
                ],
                borderColor: [
                    // 'rgba(255,99,132,1)',
                    // 'rgba(54, 162, 235, 1)',
                    // 'rgba(255, 206, 86, 1)',
                    // 'rgba(75, 192, 192, 1)',
                    // 'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {

                legend: {
                  display: false
                }
              ,
            scales: {
    
                yAxes: [{
                    ticks: {
                        beginAtZero:true
                    }
                }]
            }
        }
    });

    function getSeverityClass(severity) {
        if (severity.includes("High")) {
            return "table-danger";
        } else if (severity.includes("Medium")) {
            return "table-warning";
        } else if (severity.includes("Low")) {
            return "table-success";
        }
        return "";
    }

    //receive details from server
    socket.on('newresult', function(msg) {
        console.log("Received result" + msg.result);
        //maintain a list of 10 messages
        if (messages_received.length >= 10){
            messages_received.shift()
        }            
        messages_received.push(msg.result);
        updateTable(); // Update table with the new data

        // Update chart
        for (var i=0; i < msg.ips.length; i++) {
            myChart.data.datasets[0].data[i] =msg.ips[i].count;
            myChart.data.labels[i] =msg.ips[i].SourceIP;
        }
        myChart.update();
    });

    function updateTable() {
        var prediction_filter = $('#prediction_filter').val();
        var severity_filter = $('#severity_filter').val();
        var messages_string = '<tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Flow start time</th><th>Flow last seen</th><th>App name</th><th>PID</th><th>Prediction</th><th>Prob</th><th>Risk</th><th>Severity</th></tr>';
        var filtered_messages = messages_received;

        if (prediction_filter !== 'all') {
            filtered_messages = filtered_messages.filter(function(msg) {
                return msg[10] === prediction_filter; // Prediction is at index 10
            });
        }

        if (severity_filter !== 'all') {
            filtered_messages = filtered_messages.filter(function(msg) {
                // Extract severity level from HTML string
                var severity_html = msg[12];
                var severity = $(severity_html).text();
                return severity === severity_filter;
            });
        }

        for (var i = filtered_messages.length - 1; i >= 0; i--) {
            var severity_html = filtered_messages[i][12];
            var severityClass = getSeverityClass(severity_html);
            messages_string = messages_string + '<tr class="' + severityClass + '">';
            for (var j = 0; j < filtered_messages[i].length; j++) {
                messages_string = messages_string + '<td>' + filtered_messages[i][j].toString() + '</td>';
            }
            messages_string = messages_string + '<td> <a href="/flow-detail?flow_id=' + filtered_messages[i][0].toString() + '"><div>Detail</div></a></td>' + '</tr>';
        }
        $('#details').html(messages_string);
    }

    $('#prediction_filter').on('change', function() {
        updateTable();
    });

    $('#severity_filter').on('change', function() {
        updateTable();
    });
});