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

    //receive details from server
    socket.on('newresult', function(msg) {
        console.log("Received result" + msg.result);
        //maintain a list of ten messages
        if (messages_received.length >= 10){
            messages_received.shift()
        }            
        messages_received.push(msg.result);
        
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
            // *** REMOVED: The line that added the 'Detail' button column (no longer appended) ***
            messages_string = messages_string + '</tr>';

        }
        $('#details').html(messages_string);

        // var i = 0;
        // Object.keys(msg.ips).forEach(function(key) {
        //     myChart.data.datasets[0].data[i] = msg.ips[key] ;
        //     myChart.data.labels[i] =key;
        //     i = i+1;
        //   })

        for (var i=0; i < msg.ips.length; i++) {
            myChart.data.datasets[0].data[i] =msg.ips[i].count;
            myChart.data.labels[i] =msg.ips[i].SourceIP;
           
           }
           
               myChart.update();

        myChart.update();


    });

});