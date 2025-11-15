// ... existing code ...
        myChart.update();


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