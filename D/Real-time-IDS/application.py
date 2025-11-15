
def snif_and_detect():

    while not thread_stop_event.isSet():
        print("Begin Sniffing".center(20, ' '))
        # sniff for 1 second at a time, checking thread_stop_event in between
        sniff(prn=newPacket, timeout=1)
        
    print("Sniffing stopped.")


@app.route('/')
def index():
@socketio.on('connect', namespace='/test')
def test_connect():
    # need visibility of the global thread object
    global thread
    print('Client connected')

    # The sniffing thread is no longer started automatically on connect.
    # It will be started by a 'start_sniffing' event from the client.

@socketio.on('start_sniffing', namespace='/test')
def start_sniffing():
    """Starts the background sniffing thread."""
    global thread
    if not thread.is_alive():
        thread_stop_event.clear()
        print("Starting Thread")
        thread = socketio.start_background_task(snif_and_detect)

@socketio.on('stop_sniffing', namespace='/test')
def stop_sniffing():
    """Stops the background sniffing thread."""
    print('Stop sniffing command received')
    thread_stop_event.set()


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')

from data_loader import load_ids_logs
// ... existing code ...