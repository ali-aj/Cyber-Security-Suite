def simulate(input_data):
    # Simulating a buffer overflow
    buffer_size = 10
    if len(input_data) > buffer_size:
        return {
            "status": "Overflow detected",
            "message": f"Input exceeds buffer size of {buffer_size} characters"
        }
    else:
        return {
            "status": "No overflow",
            "message": "Input within buffer limits"
        }

