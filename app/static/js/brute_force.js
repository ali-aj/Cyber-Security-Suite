document.getElementById('brute-force-form').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    fetch('/brute_force', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = `
            <h3>Simulation Results:</h3>
            <p>Status: ${data.status}</p>
            <p>Message: ${data.message}</p>
        `;
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

