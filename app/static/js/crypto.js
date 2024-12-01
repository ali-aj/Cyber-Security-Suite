document.getElementById('crypto-form').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    fetch('/crypto', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const resultsDiv = document.getElementById('results');
        if (data.error) {
            resultsDiv.innerHTML = `<p>Error: ${data.error}</p>`;
        } else {
            resultsDiv.innerHTML = `<p>Result: ${data.result}</p>`;
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

