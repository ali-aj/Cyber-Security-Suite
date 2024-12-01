document.getElementById('xss-form').addEventListener(  'submit', function(e) {
    e.preventDefault();
    const url = document.getElementById('url').value;
    fetch('/xss_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `url=${encodeURIComponent(url)}`
    })
    .then(response => response.json())
    .then(data => {
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = `
            <h3>Scan Results:</h3>
            <p>URL: ${data.url}</p>
            <p>Status: ${data.status}</p>
            <p>Potential XSS: ${data.potential_xss ? 'Yes' : 'No'}</p>
            <p>Inline Scripts: ${data.inline_scripts}</p>
        `;
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

