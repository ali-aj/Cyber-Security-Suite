document.getElementById('ids-form').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    fetch('/ids', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const resultsDiv = document.getElementById('results');
        let resultsHTML = '<h3>Analysis Results:</h3>';
        for (const [attackType, result] of Object.entries(data)) {
            resultsHTML += `<p>${attackType}: ${result}</p>`;
        }
        resultsDiv.innerHTML = resultsHTML;
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

