document.addEventListener('DOMContentLoaded', () => {
    const generateForm = document.getElementById('generate-form');
    const copyButtons = document.querySelectorAll('.btn-copy');

    function showToast(message) {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = 'show';
        setTimeout(() => toast.className = '', 3000);
    }

    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            showToast('Copied to clipboard!');
        } catch (err) {
            showToast('Failed to copy text.');
        }
    }

    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-target');
            const text = document.getElementById(targetId).value;
            copyToClipboard(text);
        });
    });

    generateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        formData.append('operation', 'diffie_hellman');
        
        try {
            const response = await fetch('/diffie_hellman', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            if (data.error) {
                showToast(data.error);
                return;
            }
            
            document.getElementById('shared-key-result').value = data.result;
            document.getElementById('public-key-alice').value = data.public_key_a;
            document.getElementById('public-key-bob').value = data.public_key_b;
        } catch (error) {
            showToast('Error during key generation');
            console.error('Error:', error);
        }
    });
});