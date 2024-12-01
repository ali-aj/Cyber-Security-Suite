document.addEventListener('DOMContentLoaded', () => {
    const encryptForm = document.getElementById('encrypt-form');
    const decryptForm = document.getElementById('decrypt-form');
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

    encryptForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        formData.append('operation', 'rsa_encrypt');
        
        try {
            const response = await fetch('/rsa', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            if (data.error) {
                showToast(data.error);
                return;
            }
            
            document.getElementById('encrypted-result').value = data.result;
        } catch (error) {
            showToast('Error during encryption');
            console.error('Error:', error);
        }
    });

    decryptForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        formData.append('operation', 'rsa_decrypt');
        
        try {
            const response = await fetch('/rsa', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            if (data.error) {
                showToast(data.error);
                return;
            }
            
            document.getElementById('decrypted-result').value = data.result;
        } catch (error) {
            showToast('Error during decryption');
            console.error('Error:', error);
        }
    });
});