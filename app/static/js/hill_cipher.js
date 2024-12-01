document.addEventListener('DOMContentLoaded', () => {
    const encryptForm = document.getElementById('encrypt-form');
    const decryptForm = document.getElementById('decrypt-form');
    const keyInput = document.getElementById('key');
    const copyButtons = document.querySelectorAll('.btn-copy');
    const submitButton = encryptForm.querySelector('button[type="submit"]');

    function validateKey(key) {
        const numbers = key.split(',').map(n => parseInt(n.trim()));
        return numbers.length === 9 && numbers.every(n => !isNaN(n));  // 3x3 matrix
    }

    function showToast(message) {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = 'show';
        setTimeout(() => toast.className = '', 3000);
    }

    keyInput.addEventListener('input', () => {
        const key = keyInput.value;
        const validationSpan = document.getElementById('key-validation');
        const isValid = validateKey(key);
        
        if (isValid) {
            validationSpan.textContent = 'Valid key matrix format';
            validationSpan.className = 'validation-message success';
            submitButton.disabled = false;
        } else {
            validationSpan.textContent = 'Key must be 9 comma-separated numbers';
            validationSpan.className = 'validation-message error';
            submitButton.disabled = true;
        }
    });

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
        formData.append('operation', 'hill_cipher_encrypt');
        
        try {
            const response = await fetch('/hill_cipher', {
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
        formData.append('operation', 'hill_cipher_decrypt');
        
        try {
            const response = await fetch('/hill_cipher', {
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