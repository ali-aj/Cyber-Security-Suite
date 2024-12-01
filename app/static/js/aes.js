document.addEventListener('DOMContentLoaded', () => {
    const encryptForm = document.getElementById('encrypt-form');
    const decryptForm = document.getElementById('decrypt-form');
    const keyInput = document.getElementById('key');
    const copyButtons = document.querySelectorAll('.btn-copy');
    const submitButton = encryptForm.querySelector('button[type="submit"]');

    function validateKey(key) {
        const length = new TextEncoder().encode(key).length;
        return [16, 24, 32].includes(length);
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
            validationSpan.textContent = 'Valid key length';
            validationSpan.className = 'validation-message success';
            submitButton.disabled = false;
        } else {
            validationSpan.textContent = 'Key must be 16, 24, or 32 bytes';
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
        formData.append('operation', 'aes_encrypt');
        
        try {
            const response = await fetch('/aes', {
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
        formData.append('operation', 'aes_decrypt');
        
        try {
            const response = await fetch('/aes', {
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