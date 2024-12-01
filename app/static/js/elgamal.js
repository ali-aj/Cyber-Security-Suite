document.addEventListener('DOMContentLoaded', () => {
    const encryptForm = document.getElementById('encrypt-form');
    const inputs = ['message', 'prime', 'primitive-root', 'private-key'];
    const submitButton = encryptForm.querySelector('button[type="submit"]');

    function validateForm() {
        const allFilled = inputs.every(id => document.getElementById(id).value.trim() !== '');
        submitButton.disabled = !allFilled;
    }

    inputs.forEach(id => {
        document.getElementById(id).addEventListener('input', validateForm);
    });

    async function validatePrimitiveRoot(prime, root) {
        const response = await fetch('/validate_primitive_root', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `prime=${prime}&root=${root}`
        });
        return await response.json();
    }

    document.getElementById('primitive-root').addEventListener('change', async (e) => {
        const prime = document.getElementById('prime').value;
        const root = e.target.value;
        const validation = await validatePrimitiveRoot(prime, root);
        
        const validationSpan = document.getElementById('root-validation');
        if (!validation.valid) {
            validationSpan.textContent = validation.error;
            validationSpan.className = 'validation-message error';
            submitButton.disabled = true;
        } else {
            validationSpan.textContent = 'Valid primitive root';
            validationSpan.className = 'validation-message success';
            validateForm();
        }
    });

    encryptForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        
        try {
            const response = await fetch('/elgamal', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams(formData)
            });
            
            const data = await response.json();
            if (data.error) {
                showToast(data.error);
                return;
            }
            
            document.getElementById('public-key-result').value = data.public_key;
            document.getElementById('cipher-result').value = 
                `C1: ${data.c1}\nC2: ${data.c2.join(', ')}`;
        } catch (error) {
            showToast('Error during encryption');
            console.error('Error:', error);
        }
    });
});