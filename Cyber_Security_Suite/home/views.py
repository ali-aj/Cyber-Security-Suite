from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from .models import ScanResult, IDSLog, CryptoOperation
from .utils import security_analyzer, crypto_toolkit, ids, buffer_overflow, brute_force
from .utils.elgamal import validate_elgamal_params, encrypt, decrypt, generate_keys
import json
import logging
from django.http import StreamingHttpResponse

logger = logging.getLogger(__name__)

def index(request):
    context = {
        'scan_count': ScanResult.objects.count(),
        'threat_count': ScanResult.objects.filter().count(),
        'crypto_count': CryptoOperation.objects.count(),
    }
    return render(request, 'index.html', context)

@require_http_methods(["GET", "POST"])
def xss_scan(request):
    if request.method == 'POST':
        try:
            url = request.POST.get('url')
            if not url:
                return JsonResponse({'error': 'URL is required'}, status=400)
            
            results = security_analyzer.xss_scan(url)
            
            scan_result = ScanResult.objects.create(
                url=url,
                scan_type='XSS',
                result=json.dumps(results)
            )
            
            return JsonResponse({
                'status': 'success',
                'scan_id': scan_result.id,
                'url': url,
                'vulnerabilities': results.get('vulnerabilities', []),
                'inline_scripts': results.get('inline_scripts', 0),
                'potential_xss': results.get('potential_xss', False)
            })
            
        except Exception as e:
            logger.error(f"XSS scan error: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
            
    return render(request, 'xss_scan.html')

@require_http_methods(["GET", "POST"])
def rsa(request):
    if request.method == 'POST':
        try:
            operation = request.POST.get('action')
            text = request.POST.get('message') or request.POST.get('cipher')
            
            if operation == 'rsa_encrypt':
                result = crypto_toolkit.perform_operation(operation, text, None)
            elif operation == 'rsa_decrypt':
                private_key = request.POST.get('private_key')
                if not private_key:
                    return JsonResponse({'error': 'Private key required'}, status=400)
                result = crypto_toolkit.perform_operation(operation, text, private_key)
            
            # Store operation in database
            CryptoOperation.objects.create(
                operation_type=operation.upper(),
                input_text=text,
                output_text=result['result']
            )

            return JsonResponse(result)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
            
    return render(request, 'rsa.html')

@require_http_methods(["GET", "POST"])
def aes(request):
    if request.method == 'POST':
        operation = request.POST.get('action')
        text = request.POST.get('plaintext') or request.POST.get('ciphertext')
        key = request.POST.get('key')
        result = crypto_toolkit.perform_operation(operation, text, key)

        # Store operation in database
        CryptoOperation.objects.create(
            operation_type=operation.upper(),
            input_text=text,
            output_text=result['result']
        )

        return JsonResponse(result)
    return render(request, 'aes.html')

@require_http_methods(["GET", "POST"])
def des(request):
    if request.method == 'POST':
        operation = request.POST.get('action')
        text = request.POST.get('plaintext') or request.POST.get('ciphertext')
        key = request.POST.get('key')
        result = crypto_toolkit.perform_operation(operation, text, key)

        # Store operation in database
        CryptoOperation.objects.create(
            operation_type=operation.upper(),
            input_text=text,
            output_text=result['result']
        )

        return JsonResponse(result)
    return render(request, 'des.html')

@require_http_methods(["GET", "POST"])
def hill_cipher(request):
    if request.method == 'POST':
        try:
            operation = request.POST.get('action')
            text = request.POST.get('plaintext') or request.POST.get('ciphertext')
            key_matrix = request.POST.get('matrix')
            
            if not text or not key_matrix:
                return JsonResponse({
                    'error': 'Both text and key matrix are required'
                }, status=400)
            
            result = crypto_toolkit.perform_operation(operation, text, key_matrix)

            # Store operation in database
            CryptoOperation.objects.create(
                operation_type=f'HILL_{operation.upper()}',
                input_text=text,
                output_text=result['result']
            )

            return JsonResponse(result)
            
        except Exception as e:
            return JsonResponse({
                'error': str(e)
            }, status=400)
            
    return render(request, 'hill_cipher.html')

@require_http_methods(["POST"])
def validate_primitive_root(request):
    try:
        prime = int(request.POST.get('prime'))
        root = int(request.POST.get('root'))
        result = validate_elgamal_params(prime, root, 1)
        return JsonResponse(result)
    except ValueError as e:
        return JsonResponse({"valid": False, "error": str(e)})

@require_http_methods(["GET", "POST"])
def elgamal(request):
    if request.method == 'POST':
        try:
            operation = request.POST.get('operation')
            logger.info(f"ElGamal operation: {operation}")
            
            if operation == 'encrypt':
                message = request.POST.get('message')
                prime = int(request.POST.get('prime'))
                root = int(request.POST.get('primitive-root'))
                private_key = int(request.POST.get('private-key'))
                
                validation = validate_elgamal_params(prime, root, private_key)
                if not validation["valid"]:
                    return JsonResponse({"error": validation["error"]})
                
                public_key = generate_keys(prime, root, private_key)
                c1, c2 = encrypt(message, prime, root, public_key)
                
                # Store encryption operation
                CryptoOperation.objects.create(
                    operation_type='ELGAMAL_ENCRYPT',
                    input_text=message,
                    output_text=f'c1: {c1}, c2: {c2}'
                )
                
                return JsonResponse({
                    "public_key": str(public_key),
                    "c1": str(c1),
                    "c2": [str(x) for x in c2]
                })
            
            elif operation == 'decrypt':
                c1 = int(request.POST.get('c1'))
                c2 = int(request.POST.get('c2'))
                peer_key = int(request.POST.get('peer-key'))
                prime = int(request.POST.get('prime'))
                
                plaintext = decrypt(c1, c2, peer_key, prime)
                
                # Store decryption operation
                CryptoOperation.objects.create(
                    operation_type='ELGAMAL_DECRYPT',
                    input_text=f'c1: {c1}, c2: {c2}',
                    output_text=plaintext
                )
                
                return JsonResponse({"plaintext": plaintext})
                
        except ValueError as e:
            logger.error(f"ElGamal operation error: {str(e)}")
            return JsonResponse({"error": str(e)})
            
    return render(request, 'elgamal.html')

@require_http_methods(["GET", "POST"])
def diffie_hellman(request):
    if request.method == 'POST':
        result = crypto_toolkit.perform_operation('diffie_hellman', None, None)

        # Store key exchange operation
        CryptoOperation.objects.create(
            operation_type='DIFFIE_HELLMAN',
            input_text='Key Exchange Parameters',
            output_text=f'Shared Secret: {result["result"]}'
        )

        return JsonResponse(result)
    return render(request, 'diffie_hellman.html')

@require_http_methods(["GET", "POST"])
def crypto(request):
    if request.method == 'POST':
        operation = request.POST.get('operation')
        text = request.POST.get('text')
        key = request.POST.get('key')

        result = crypto_toolkit.perform_operation(operation, text, key)

        if 'result' in result:
            # Save crypto operation to database
            crypto_op = CryptoOperation(
                operation_type=operation,
                input_text=text,
                output_text=result['result']
            )
            try:
                crypto_op.save()
            except Exception as db_error:
                logger.error(f"Database Error: {str(db_error)}")
                return JsonResponse({"error": "Database error occurred."}), 500
            return JsonResponse(result)
        else:
            # Handle error case
            error_message = result.get('error', 'Unknown error occurred.')
            return JsonResponse({"error": error_message}), 400

    return render(request, 'crypto.html')

@require_http_methods(["GET", "POST"])
def intrusion_detection(request):
    if request.method == 'POST':
        try:
            log_data = request.POST.get('log_data')
            if not log_data:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Log data is required'
                }, status=400)

            # Analyze logs
            analysis_results = ids.analyze(log_data)

            # Save to database
            ids_log = IDSLog.objects.create(
                log_data=log_data,
                analysis_result=json.dumps(analysis_results),
                severity_level=analysis_results.get('overall_severity', 'low')
            )

            # Prepare detailed response
            response_data = {
                'status': 'success',
                'log_id': ids_log.id,
                'timestamp': ids_log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'results': {
                    'severity': analysis_results['overall_severity'],
                    'findings': analysis_results['findings'],
                    'statistics': {
                        'ips': dict(analysis_results['ips']),
                        'timestamps': analysis_results['timestamps']
                    },
                    'remediation': analysis_results['remediation']
                }
            }

            return JsonResponse(response_data)

        except Exception as e:
            logger.error(f"IDS Analysis error: {str(e)}", exc_info=True)
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)

    return render(request, 'ids.html')

@require_http_methods(["GET", "POST"])
def buffer_overflow_sim(request):
    if request.method == 'POST':
        input_data = request.POST.get('input_data')
        results = buffer_overflow.simulate(input_data)
        return JsonResponse(results)
    return render(request, 'buffer_overflow.html')

@require_http_methods(["GET", "POST"])
def brute_force_sim(request):
    if request.method == 'POST':
        try:
            target = request.POST.get('target')
            charset = request.POST.get('charset', 'lower')
            
            if not target:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Target password is required'
                }, status=400)

            def event_stream():
                for result in brute_force.simulate(target=target, charset_type=charset):
                    yield f"data: {json.dumps(result)}\n\n"

            response = StreamingHttpResponse(
                event_stream(),
                content_type='text/event-stream'
            )
            response['Cache-Control'] = 'no-cache'
            response['X-Accel-Buffering'] = 'no'
            return response
            
        except Exception as e:
            logger.error(f"Brute force error: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=400)
            
    return render(request, 'brute_force.html')

def scan_history(request):
    scans = ScanResult.objects.order_by('-timestamp').all()
    return render(request, 'scan_history.html', {'scans': scans})

def ids_logs(request):
    logs = IDSLog.objects.order_by('-timestamp').all()
    return render(request, 'ids_logs.html', {'logs': logs})

def crypto_history(request):
    operations = CryptoOperation.objects.order_by('-timestamp').all()
    return render(request, 'crypto_history.html', {'operations': operations})