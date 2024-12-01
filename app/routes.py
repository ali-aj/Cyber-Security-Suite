from flask import Blueprint, render_template, request, jsonify
from .utils import buffer_overflow, brute_force, crypto_toolkit, ids, security_analyzer
from .utils.elgamal import validate_elgamal_params, encrypt, decrypt, generate_keys
from . import db
import json
import logging

logger = logging.getLogger(__name__)

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/xss_scan', methods=['GET', 'POST'])
def xss_scan():
    if request.method == 'POST':
        url = request.form['url']
        results = security_analyzer.xss_scan(url)
        
        # Save scan result to database
        scan_result = ScanResult(url=url, scan_type='XSS', result=json.dumps(results))
        db.session.add(scan_result)
        db.session.commit()
        
        return jsonify(results)
    return render_template('xss_scan.html')

@main.route('/rsa', methods=['GET', 'POST'])
def rsa():
    if request.method == 'POST':
        operation = request.form.get('operation')
        text = request.form.get('text')
        result = crypto_toolkit.perform_operation(operation, text, None)
        return jsonify(result)
    return render_template('rsa.html')

@main.route('/aes', methods=['GET', 'POST'])
def aes():
    if request.method == 'POST':
        operation = request.form.get('operation')
        text = request.form.get('text')
        key = request.form.get('key')
        result = crypto_toolkit.perform_operation(operation, text, key)
        return jsonify(result)
    return render_template('aes.html')

@main.route('/des', methods=['GET', 'POST'])
def des():
    if request.method == 'POST':
        operation = request.form.get('operation')
        text = request.form.get('text')
        key = request.form.get('key')
        result = crypto_toolkit.perform_operation(operation, text, key)
        return jsonify(result)
    return render_template('des.html')

@main.route('/hill_cipher', methods=['GET', 'POST'])
def hill_cipher():
    if request.method == 'POST':
        operation = request.form.get('operation')
        text = request.form.get('text')
        key = request.form.get('key')
        result = crypto_toolkit.perform_operation(operation, text, key)
        return jsonify(result)
    return render_template('hill_cipher.html')


@main.route('/validate_primitive_root', methods=['POST'])
def validate_primitive_root():
    try:
        prime = int(request.form.get('prime'))
        root = int(request.form.get('root'))
        result = validate_elgamal_params(prime, root, 1)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"valid": False, "error": str(e)})
    

@main.route('/elgamal', methods=['GET', 'POST'])
def elgamal():
    if request.method == 'POST':
        try:
            operation = request.form.get('operation')
            logger.info(f"ElGamal operation: {operation}")
            logger.info(f"Form data: {request.form}")

            if operation == 'encrypt':
                message = request.form.get('message')
                prime = int(request.form.get('prime'))
                root = int(request.form.get('primitive-root'))
                private_key = int(request.form.get('private-key'))
                
                # Validate parameters
                validation = validate_elgamal_params(prime, root, private_key)
                if not validation["valid"]:
                    return jsonify({"error": validation["error"]})
                
                # Generate public key
                public_key = generate_keys(prime, root, private_key)
                
                # Encrypt message
                c1, c2 = encrypt(message, prime, root, public_key)
                
                return jsonify({
                    "public_key": str(public_key),
                    "c1": str(c1),
                    "c2": [str(x) for x in c2]
                })
                
        except ValueError as e:
            logger.error(f"ElGamal operation error: {str(e)}")
            return jsonify({"error": str(e)})
            
    return render_template('elgamal.html')

@main.route('/diffie_hellman', methods=['GET', 'POST'])
def diffie_hellman():
    if request.method == 'POST':
        result = crypto_toolkit.perform_operation('diffie_hellman', None, None)
        return jsonify(result)
    return render_template('diffie_hellman.html')

@main.route('/crypto', methods=['GET', 'POST'])
def crypto():
    if request.method == 'POST':
        operation = request.form.get('operation')
        text = request.form.get('text')
        key = request.form.get('key')

        result = crypto_toolkit.perform_operation(operation, text, key)

        if 'result' in result:
            # Save crypto operation to database
            crypto_op = CryptoOperation(
                operation_type=operation,
                input_text=text,
                output_text=result['result']
            )
            try:
                db.session.add(crypto_op)
                db.session.commit()
            except Exception as db_error:
                db.session.rollback()
                logger.error(f"Database Error: {str(db_error)}")
                return jsonify({"error": "Database error occurred."}), 500
            return jsonify(result)
        else:
            # Handle error case
            error_message = result.get('error', 'Unknown error occurred.')
            return jsonify({"error": error_message}), 400

    return render_template('crypto.html')

@main.route('/ids', methods=['GET', 'POST'])
def intrusion_detection():
    if request.method == 'POST':
        log_data = request.form['log_data']
        results = ids.analyze(log_data)
        
        # Save IDS log to database
        ids_log = IDSLog(log_data=log_data, analysis_result=json.dumps(results))
        db.session.add(ids_log)
        db.session.commit()
        
        return jsonify(results)
    return render_template('ids.html')

@main.route('/buffer_overflow', methods=['GET', 'POST'])
def buffer_overflow_sim():
    if request.method == 'POST':
        input_data = request.form['input_data']
        results = buffer_overflow.simulate(input_data)
        return jsonify(results)
    return render_template('buffer_overflow.html')

@main.route('/brute_force', methods=['GET', 'POST'])
def brute_force_sim():
    if request.method == 'POST':
        target = request.form['target']
        results = brute_force.simulate(target)
        return jsonify(results)
    return render_template('brute_force.html')

@main.route('/scan_history')
def scan_history():
    scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    return render_template('scan_history.html', scans=scans)

@main.route('/ids_logs')
def ids_logs():
    logs = IDSLog.query.order_by(IDSLog.timestamp.desc()).all()
    return render_template('ids_logs.html', logs=logs)

@main.route('/crypto_history')
def crypto_history():
    operations = CryptoOperation.query.order_by(CryptoOperation.timestamp.desc()).all()
    return render_template('crypto_history.html', operations=operations)

