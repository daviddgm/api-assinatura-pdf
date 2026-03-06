import os
import tempfile
import uuid
import traceback
from flask import Flask, request, send_file
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

app = Flask(__name__)

@app.route('/assinar', methods=['POST'])
def assinar_pdf():
    try:
        if 'pdf' not in request.files or 'p12' not in request.files or 'senha' not in request.form:
            return "Erro: Faltam parâmetros (pdf, p12 ou senha)", 400

        pdf_file = request.files['pdf']
        p12_file = request.files['p12']
        senha = request.form['senha'].encode('utf-8')

        # 1. Desmonta o P12 usando a biblioteca raiz de criptografia (100% à prova de falhas)
        p12_data = p12_file.read()
        try:
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data, 
                senha
            )
        except ValueError as e:
            if "MAC" in str(e) or "password" in str(e).lower():
                return "Erro: Senha do certificado incorreta.", 400
            raise e
            
        # 2. Validação definitiva
        if private_key is None:
            return "Erro: O seu arquivo .p12 não contém chave privada (apenas leitura).", 400

        # 3. Caminhos temporários
        temp_dir = tempfile.gettempdir()
        id_unico = str(uuid.uuid4())[:8]
        pdf_path = os.path.join(temp_dir, f'entrada_{id_unico}.pdf')
        out_path = os.path.join(temp_dir, f'saida_{id_unico}.pdf')
        key_path = os.path.join(temp_dir, f'key_{id_unico}.pem')
        cert_path = os.path.join(temp_dir, f'cert_{id_unico}.pem')
        
        pdf_file.seek(0)
        pdf_file.save(pdf_path)

        # 4. O HACK: Salva a chave e o cert extraídos em formato puro (PEM)
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        with open(cert_path, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        # 5. Carrega o pyHanko a partir dos PEMs puros (Bypass no bug da biblioteca)
        signer = signers.SimpleSigner.load(
            key_file=key_path,
            cert_file=cert_path,
            key_passphrase=None
        )

        # 6. Aplica a assinatura
        with open(pdf_path, 'rb') as doc:
            writer = IncrementalPdfFileWriter(doc)
            nome_campo = 'Assinatura_OSE_' + id_unico
            
            with open(out_path, 'wb') as out_file:
                signers.sign_pdf(
                    writer, 
                    signers.PdfSignatureMetadata(
                        field_name=nome_campo,
                        md_algorithm='sha256'
                    ),
                    signer=signer, 
                    output=out_file
                )

        return send_file(out_path, as_attachment=True, download_name='assinado.pdf', mimetype='application/pdf')

    except Exception as e:
        erro_completo = traceback.format_exc()
        return f"Erro Crítico do Servidor:\n{str(e)}\n\nTraceback Completo:\n{erro_completo}", 500
        
    finally:
        # 7. Limpeza rigorosa para segurança
        if 'pdf_path' in locals() and os.path.exists(pdf_path): os.remove(pdf_path)
        if 'out_path' in locals() and os.path.exists(out_path): os.remove(out_path)
        if 'key_path' in locals() and os.path.exists(key_path): os.remove(key_path)
        if 'cert_path' in locals() and os.path.exists(cert_path): os.remove(cert_path)
