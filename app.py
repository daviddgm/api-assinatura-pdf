import os
import tempfile
import uuid
import traceback
from flask import Flask, request, send_file
from cryptography.hazmat.primitives.serialization import pkcs12
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

app = Flask(__name__)

@app.route('/assinar', methods=['POST'])
def assinar_pdf():
    try:
        # 1. Verifica os parâmetros
        if 'pdf' not in request.files or 'p12' not in request.files or 'senha' not in request.form:
            return "Erro: Faltam parâmetros (pdf, p12 ou senha)", 400

        pdf_file = request.files['pdf']
        p12_file = request.files['p12']
        senha = request.form['senha'].encode('utf-8')

        # 2. Lê o P12 direto da memória
        p12_data = p12_file.read()
        
        try:
            # Desmonta o P12 usando a biblioteca raiz de criptografia (à prova de falhas)
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data, 
                senha
            )
        except ValueError as e:
            if "MAC" in str(e) or "password" in str(e).lower():
                return "Erro: Senha do certificado incorreta.", 400
            raise e
            
        # Validação verdadeira e definitiva da chave privada
        if private_key is None:
            return "Erro REAL: O seu arquivo .p12 não contém chave privada. Ele é apenas para leitura.", 400

        # 3. Monta o Signer do pyHanko manualmente com as peças extraídas
        signer = signers.SimpleSigner(
            signing_cert=certificate,
            signing_key=private_key
        )

        # 4. Caminhos temporários para o PDF
        temp_dir = tempfile.gettempdir()
        id_unico = str(uuid.uuid4())[:8]
        pdf_path = os.path.join(temp_dir, f'entrada_{id_unico}.pdf')
        out_path = os.path.join(temp_dir, f'saida_{id_unico}.pdf')
        
        pdf_file.seek(0)
        pdf_file.save(pdf_path)

        # 5. Aplica a assinatura (Forçando o SHA-256 para o pyHanko não se perder)
        with open(pdf_path, 'rb') as doc:
            writer = IncrementalPdfFileWriter(doc)
            nome_campo = 'Assinatura_OSE_' + id_unico
            
            with open(out_path, 'wb') as out_file:
                signers.sign_pdf(
                    writer, 
                    signers.PdfSignatureMetadata(
                        field_name=nome_campo,
                        md_algorithm='sha256' # <-- A correção do NoneType estava aqui!
                    ),
                    signer=signer, 
                    output=out_file
                )

        # 6. Devolve o arquivo
        return send_file(out_path, as_attachment=True, download_name='assinado.pdf', mimetype='application/pdf')

    except Exception as e:
        # Se falhar agora, teremos o relatório forense completo
        erro_completo = traceback.format_exc()
        return f"Erro Crítico do Servidor:\n{str(e)}\n\nTraceback Completo:\n{erro_completo}", 500
        
    finally:
        if 'pdf_path' in locals() and os.path.exists(pdf_path): os.remove(pdf_path)
        if 'out_path' in locals() and os.path.exists(out_path): os.remove(out_path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
