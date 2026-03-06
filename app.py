import os
import tempfile
import uuid
import traceback
from flask import Flask, request, send_file
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

        temp_dir = tempfile.gettempdir()
        id_unico = str(uuid.uuid4())[:8]
        pdf_path = os.path.join(temp_dir, f'entrada_{id_unico}.pdf')
        p12_path = os.path.join(temp_dir, f'cert_{id_unico}.p12')
        out_path = os.path.join(temp_dir, f'saida_{id_unico}.pdf')

        # Salva os arquivos corretamente no disco para o pyHanko ler nativamente
        pdf_file.save(pdf_path)
        p12_file.save(p12_path)

        # 1. Carrega o certificado usando o método oficial do pyHanko
        signer = signers.SimpleSigner.load_pkcs12(p12_path, senha)

        # 2. Aplica a assinatura
        with open(pdf_path, 'rb') as doc:
            writer = IncrementalPdfFileWriter(doc)
            nome_campo = 'Assinatura_OSE_' + id_unico

            with open(out_path, 'wb') as out_file:
                signers.sign_pdf(
                    writer, 
                    signers.PdfSignatureMetadata(
                        field_name=nome_campo,
                        md_algorithm='sha256' # <-- A verdadeira solução para o erro NoneType!
                    ),
                    signer=signer, 
                    output=out_file
                )

        return send_file(out_path, as_attachment=True, download_name='assinado.pdf', mimetype='application/pdf')

    except Exception as e:
        erro_completo = traceback.format_exc()
        if "mac verify failure" in str(e).lower():
            return "Erro: A senha do certificado está incorreta.", 400
            
        return f"Erro Crítico do Servidor:\n{str(e)}\n\nTraceback Completo:\n{erro_completo}", 500
        
    finally:
        if 'pdf_path' in locals() and os.path.exists(pdf_path): os.remove(pdf_path)
        if 'p12_path' in locals() and os.path.exists(p12_path): os.remove(p12_path)
        if 'out_path' in locals() and os.path.exists(out_path): os.remove(out_path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
