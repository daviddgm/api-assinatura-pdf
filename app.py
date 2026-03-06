import os
import tempfile
import uuid
from flask import Flask, request, send_file
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

app = Flask(__name__)

@app.route('/assinar', methods=['POST'])
def assinar_pdf():
    if 'pdf' not in request.files or 'p12' not in request.files or 'senha' not in request.form:
        return "Faltam parâmetros (pdf, p12 ou senha)", 400

    pdf_file = request.files['pdf']
    p12_file = request.files['p12']
    senha = request.form['senha'].encode('utf-8')

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_pdf, \
         tempfile.NamedTemporaryFile(delete=False, suffix='.p12') as tmp_p12, \
         tempfile.NamedTemporaryFile(delete=False, suffix='_assinado.pdf') as tmp_out:
        
        pdf_file.save(tmp_pdf.name)
        p12_file.save(tmp_p12.name)
        
        try:
            signer = signers.SimpleSigner.load_pkcs12(tmp_p12.name, senha)

            with open(tmp_pdf.name, 'rb') as doc:
                writer = IncrementalPdfFileWriter(doc)
                nome_campo = 'Assinatura_OSE_' + str(uuid.uuid4())[:8]
                
                with open(tmp_out.name, 'wb') as out_file:
                    signers.sign_pdf(
                        writer, 
                        signers.PdfSignatureMetadata(field_name=nome_campo),
                        signer=signer, 
                        out=out_file
                    )

            return send_file(tmp_out.name, as_attachment=True, download_name='assinado.pdf', mimetype='application/pdf')

        except Exception as e:
            return f"Erro ao assinar: {str(e)}", 500
            
        finally:
            if os.path.exists(tmp_pdf.name): os.remove(tmp_pdf.name)
            if os.path.exists(tmp_p12.name): os.remove(tmp_p12.name)

# Não precisamos mais do app.run() aqui no final.
