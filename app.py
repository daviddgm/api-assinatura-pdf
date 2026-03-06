import os
import tempfile
import uuid
from flask import Flask, request, send_file
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

app = Flask(__name__)

@app.route('/assinar', methods=['POST'])
def assinar_pdf():
    # 1. Verifica os parâmetros
    if 'pdf' not in request.files or 'p12' not in request.files or 'senha' not in request.form:
        return "Erro: Faltam parâmetros (pdf, p12 ou senha)", 400

    pdf_file = request.files['pdf']
    p12_file = request.files['p12']
    senha = request.form['senha'].encode('utf-8')

    # 2. Caminhos seguros para salvar os arquivos no diretório temporário
    temp_dir = tempfile.gettempdir()
    id_unico = str(uuid.uuid4())[:8]
    
    pdf_path = os.path.join(temp_dir, f'entrada_{id_unico}.pdf')
    p12_path = os.path.join(temp_dir, f'cert_{id_unico}.p12')
    out_path = os.path.join(temp_dir, f'saida_{id_unico}.pdf')
    
    try:
        # Salva o PDF e o Certificado no disco da API
        pdf_file.save(pdf_path)
        p12_file.save(p12_path)
        
        # 3. Passa o CAMINHO do arquivo (e não a memória) para o pyHanko
        signer = signers.SimpleSigner.load_pkcs12(p12_path, senha)

        # 4. Aplica a assinatura incremental
        with open(pdf_path, 'rb') as doc:
            writer = IncrementalPdfFileWriter(doc)
            nome_campo = 'Assinatura_OSE_' + id_unico
            
            with open(out_path, 'wb') as out_file:
                signers.sign_pdf(
                    writer, 
                    signers.PdfSignatureMetadata(field_name=nome_campo),
                    signer=signer, 
                    output=out_file
                )

        # 5. Devolve o arquivo
        return send_file(out_path, as_attachment=True, download_name='assinado.pdf', mimetype='application/pdf')

    except Exception as e:
        erro_msg = str(e)
        # 6. Traduções de erros comuns
        if "get_signature_mechanism_for_digest" in erro_msg or "NoneType" in erro_msg:
            return "Erro: O seu certificado .p12 não possui a 'Chave Privada' embutida.", 400
        if "mac verify failure" in erro_msg.lower():
            return "Erro: A senha do certificado está incorreta.", 400
            
        return f"Erro interno ao assinar: {erro_msg}", 500
        
    finally:
        # 7. Limpeza rigorosa dos 3 arquivos para não encher o disco do Render
        if os.path.exists(pdf_path): os.remove(pdf_path)
        if os.path.exists(p12_path): os.remove(p12_path)
        if os.path.exists(out_path): os.remove(out_path)
