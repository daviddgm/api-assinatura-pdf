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
    # Lemos o .p12 direto para a memória. Muito mais rápido e seguro contra corrupção.
    p12_data = request.files['p12'].read() 
    senha = request.form['senha'].encode('utf-8')

    if len(p12_data) == 0:
        return "Erro: O arquivo .p12 chegou vazio na API.", 400

    # 2. Preparamos caminhos seguros para o PDF (usando o diretório temp do Linux)
    temp_dir = tempfile.gettempdir()
    id_unico = str(uuid.uuid4())[:8]
    pdf_path = os.path.join(temp_dir, f'entrada_{id_unico}.pdf')
    out_path = os.path.join(temp_dir, f'saida_{id_unico}.pdf')
    
    try:
        # Salva o PDF original no disco
        pdf_file.save(pdf_path)
        
        # 3. Carrega o certificado da memória
        signer = signers.SimpleSigner.load_pkcs12(p12_data, senha)

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

        # 5. Devolve o arquivo e já avisa o navegador que é um PDF
        return send_file(out_path, as_attachment=True, download_name='assinado.pdf', mimetype='application/pdf')

    except Exception as e:
        erro_msg = str(e)
        # 6. Intercepta o erro da chave privada e traduz para português
        if "get_signature_mechanism_for_digest" in erro_msg or "NoneType" in erro_msg:
            return "Erro: O seu certificado .p12 é inválido para assinatura. Ele não possui a 'Chave Privada' embutida. Exporte ele novamente do Windows marcando 'Sim, exportar a chave privada'.", 400
        
        return f"Erro interno ao assinar: {erro_msg}", 500
        
    finally:
        # 7. Limpeza (Sempre limpa o servidor do Render para não lotar o disco)
        if os.path.exists(pdf_path): os.remove(pdf_path)
        if os.path.exists(out_path): os.remove(out_path)
