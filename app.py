import os
import tempfile
import uuid
import traceback
from flask import Flask, request, send_file
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.sign.signers import PdfSigner

app = Flask(__name__)

@app.route('/assinar', methods=['POST'])
def assinar_pdf():
    try:
        if 'pdf' not in request.files or 'p12' not in request.files or 'senha' not in request.form:
            return "Erro: Faltam parâmetros (pdf, p12 ou senha)", 400

        pdf_file = request.files['pdf']
        p12_file = request.files['p12']
        senha = request.form['senha'].encode('utf-8')
        
        # --- NOVOS PARÂMETROS RECEBIDOS DO PHP PARA O CARIMBO VISUAL ---
        nome_assinante = request.form.get('nome_assinante', 'Responsável')
        cargo = request.form.get('cargo', '')
        posicao = request.form.get('posicao', '1') # 1=Esquerda, 2=Centro, 3=Direita

        # 1. Desmonta o P12 (Bypass de Segurança)
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
            
        if private_key is None:
            return "Erro: O seu ficheiro .p12 não contém chave privada.", 400

        # 2. Caminhos temporários
        temp_dir = tempfile.gettempdir()
        id_unico = str(uuid.uuid4())[:8]
        pdf_path = os.path.join(temp_dir, f'entrada_{id_unico}.pdf')
        out_path = os.path.join(temp_dir, f'saida_{id_unico}.pdf')
        key_path = os.path.join(temp_dir, f'key_{id_unico}.pem')
        cert_path = os.path.join(temp_dir, f'cert_{id_unico}.pem')
        
        pdf_file.seek(0)
        pdf_file.save(pdf_path)

        # 3. Salva as chaves puras
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        with open(cert_path, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        # 4. Carrega o signer
        signer = signers.SimpleSigner.load(
            key_file=key_path,
            cert_file=cert_path,
            key_passphrase=None
        )

        # --- LÓGICA DO CARIMBO VISUAL ---
        # Define as coordenadas (Box) na folha A4.
        # Largura da folha A4 é aprox 595 pontos. A Altura (Y) começa em 0 na base.
        # 1 = Esquerda (Resp. Contratada)
        if posicao == '1':   
            box = (60, 280, 220, 330)
        # 2 = Centro (Gestor do Contrato)
        elif posicao == '2': 
            box = (220, 280, 380, 330)
        # 3 = Direita (Fiscal do Contrato)
        else:                
            box = (380, 280, 540, 330)

        # 5. Aplica a assinatura e o carimbo
        with open(pdf_path, 'rb') as doc:
            writer = IncrementalPdfFileWriter(doc)
            nome_campo = 'Assinatura_OSE_' + id_unico
            
            # Lê a quantidade de páginas direto da árvore de propriedades (Root) do PDF
            total_paginas = int(writer.prev.root['/Pages']['/Count'])
            ultima_pagina = total_paginas - 1

            # Cria o "quadrado" no ficheiro PDF (invisível até ser carimbado)
            append_signature_field(
                writer,
                SigFieldSpec(
                    sig_field_name=nome_campo,
                    on_page=ultima_pagina,
                    box=box
                )
            )

            # Desenha o texto do carimbo
            texto = f"ASSINADO DIGITALMENTE\nPor: {nome_assinante}\n{cargo}\nData: %(ts)s"
            stamp_style = TextStampStyle(stamp_text=texto)
            border_width=0

            # Prepara o motor de assinatura acoplando o estilo visual e a chave
            pdf_signer = PdfSigner(
                signature_meta=signers.PdfSignatureMetadata(
                    field_name=nome_campo, 
                    md_algorithm='sha256'
                ),
                signer=signer,
                stamp_style=stamp_style
            )
            
            with open(out_path, 'wb') as out_file:
                # A mágica da versão 0.21.0: passamos APENAS o writer e o output!
                # Ele já sabe qual é o in_file internamente.
                pdf_signer.sign_pdf(writer, output=out_file)

        return send_file(out_path, as_attachment=True, download_name='assinado.pdf', mimetype='application/pdf')

    except Exception as e:
        erro_completo = traceback.format_exc()
        return f"Erro Crítico do Servidor:\n{str(e)}\n\nTraceback Completo:\n{erro_completo}", 500
        
    finally:
        if 'pdf_path' in locals() and os.path.exists(pdf_path): os.remove(pdf_path)
        if 'out_path' in locals() and os.path.exists(out_path): os.remove(out_path)
        if 'key_path' in locals() and os.path.exists(key_path): os.remove(key_path)
        if 'cert_path' in locals() and os.path.exists(cert_path): os.remove(cert_path)
