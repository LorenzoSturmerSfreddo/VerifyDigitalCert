import os
import OpenSSL
import shutil
from cert_chain_resolver.resolver import resolve

store = OpenSSL.crypto.X509Store()

#Esta função não é necessária pois podemos fazer a comparação dos certificados dentro da função de validação;
"""
def loadTrusted():
    certificados = os.listdir("./trusted/")
    for it in certificados:
        with open("./trusted/" + it, "rb") as c:
            chain = resolve(c.read())
            for cert in chain:
                if cert.is_root:
                    store.add_cert(cert)
"""

#Esta função adiciona o certificado ROOT à lista de certificados confiáveis. Utilizando desta forma, podemos pegar a CA de qualquer certificado que
#desejarmos da internet e dizer q a CA dele é confíavel;
def addTrustedCertificate():
    path = input("Insira o caminho do certificado raiz:\n")
    if os.path.isfile(path):
        if path.endswith(".crt") or path.endswith(".cer") or path.endswith(".pem"):
            with open(path,'rb') as c:
                chain = resolve(c.read())
                for cert in chain:
                    if cert.is_root:
                        shutil.copy(path, "./trusted/")
    else:
        print("Arquivo não encontrado")


#Esta função compara o certificado CA para verificar se ele consta na lista de certificados confiáveis;
def validateCertificate():
    path = input("Insira o caminho do arquivo:\n")
    if os.path.isfile(path):
        if path.endswith(".crt") or path.endswith(".cer") or path.endswith(".pem"):
            if path.endswith(".crt") or path.endswith(".cer") or path.endswith(".pem"):
                with open(path, 'rb') as c:
                    chain = resolve(c.read())
                    for cert in chain:
                        if cert.is_root:
                            try:
                                certificados = os.listdir("./trusted/")
                                for it in certificados:
                                    with open("./trusted/" + it, "rb") as trusted:
                                        chain_cert = resolve(trusted.read())
                                        for cert_val in chain:
                                            if cert_val.is_root and cert_val == cert:
                                                print("Certificado confiavel")
                            except OpenSSL.crypto.X509StoreContextError as e:
                                print("Certificado não confiavel")
                                print(e)
    else:
        print("Arquivo não encontrado")

#loadTrusted()
opc = 0
while opc != 4:
    print()
    print("--------- Validar confiança de certificados ---------")
    print("1 - Adicionar ACR")
    print("2 - Validar confiança de certificado")
    print("3 - Sair")
    opc = int(input())
    print()
    if opc == 1:
        addTrustedCertificate()
    elif opc == 2:
        validateCertificate()
    elif opc == 3:
        break