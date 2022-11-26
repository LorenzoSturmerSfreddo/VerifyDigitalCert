import os
import OpenSSL
import shutil
from cert_chain_resolver.resolver import resolve

store = OpenSSL.crypto.X509Store()

#Esta função adiciona o certificado ROOT à lista de certificados confiáveis. Utilizando desta forma, podemos pegar a CA de qualquer certificado que
#desejarmos da internet e dizer q a CA dele é confíavel;
def addTrustedCertificate():
    path = input("\nCaminho do certificado ROOT:\n")
    if os.path.isfile(path):
        if path.endswith(".crt") or path.endswith(".cer") or path.endswith(".pem"):
            with open(path,'rb') as c:
                chain = resolve(c.read())
                for cert in chain:
                    if cert.is_root:
                        shutil.copy(path, "./trusted/")
                        print("Certificado ROOT adicionado a lista de confiança!")
    else:
        print("\nCertificado não encontrado!")


#Esta função compara o certificado CA para verificar se ele consta na lista de certificados confiáveis;
def validateCertificate():
    path = input("\nCaminho do certificado:\n")
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
                                        for cert_val in chain_cert:
                                            if cert_val.is_root and str(cert) == str(cert_val):
                                                print("\nCertificado confiavel!\n" + str(cert_val))
                                            elif cert_val.is_root and str(cert) != str(cert_val):
                                                print("\nCertificado não confiavel!\n" + str(cert_val))
                            except OpenSSL.crypto.X509StoreContextError as e:
                                print("\nCertificado não confiavel!\n" + cert_val)

    else:
        print("\nCertificado não encontrado!")

opc = 0
while opc != 4:
    print("\n********* Menu *********")
    print("1 -> Adicionar AC ROOT à lista de confiança.")
    print("2 -> Validar confiança de um certificado.")
    print("3 -> Sair.")
    opc = int(input())
    if opc == 1:
        addTrustedCertificate()
    elif opc == 2:
        validateCertificate()
    elif opc == 3:
        break