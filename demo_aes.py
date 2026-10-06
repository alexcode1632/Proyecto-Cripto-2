# Demostración: hash SHA-256, firma Ed25519 y cifrado AES-256-GCM.

from cryptography.exceptions import InvalidTag

import crypto_core as cc

testamento = b"Testamento de Juan Perez: lego mi casa a mi hija Maria."
id_doc = b"DOC-2026-0001"

print("=== 1. Hash y firma ===")
privada, publica = cc.generar_par_firma()
firma = cc.firmar(privada, testamento)
print(f"SHA-256:        {cc.huella(testamento).hex()[:32]}...")
print(f"Firma Ed25519:  {firma.hex()[:32]}...")

print("\n=== 2. Cifrar y descifrar con AES-256-GCM ===")
llave = cc.generar_llave()
paquete = cc.cifrar(llave, testamento, id_doc)
print(f"Cifrado:        {paquete.hex()[:32]}... ({len(paquete)} bytes)")
print("Descifrado:    ", cc.descifrar(llave, paquete, id_doc).decode())

print("\n=== 3. Descifrar con una llave incorrecta ===")
try:
    cc.descifrar(cc.generar_llave(), paquete, id_doc)
    print("ERROR: no debió descifrarse")
except InvalidTag:
    print("Rechazado: llave incorrecta (InvalidTag)")

print("\n=== 4. Alterar un byte del documento cifrado ===")
alterado = bytearray(paquete)
alterado[20] ^= 0x01
try:
    cc.descifrar(llave, bytes(alterado), id_doc)
    print("ERROR: no debió descifrarse")
except InvalidTag:
    print("Rechazado: GCM detectó la modificación (InvalidTag)")

print("\n=== 5. Verificar firma sobre un documento falsificado ===")
falso = b"Testamento de Juan Perez: lego mi casa a mi vecino Pedro."
print("Firma valida (original):   ", cc.verificar_firma(publica, testamento, firma))
print("Firma valida (falsificado):", cc.verificar_firma(publica, falso, firma))
