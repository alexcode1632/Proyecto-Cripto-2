# Pruebas unitarias.  Ejecutar:  python -m pytest -v

import pytest
from cryptography.exceptions import InvalidTag

import crypto_core as cc


# ------------------------------------------------------------- AES-256-GCM
def test_aes_ida_y_vuelta():
    llave = cc.generar_llave()
    paquete = cc.cifrar(llave, b"contrato", b"DOC-1")
    assert cc.descifrar(llave, paquete, b"DOC-1") == b"contrato"


def test_aes_nonce_distinto_cada_vez():
    llave = cc.generar_llave()
    assert cc.cifrar(llave, b"x", b"") != cc.cifrar(llave, b"x", b"")


def test_aes_detecta_alteracion():
    llave = cc.generar_llave()
    paquete = bytearray(cc.cifrar(llave, b"contrato", b"DOC-1"))
    paquete[-1] ^= 1
    with pytest.raises(InvalidTag):
        cc.descifrar(llave, bytes(paquete), b"DOC-1")


def test_aes_detecta_cambio_de_id():
    llave = cc.generar_llave()
    paquete = cc.cifrar(llave, b"contrato", b"DOC-1")
    with pytest.raises(InvalidTag):
        cc.descifrar(llave, paquete, b"DOC-2")


# ------------------------------------------------------- SHA-256 y Ed25519
def test_huella_vector_conocido():
    # Vector de prueba estándar de SHA-256 para "abc"
    assert cc.huella(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_firma_valida_e_invalida():
    privada, publica = cc.generar_par_firma()
    firma = cc.firmar(privada, b"testamento")
    assert cc.verificar_firma(publica, b"testamento", firma)
    assert not cc.verificar_firma(publica, b"testamento alterado", firma)


def test_firma_con_otra_llave_no_verifica():
    privada, _ = cc.generar_par_firma()
    _, otra_publica = cc.generar_par_firma()
    assert not cc.verificar_firma(otra_publica, b"doc", cc.firmar(privada, b"doc"))


if __name__ == "__main__":
    pytest.main(["-v", __file__])
