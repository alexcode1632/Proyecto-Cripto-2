# Securing documents in a law firm — núcleo criptográfico (avance 3)

Prototipo en Python de los servicios de integridad, no repudio y confidencialidad.

| Archivo | Contenido |
|---|---|
| `crypto_core.py` | Hash SHA-256, firma Ed25519 y cifrado AES-256-GCM |
| `demo_aes.py` | Demostración con un testamento |
| `test_crypto.py` | 7 pruebas unitarias |

## Ejecutar

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python demo_aes.py
python -m pytest -v
```

# Ejecutar con 

source venv/bin/activate
python demo_aes.py
python -m pytest -v

## Flujo (sign-then-encrypt)

1. El abogado firma `SHA-256(documento)` con su llave privada Ed25519.
2. Se genera una llave AES-256 aleatoria y se cifra el documento con AES-GCM (nonce aleatorio de 12 bytes; el id del documento va como dato asociado).
3. Para abrirlo se descifra con la llave y se verifica la firma con la llave pública del firmante.

## Siguiente avance

- Esquema de Shamir *t* de *n* para dividir la llave AES entre cliente y abogados.
- Back-end, base de datos, PKI (certificados X.509) y MFA.
