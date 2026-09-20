# Investigación de recuperación Exodus BIP-39

Herramienta local y reproducible para la **recuperación autorizada y verificación de wallets Exodus BIP-39**.

## Idea central

El proyecto distingue entre dos clases de información:

- los backups locales cifrados de Exodus pueden contener material secreto causal suficiente para reconstruir una mnemonic;
- los datos públicos de blockchain suelen servir como **verificadores** de candidatos, no como una función inversa de BIP-39.

## Funcionamiento

La aplicación analiza copias autorizadas que contengan pares compatibles:

```text
seed.seco
passphrase.json
```

y verifica el resultado contra una dirección Ethereum pública conocida.

Cadena de comprobación:

```text
backup Exodus
→ descifrado SECO
→ entropía BIP-39
→ mnemonic
→ seed BIP-39
→ BIP-32/BIP-44
→ m/44'/60'/0'/0/0
→ clave pública secp256k1
→ dirección Ethereum
→ comparación con la dirección objetivo
```

La frase sólo se muestra cuando la dirección derivada coincide exactamente.

## Seguridad

Este repositorio **no contiene** datos reales de la wallet utilizada durante la investigación:

- no hay frase de recuperación real;
- no hay clave privada real;
- no hay `seed.seco` real;
- no hay `passphrase.json` real;
- no hay ZIP privados de Exodus;
- no hay CSV reales del usuario.

Ejecuta siempre la recuperación localmente en un ordenador de confianza.

## Instalación en Windows

1. Instala Python 3.11 o 3.12.
2. Marca `Add Python to PATH`.
3. Descarga/clona el repositorio.
4. Ejecuta `run_windows.bat`.

## Publicación

GitHub se utilizará como repositorio público de código y desarrollo. El archivado versionado y los DOI se gestionarán mediante **Zenodo**.
