# Investigación de recuperación Exodus BIP-39

Herramienta local y reproducible para la **recuperación autorizada y verificación de wallets Exodus BIP-39**.

## Novedades de v0.2.0

- Recuperación BIP-39 para tamaños de entropía válidos, incluido **256 bits / 24 palabras**.
- Procesamiento paralelo configurable de múltiples backups.
- Reducción automática de workers cuando `scrypt` necesita mucha memoria.
- Gestión explícita de `hashlib.scrypt(maxmem=...)` para evitar que el límite implícito de OpenSSL descarte contenedores Exodus legítimos con parámetros de memoria elevados.
- Verificación Ethereum mediante múltiples rutas BIP-44, cuentas e índices de dirección, además de rutas personalizadas.
- Caché en memoria para evitar repetir derivaciones criptográficas cuando distintos backups contienen material seed repetido.
- Interfaz gráfica responsiva con procesamiento en segundo plano y barra de progreso.
- Modo rápido opcional para detección de direcciones desde CSV, claramente marcado como resultado parcial.
- Exportación local cifrada mediante scrypt y AES-256-GCM.
- Suite automatizada ampliada de 31 a **40 pruebas superadas**.

## Idea central

El proyecto distingue entre dos clases de información:

- los backups locales cifrados de Exodus pueden contener material secreto causal suficiente para reconstruir una frase mnemónica;
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
→ análisis e integridad SECO
→ scrypt con gestión explícita de memoria
→ descifrado AES-256-GCM
→ payload seed de Exodus
→ entropía / frase BIP-39
→ verificación del seed BIP-39
→ BIP-32/BIP-44
→ rutas Ethereum configurables
→ clave pública secp256k1
→ dirección Ethereum
→ comparación con la dirección objetivo
```

La frase solo se muestra después de comprobar tanto la consistencia del seed BIP-39 recuperado como la coincidencia de una dirección Ethereum derivada con el objetivo indicado por el operador.

## Longitudes BIP-39

La aplicación admite los tamaños estándar implementados:

- 128 bits → 12 palabras
- 160 bits → 15 palabras
- 192 bits → 18 palabras
- 224 bits → 21 palabras
- 256 bits → **24 palabras**

## Rutas Ethereum

La interfaz puede generar rutas:

```text
m/44'/60'/account'/0/index
```

con cuenta e índice máximos configurables, además de admitir rutas personalizadas.

## Corrección scrypt/OpenSSL

Algunos contenedores seguros de Exodus pueden utilizar parámetros `scrypt` que requieren bastante memoria. Depender del límite implícito de OpenSSL puede producir `memory limit exceeded` y hacer que un backup legítimo parezca incompatible.

La versión 0.2.0 calcula y proporciona explícitamente `maxmem` a `hashlib.scrypt()` dentro del límite de seguridad configurado. Cuando los parámetros requieren mucha RAM, también reduce automáticamente el número de workers paralelos.

Esto es una corrección de compatibilidad y funcionamiento; no reduce los parámetros criptográficos de scrypt.

## Caché y rendimiento

Cuando varios backups históricos contienen el mismo material seed recuperado, la aplicación evita repetir derivaciones posteriores mediante una caché temporal en memoria. La caché existe durante la ejecución y no sustituye el modelo de seguridad local.

## Exportación cifrada

El resultado recuperado puede exportarse opcionalmente de forma cifrada. La exportación utiliza derivación de clave con scrypt y cifrado autenticado AES-256-GCM.

La frase recuperada debe seguir tratándose como información altamente sensible.

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

1. Instala Python 3.11 o posterior compatible con las dependencias.
2. Marca `Add Python to PATH`.
3. Descarga o clona el repositorio.
4. Ejecuta `run_windows.bat`.

## Validación de v0.2.0

La suite se ejecuta con:

```text
python -m pytest -v
```

Resultado de validación:

```text
40 passed
```

Las pruebas públicas usan vectores sintéticos o públicos y no incluyen frases, claves privadas ni backups reales.

## Publicación y archivado

GitHub se utiliza como repositorio público de código y desarrollo.

La versión **v0.1.0** está archivada permanentemente mediante Zenodo:

**DOI v0.1.0:** [10.5281/zenodo.22858136](https://doi.org/10.5281/zenodo.22858136)

La versión **v0.2.0** ha sido archivada permanentemente mediante Zenodo:

**DOI v0.2.0:** [10.5281/zenodo.22861160](https://doi.org/10.5281/zenodo.22861160)

Las etiquetas históricas no se reescriben.

## Citación

Los metadatos se encuentran en [`CITATION.cff`](CITATION.cff).

Cita recomendada para la versión archivada actual:

> Sánchez Expósito, T. (2026). *Exodus BIP-39 Recovery Research* (Versión 0.2.0) [Software]. Zenodo. https://doi.org/10.5281/zenodo.22861160

ORCID: [0009-0006-3715-8516](https://orcid.org/0009-0006-3715-8516)

## Licencia

Este proyecto se distribuye bajo la **Apache License 2.0**. Consulta [`LICENSE`](LICENSE).

Copyright © 2026 Tomás Sánchez Expósito.
