# Research logging — v0.3.0

Esta versión añade un registro forense automático de cada ejecución.

## Archivos generados

Por cada sesión se crean dos archivos con el mismo identificador:

- `research_YYYYMMDD_HHMMSS_<id>.log`: formato legible.
- `research_YYYYMMDD_HHMMSS_<id>.jsonl`: un objeto JSON por evento para análisis reproducible.

Cada evento incluye número secuencial, hora UTC, tiempo transcurrido, hilo, candidato, tipo de evento y detalles.

## Qué registra

Entre otros pasos:

- versión de la aplicación, Python y plataforma;
- ruta y SHA-256 del ZIP de entrada;
- descubrimiento de cada pareja `seed.seco` + `passphrase.json`;
- ruta exacta de ambos archivos dentro del ZIP/carpeta;
- tamaños y huellas SHA-256 de los archivos;
- validación del contenedor SECO y checksum;
- parámetros scrypt `N`, `r`, `p`, memoria estimada y `maxmem`;
- origen de la credencial usada para el descifrado;
- inicio/fin de scrypt y tiempos;
- autenticación AES-256-GCM del blob key y del payload;
- tamaños del payload y descompresión;
- longitud de entropía y número de palabras BIP-39;
- comprobación de que el mnemonic reconstruido reproduce el seed almacenado;
- hit/miss de la caché de derivación;
- cada ruta BIP-44 probada y la dirección Ethereum pública derivada;
- comparación con la dirección objetivo;
- candidato exacto que produjo una coincidencia;
- errores con tipo, mensaje y traceback;
- resumen final de la sesión.

## Punto importante para este experimento

La aplicación **no solicita la contraseña de interfaz de Exodus**. Para cada candidato compatible lee el `passphrase.json` emparejado que está dentro del propio backup/export y lo utiliza para procesar `seed.seco`.

El log deja esto explícito con campos como:

- `credential_source`
- `passphrase_path`
- `operator_wallet_password_prompted: false`

Así puede distinguirse experimentalmente entre "no introducir la contraseña de Exodus" y "no disponer de material de descifrado": son situaciones diferentes.

## Secretos

El log no escribe en claro:

- mnemonic BIP-39;
- valor de `passphrase`;
- seed BIP-39;
- entropía;
- claves privadas;
- claves KDF/AES.

Para trazabilidad se utilizan tamaños, metadatos y algunas huellas SHA-256. Las direcciones Ethereum y las rutas de derivación sí aparecen porque son datos de verificación.

Aunque no contiene los secretos en claro, el log debe tratarse como material sensible de investigación antes de publicarlo, porque revela estructura de archivos, rutas locales, hashes y direcciones públicas.
