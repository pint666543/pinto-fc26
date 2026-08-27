PINTO FC26 — V10 ONLINE
=======================

OBJETIVO
--------
Esta versión está preparada para que jugadores y DTs se registren desde
CUALQUIER PAÍS usando un enlace público.

Ejemplo después de desplegar:
https://pinto-fc26.onrender.com/register.html

Ese mismo enlace se puede enviar por:
- Discord
- WhatsApp
- TikTok
- Instagram
- Messenger
- cualquier navegador móvil

FLUJO
-----
1. El jugador abre /register.html desde su teléfono.
2. Envía su inscripción.
3. La información se guarda en PostgreSQL.
4. Tu panel de Comisionado consulta la misma base de datos.
5. REGISTRATION muestra la solicitud.
6. Tú apruebas/rechazas.
7. Si apruebas al jugador, entra al pool del Draft.
8. Los DTs conectados ven el cambio.

TECNOLOGÍA V10
--------------
- Frontend: HTML/CSS/JavaScript
- Backend: Node.js + Express
- Base de datos online: PostgreSQL
- Sincronización: API central + polling
- Compatible con Render / Railway / otros hosts Node.js

PARA PROBAR EN TU PC
--------------------
1. Instala Node.js LTS.
2. Ejecuta PROBAR_V10_LOCAL.bat.
3. Si DATABASE_URL no está configurada, usa un archivo local temporalmente.

PARA PUBLICAR EN INTERNET
-------------------------
Necesitas:
A) un hosting Node.js (por ejemplo Render o Railway)
B) una base de datos PostgreSQL

En Render:
1. Crea una base de datos PostgreSQL.
2. Crea un Web Service desde esta carpeta/repositorio.
3. Build Command: npm install
4. Start Command: npm start
5. Agrega DATABASE_URL con la URL de PostgreSQL.
6. Render asignará un dominio https público.
7. Comparte:
   https://TU-DOMINIO/register.html

IMPORTANTE
----------
Yo puedo preparar todo el código, pero no puedo crear por mi cuenta una cuenta
de hosting a tu nombre ni publicar usando credenciales que no tengo.

SEGURIDAD
---------
La V10 incluye variable ADMIN_KEY preparada para controles administrativos.
La siguiente evolución recomendada es autenticación real por email/contraseña
para DTs y Comisionado.
