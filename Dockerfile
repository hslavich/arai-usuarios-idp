FROM hub.siu.edu.ar:5005/siu/expedientes/arai-usuarios/idp:v3.0.8
LABEL org.opencontainers.image.source=https://github.com/hslavich/arai-usuarios-idp

COPY Varios.php /usr/local/app/core/src/SIU/AraiUsuarios/Util/Varios.php
