FROM nginx:1.27-alpine

WORKDIR /usr/share/nginx/html

COPY index.html ./index.template.html
COPY dashboard.js ./dashboard.js
COPY styles.css ./styles.css
COPY config.js ./config.template.js

ENV API_BASE=""

CMD ["/bin/sh", "-c", "apk add --no-cache envsubst >/dev/null && envsubst '$API_BASE' < index.template.html > index.html && envsubst '$API_BASE' < config.template.js > config.js && exec nginx -g 'daemon off;'"]
