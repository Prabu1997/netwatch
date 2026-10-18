FROM node:20-alpine
RUN apk add --no-cache iproute2 iptables ip6tables tcpdump
WORKDIR /app
COPY server.js intel.js ./
COPY lib ./lib
COPY public ./public
ENV HOST=127.0.0.1 PORT=8080
ENV DATA_DIR=/app/data
VOLUME /app/data
CMD ["node","server.js"]
