# genieacs-sim (MIT) CWMP CPE simulator, black-box test peer only.
FROM node:22-alpine
ARG SIM_REF=be391cab6d586a1e98cd65e57f7cd7ae715be791
RUN apk add --no-cache git \
 && git clone https://github.com/genieacs/genieacs-sim.git /sim \
 && cd /sim && git checkout ${SIM_REF} && npm install --omit=dev
WORKDIR /sim
ENTRYPOINT ["./genieacs-sim"]
