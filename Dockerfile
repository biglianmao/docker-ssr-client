FROM alpine

MAINTAINER storezhang "storezhang@gmail.com"

ENV SSR_DATA="/ssr-data"

EXPOSE 1081

VOLUME ${SSR_DATA}
WORKDIR ${SSR_DATA}

ADD ./polipo/polipo /usr/bin/polipo
ADD ./polipo/config /etc/polipo.conf
ADD ./supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN set -x \
    && echo -e "https://mirrors.ustc.edu.cn/alpine/latest-stable/main\nhttps://mirrors.ustc.edu.cn/alpine/latest-stable/community" > /etc/apk/repositories \
    && apk update \
    && apk --no-cache add su-exec curl py-pip supervisor \
    && chmod 777 /usr/bin/polipo \
    && adduser -S -h ${SSR_DATA} ssr \
    && chown -R ssr "${SSR_DATA}" \
    && chown -R ssr /etc/polipo.conf

COPY ./shadowsocks /opt/shadowsocks

ENTRYPOINT ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
