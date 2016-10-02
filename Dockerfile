FROM ubuntu:14.04

RUN \
  apt-get clean && apt-get update && apt-get install -y --no-install-recommends software-properties-common \
  && add-apt-repository ppa:webupd8team/java \
  && apt-get update \
  && echo debconf shared/accepted-oracle-license-v1-1 select true |  debconf-set-selections \
  && echo debconf shared/accepted-oracle-license-v1-1 seen true |  debconf-set-selections \
  && apt-get install -y --no-install-recommends oracle-java8-installer curl

RUN echo Asia/Kolkata | sudo tee /etc/timezone && sudo dpkg-reconfigure --frontend noninteractive tzdata

EXPOSE 8080
EXPOSE 8081

VOLUME /var/log/primer

ADD config/docker/config.yml config.yml
ADD target/primer*.jar primer-service.jar

CMD sh -c "curl -X GET --header 'Accept: application/x-yaml' 'http://'${CONFIG_SERVICE_HOST_PORT}'/v1/phonepe/primer/'${CONFIG_ENV} > ${CONFIG_ENV}.yml && sleep 15; java -jar -XX:+${GC_ALGO-UseG1GC} -Xms${JAVA_PROCESS_MIN_HEAP-1g} -Xmx${JAVA_PROCESS_MAX_HEAP-1g} primer-service.jar server ${CONFIG_ENV}.yml"
