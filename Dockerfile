FROM docker.phonepe.com:5000/pp-ops-xenial:0.6

RUN \
  apt-get clean && apt-get update && apt-get install -y --no-install-recommends software-properties-common curl

EXPOSE 8080
EXPOSE 8081

ADD target/primer*.jar primer-service.jar

CMD DNS_HOST=`ip r | awk '/default/{print $3}'` && printf "nameserver $DNS_HOST\n" > /etc/resolv.conf  && sleep 15; java -jar -XX:+${GC_ALGO-UseG1GC} -Xms${JAVA_PROCESS_MIN_HEAP-1g} -Xmx${JAVA_PROCESS_MAX_HEAP-1g} primer-service.jar server  server /rosey/config.yml
