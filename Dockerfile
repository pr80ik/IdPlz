FROM public.ecr.aws/docker/library/eclipse-temurin:21-jre

##################
# install web-app
##################
ARG JAR_FILE=target/id-plz-0.0.1-SNAPSHOT.jar
COPY ${JAR_FILE} /app/app.jar

VOLUME /tmp

WORKDIR /app
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
