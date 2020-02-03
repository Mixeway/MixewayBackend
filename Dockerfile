FROM openjdk:8u232-jdk-stretch
VOLUME /tmp
ARG JAR_FILE
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom", "-Dspring.profiles.active=${PROFILE}", "$JAVA_OPTS","-jar", "/app.jar"]