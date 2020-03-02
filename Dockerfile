FROM maven:3.6-jdk-8 as maven
WORKDIR /app
COPY ./pom.xml ./pom.xml
RUN mvn dependency:go-offline -B
COPY ./src ./src

RUN mvn package -DskipTests && cp target/mixeway-*.jar app.jar

FROM openjdk:8-jre-alpine
LABEL maintainer="gsiewruk@gmail.com"
WORKDIR /app
COPY --from=maven /app/app.jar ./app.jar

ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom", "-Dspring.profiles.active=${PROFILE}","-jar", "/app/app.jar"]