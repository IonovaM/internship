#FROM openjdk:17.0.2-jdk-slim-buster
FROM adoptopenjdk/openjdk11:alpine-jre
ARG JAR_FILE=????????
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","/app.jar"]