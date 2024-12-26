# Этап сборки
FROM openjdk:17 AS build
WORKDIR /app
ARG PROJECT_NAME
RUN microdnf install -y findutils
COPY . .
RUN ./gradlew clean build

# Этап выполнения
FROM openjdk:17-jdk-slim
LABEL authors="lelmon"
WORKDIR /app
ARG PROJECT_NAME
#RUN microdnf install -y telnet iputils openssl
COPY --from=build /app/build/libs/${PROJECT_NAME}-0.0.1-SNAPSHOT.jar app.jar
CMD ["java", "-jar", "app.jar"]
