# Этап сборки
FROM openjdk:19 AS build
WORKDIR /app
COPY ../notification .
RUN ./gradlew clean build

# Этап выполнения
FROM openjdk:19-jdk-slim
LABEL authors="lelmon"
WORKDIR /app
RUN microdnf install -y telnet iputils openssl
COPY --from=build /app/build/libs/notification-0.0.1-SNAPSHOT.jar app.jar
CMD ["java", "-jar", "app.jar"]
