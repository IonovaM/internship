FROM openjdk:19
LABEL authors="lelmon"

WORKDIR /app

COPY build/libs/auth-server-0.0.1-SNAPSHOT.jar app.jar

CMD ["java", "-jar", "app.jar"]