FROM openjdk:19
LABEL authors="lelmon"

WORKDIR /app

RUN microdnf install -y iputils
RUN microdnf install -y telnet
RUN microdnf install -y iputils openssl

COPY build/libs/notification-0.0.1-SNAPSHOT.jar app.jar

CMD ["java", "-jar", "app.jar"]
