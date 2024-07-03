#FROM openjdk:11
#
#ARG JAR_FILE=target/*.jar
#
#COPY ${JAR_FILE} authserver.jar
#
#ENTRYPOINT ["java", "-jar", "/authserver.jar"]
#
#EXPOSE 7777
# Используем базовый образ с Java и средой выполнения Java 11
FROM openjdk:19

# Установка рабочей директории внутри контейнера
WORKDIR /app

# Копируем JAR файл с приложением внутрь контейнера
COPY build/libs/auth-server-0.0.1-SNAPSHOT.jar app.jar

# Определяем команду для запуска приложения в контейнере
CMD ["java", "-jar", "app.jar"]
