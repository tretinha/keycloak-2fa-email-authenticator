FROM maven:3.9.9-eclipse-temurin-17

COPY . .

RUN mvn -B package --file pom.xml