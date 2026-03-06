FROM maven:3.9.6-eclipse-temurin-11 AS build
WORKDIR /app
COPY pom.xml ./
COPY src ./src
RUN mvn -q package

FROM eclipse-temurin:11-jre
WORKDIR /app
COPY --from=build /app/target/cartier-waf-1.0.0.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
