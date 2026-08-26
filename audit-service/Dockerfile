# Built from the repository root so the reactor can resolve the shared `common` module:
#   docker build -f audit-service/Dockerfile .
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

# Copy the POMs first and prime the dependency cache. Source changes then rebuild without
# re-downloading the world, which is the difference between a 20-second and a 4-minute image build.
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY common/pom.xml common/pom.xml
COPY identity-service/pom.xml identity-service/pom.xml
COPY authz-service/pom.xml authz-service/pom.xml
COPY audit-service/pom.xml audit-service/pom.xml
RUN chmod +x mvnw && ./mvnw -B -q -pl audit-service -am dependency:go-offline

COPY common/src common/src
COPY audit-service/src audit-service/src
RUN ./mvnw -B -pl audit-service -am -DskipTests package

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Non-root: the service needs no privileges, so it should not run with any.
RUN addgroup -S trust && adduser -S trust -G trust
COPY --from=build /workspace/audit-service/target/audit-service-*-exec.jar app.jar
USER trust

EXPOSE 8083
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
