# Multi-stage so `docker build -f server/Dockerfile .` works from a clean checkout with no local
# JDK or Gradle. Build context is the repository root, because the wrapper and the version catalog
# live there.
FROM eclipse-temurin:17-jdk AS build
WORKDIR /workspace

# Copy the build definition first so dependency resolution is cached independently of source
# changes — editing a Java file must not re-download the world.
COPY gradlew ./
COPY gradle gradle
COPY settings.gradle build.gradle gradle.properties ./
COPY server/build.gradle server/
RUN ./gradlew --no-daemon dependencies --configuration runtimeClasspath > /dev/null 2>&1 || true

COPY server/src server/src
RUN ./gradlew --no-daemon :server:bootJar

FROM eclipse-temurin:17-jre AS runtime
WORKDIR /app

# Unprivileged: nothing in this image needs root, and an identity service is a poor place to make
# an exception.
RUN groupadd --system authgate && useradd --system --gid authgate --no-create-home authgate
USER authgate

COPY --from=build --chown=authgate:authgate /workspace/server/build/libs/authgate-server.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
