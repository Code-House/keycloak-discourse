# syntax=docker/dockerfile:1

FROM quay.io/keycloak/keycloak:22.0.5 as build

ENV KC_DB=postgres
ENV KC_HTTP_RELATIVE_PATH=/

WORKDIR /opt/keycloak

# Install custom providers
COPY --link --chown=1000 extension/idp/target/idp-*.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

### Development
FROM build as development

USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]

### production
FROM quay.io/keycloak/keycloak:22.0.5 as production

COPY --link --from=build /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]
