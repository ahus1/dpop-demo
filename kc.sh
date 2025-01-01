cd ..
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD=admin
export DEBUG=true
keycloak-26.0.7/bin/kc.sh start-dev --features=dpop