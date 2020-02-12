package it.smartcommunitylab.aac.security.jwt;

import java.net.URI;
import java.nio.charset.Charset;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.AbstractMap;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

public class JwtRevocationValidator implements OAuth2TokenValidator<Jwt> {

    public final OAuth2Error error = new OAuth2Error("invalid_token", "The token is inactive", null);

    private static final Duration DEFAULT_CLOCK_SKEW = Duration.of(60, ChronoUnit.SECONDS);
    private static final Duration DEFAULT_CACHE_INTERVAL = Duration.of(60, ChronoUnit.SECONDS);
    private static final ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {
    };
    private static final RestTemplate rest = new RestTemplate();

    private final String clientId;
    private final String clientSecret;

    private Duration cacheInterval;
    private Duration clockSkew;
    private Clock clock = Clock.systemUTC();

    private URI introspectionURI;

    private Map<String, AbstractMap.SimpleImmutableEntry<Instant, Boolean>> cache = new HashMap<>();

    public JwtRevocationValidator(String issuer, String clientId, String clientSecret) {
        Assert.hasText(issuer, "issuer cannot be empty");
        Assert.hasText(clientId, "clientId cannot be empty");
        Assert.hasText(clientSecret, "clientSecret cannot be empty");

        this.clientId = clientId;
        this.clientSecret = clientSecret;

        this.cacheInterval = DEFAULT_CACHE_INTERVAL;
        this.clockSkew = DEFAULT_CLOCK_SKEW;

        Map<String, Object> configuration = JwtDecoderProviderConfigurationUtils
                .getConfigurationForOauthIssuerLocation(issuer);
        Assert.notNull(configuration.get("introspection_endpoint"), "introspection_endpoint can not be null");
        this.introspectionURI = URI.create(configuration.get("introspection_endpoint").toString());
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String token = jwt.getTokenValue();
        Instant expiry = jwt.getExpiresAt();

        // validate jwt expire, no reason to check those
        if (expiry != null) {
            if (Instant.now(this.clock).minus(clockSkew).isAfter(expiry)) {
                return OAuth2TokenValidatorResult.failure(error);
            }
        }

        boolean isActive = false;

        // validate against cache if present
        Optional<Boolean> isValid = checkCache(token);
        if (isValid.isPresent()) {
            isActive = isValid.get().booleanValue();
        } else {
            // check against introspection and save
            isActive = isEndpointActive(token);
            setCache(token, isActive);
        }

        if (isActive) {
            return OAuth2TokenValidatorResult.success();
        } else {
            return OAuth2TokenValidatorResult.failure(error);
        }

    }

    private synchronized Optional<Boolean> checkCache(String token) {
        if (cache.containsKey(token)) {
            // check cache expire
            AbstractMap.SimpleImmutableEntry<Instant, Boolean> entry = cache.get(token);
            Instant expiry = entry.getKey();
            if (Instant.now(this.clock).minus(cacheInterval).isBefore(expiry)) {
                return Optional.of(entry.getValue());
            } else {
                // purge expired
                cache.remove(token);
            }

        }

        return Optional.empty();
    }

    private synchronized void setCache(String token, boolean active) {
        Instant expiry = Instant.now(this.clock);
        cache.put(token, new AbstractMap.SimpleImmutableEntry<>(expiry, Boolean.valueOf(active)));
    }

    private boolean isEndpointActive(String token) {
        try {
            // build basic auth for client
            String auth = clientId + ":" + clientSecret;
            byte[] encodedAuth = Base64.getEncoder().encode(
                    auth.getBytes(Charset.forName("UTF-8")));
            String authHeader = "Basic " + new String(encodedAuth);

            // call introspection endpoint
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, authHeader);
            // request json
            headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);

            // post as form data
            MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
            map.add("token", token);
            map.add("token_type_hint", "access_token");
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<MultiValueMap<String, String>>(map,
                    headers);

            ResponseEntity<Map<String, Object>> response = rest.exchange(introspectionURI,
                    HttpMethod.POST, entity, typeReference);

            return Boolean.parseBoolean(response.getBody().get("active").toString());
        } catch (RuntimeException e) {
            return false;
        }
    }

    public void setCacheInterval(Duration cacheInterval) {
        Assert.notNull(cacheInterval, "cacheInterval cannot be null");
        this.cacheInterval = cacheInterval;
    }

    public void setClockSkew(Duration clockSkew) {
        Assert.notNull(clockSkew, "clockSkew cannot be null");
        this.clockSkew = clockSkew;
    }
}
