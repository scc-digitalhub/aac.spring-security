# AAC Spring Security
A library for *Spring Security* implementing useful helpers for OAuth2/OIDC authentication and authorization.
Integrates with ``spring-security-oauth2-resource-server``. Developed for AAC integration, can be used with different IdP as long as claims in JWT are AAC-compatible.

## Install

Include the library as a dependency along with spring security resource server.

For example with maven 

```
<dependency>
   <groupId>org.springframework.security</groupId>
   <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>


<dependency>
   <groupId>org.springframework.security</groupId>
   <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>


<dependency>
   <groupId>it.smartcommunitylab</groupId>
   <artifactId>aac.spring-security</artifactId>
   <version>1.0.0</version>
</dependency>

``` 


## Usage

The library offers various features dedicated to:

* token (JWT) validation
* token parsing
* authorities and role mapping
* permission handling

In order to properly adopt the library it is mandatory to activate the OAuth2 resource server support via spring DSL. See the reference documentation at https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2resourceserver

For example, to enable also *jwt* support add the following to a WebSecurityConfigurerAdapter:

```
    @Override
    public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/api/**").authenticated()
                    .and()
                    .oauth2ResourceServer()
                    .jwt();

    }
```  



### JWT Validation

The library offers helpers for *audience* and *revocation* validation.


To define new validators or extend the default spring behaviour, it is necessary to register a new ``@Bean`` acting as ``JWTDecoder``. Within the bean, a ``DelegatingOAuth2TokenValidator`` will execute all the validators in sequence and collect all the errors.

For example:

```
 @Bean
 JwtDecoder jwtDecoder() {
     NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri);

  OAuth2TokenValidator<Jwt> audienceValidator = new JwtAudienceValidator(clientId);
  OAuth2TokenValidator<Jwt> revocationValidator = new JwtRevocationValidator(issuerUri, clientId, clientSecret);

  OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
  OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator,
          revocationValidator);

  jwtDecoder.setJwtValidator(withAudience);

  return jwtDecoder;
 }


```

Do note that is is mandatory to include the default JWT validator via ``createDefaultWithIssuer``, otherwise all the basic JWT checks will be skipped.


#### Audience Validator
The OpenID specification requires client to verify the ``audience`` of tokens by comparing their own ``client_id`` with the values contained within the JWT.
OAuth2 does not enforce such a requirement, since tokens can be treated as *opaque* by clients. When using JWT as *bearers*, it is advisable to apply the same validation as dictated by OpenID spec also for ``access_tokens``.

The ``JWTAudienceValidator`` class can compare the given ``client_id`` with the audiences specified inside the JWT, and raise a validation error if the two don't match.

The application configuration should include the ``client_id`` which should be provided to the class constructor. 

```
OAuth2TokenValidator<Jwt> audienceValidator = new JwtAudienceValidator(clientId);

```


#### Revocation Validator
With JWTs, the idea is to enable clients to *locally* verify tokens, without the need to contact the authorization server. All the check for signature and expiration can be performed locally, and thus determine the token validity. As long as tokens are not expired, they will be considered ``active`` by all parties.

By introducing revocation, we support the scenario where access has been revoked (for example after a security breach). The authorization server can handle the revocation step, and invalidate the token, but all clients *trusting* JWTs won't know about the revocation, and keep accepting the revoked token until it expires.

The usual approach to mitigate this window of opportunity is to reduce the token lifetime to reasonable intervals, which depending on the scenario could be hours or even minutes.

While this works perfectly fine for most scenarios, sometimes we need the ability to use tokens with an extended lifetime (e.g. hours) but at the same time we need to keep a smaller uncertainty window for revoked tokens.

The proposed solution is to leverage *OAuth2 introspection* to check the validity of tokens with the authorization server, partially negating the advantages of JWTs. By contacting the IdP, the client can know the token status *at that precise moment in time*, not at the time of release.


The ``JWTRecovationValidator`` can check JWTs against the OAuth2 introspection endpoint, and establish if they are either valid or inactive. A fully configurable local *cache* will avoid the need to check tokens at each request, reducing the system load and avoid a DoS opportunity. By properly configuring cache duration (or disabling cache), clients can obtain an increased security even when adopting longer lasting access tokens.

In order to configure the class, the application has to provide:

* ``client_id``, ``client_secret`` to access the introspection endpoint
* ``issuer`` 

and eventually

* ``clockSkew`` for JWT expiration validation
* ``cacheDuration`` for local cache duration

For example

```
OAuth2TokenValidator<Jwt> revocationValidator = new JwtRevocationValidator(issuerUri, clientId, clientSecret);
```

### Authorities 





#### Scopes

#### Default User role

#### Default Client role

#### Multitenancy (spaces)


#### Components

### Roles




### Permissions

### Space Permissions


