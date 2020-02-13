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

```java
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

```java
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

Do note that is is mandatory to include the default JWT validator via ``createDefaultWithIssuer``, otherwise all the basic JWT checks will be skipped. Furthermore, calling ``JwtDecoders#fromIssuerLocation`` is what invokes the Provider Configuration or Authorization Server Metadata endpoint in order to derive the JWK Set Uri. It is mandatory to derive the basic ``jwtDecoder`` from one the factory to obtain a valid configuration.


#### Audience Validator
The OpenID specification requires client to verify the ``audience`` of tokens by comparing their own ``client_id`` with the values contained within the JWT.
OAuth2 does not enforce such a requirement, since tokens can be treated as *opaque* by clients. When using JWT as *bearers*, it is advisable to apply the same validation as dictated by OpenID spec also for ``access_tokens``.

The ``JWTAudienceValidator`` class can compare the given ``client_id`` with the audiences specified inside the JWT, and raise a validation error if the two don't match.

The application configuration should include the ``client_id`` which should be provided to the class constructor. 

```java
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

```java
OAuth2TokenValidator<Jwt> revocationValidator = new JwtRevocationValidator(issuerUri, clientId, clientSecret);
```

### Authorities 

In Spring Security, a ``GrantedAuthority`` represents an individual privilege granted to the current ``Principal``.
By enriching the security context with a collection of authorities granted to the currently logged user, we obtain the ability to *fine-tune* the authorization handling within the application.

The ``hasAuthority('ABC')`` expression can be used inside *authorization* annotations on methods to check wheter the user has a specific privilege. 

For example, to check *before* executing a method we will use:

```java
   @PreAuthorize("hasAuthority('READ_REGISTRATION')")
   public RegistrationDTO getRegistration(
      ...
   }
```

Or to filter *after* execution the returned values for a given expression:

```java
   @PreAuthorize("hasAuthority('READ_REGISTRATION')")
   @PostFilter("hasPermission(filterObject, 'READ'))
   public List<RegistrationDTO> listRegistration(
      ...
   }
```


See https://docs.spring.io/spring-security/site/docs/5.2.2.RELEASE/reference/htmlsingle/#el-access for detailed documentation on expressions.


In order to properly leverage authorities we need to populate the security context. While legacy approaches can use a dedicated repository local to the application, in a cloud environment it is advisable to properly manage roles and permissions in a more centralized way. 
When using OAuth2/OpenID the *authentication* and *authorization* is managed by an external Identity provider such as AAC.
This scheme can provide the application with additional information regarding user privileges, such as *roles* or *scopes*.

This library provides an easy and customizable way to extract *authorities* information from JWTs, and (if required) map all the data to an application-specific scheme.

Spring provides a dedicated extension point to configure this, a ``JwtTokenConverter``. By implementing a proper method, developer are able to customize the extraction process.

This library provides a custom ``JwtAuthenticationConverter`` able to delegate authorities extraction to a list of specialized classes, in order to compose the desired configuration without having to implement every time a custom method.

```java

    Converter<Jwt, AbstractAuthenticationToken> jwtTokenConverter() {
        return new JwtAuthenticationConverter(
                new JwtComponentAwareAuthoritiesRoleConverter(component),
                new JwtScopeAuthoritiesConverter());
    }
```

In order to enable this custom converter we need to provide it to the httpSecurity DSL, as in :

```java
    @Override
    public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/api/**").authenticated()
                    .and()
                    .oauth2ResourceServer()
                    .jwt()
                    .jwtAuthenticationConverter(jwtTokenConverter());

    }
```  

The following paragraphs document the specialized converters distributed with this library.

#### Scopes
In OAuth2, scopes represent a specific privilege the user has *delegated* to the bearer-carrying application.
Do note that they do not represent a specific permission given *to the user*, but a privilege the user has delegated *to the client* via the ``access_token``.
As such, they can be used by spring applications to represent a subset of the users's ``GrantedAuthorities`` delegated to the current principal.

For example, a scope named ``profile`` represents the delegation of the privilege to access his *profile* a specific user has given to the application. 
Instead, a scope named ``profile.read.all`` could represent the delegation to read all the users' profiles, given that the delegating user has such privilege. If the user does not possess a privilege, he should not be able to delegate it via scopes.


Spring security provides a useful converter which can extract ``scopes`` from a JWT and assign a list of privileges named after the scopes, such as ``SCOPE_<scope>`` (for example ``SCOPE_profile``). 
 
This library extends this behavior and provides a specialized ``ScopeGrantedAuthority`` class, along with a dedicated extractor ``JwtScopeAuthoritiesConverter``. This enables a more specific handling of such privileges, and reduces the risks of confusing them with differently types authorities.
Future versions will also provide a specialized *security expression* ``hasScope`` which will automatically check only the scope-related authorities. For now, a developer can use the generic ``hasAuthority('SCOPE_profile``)`` annotation as an equivalent workaround.

In order to wire the converter we need to provide it to the custom ``JwtAuthenticationConverter``, as in the example:

```java

 Converter<Jwt, AbstractAuthenticationToken> jwtTokenConverter() {
     return new JwtAuthenticationConverter(
             new JwtScopeAuthoritiesConverter());

```     

When configured, the converter will parse the JWT to look for scopes inside the following claims:
* ``scope``
* ``scopes``

For each given scope, it will instantiate the ``ScopeGrantedAuthority`` class, which will expose the following methods:

```java
 public String getScope();
 public String getAuthority();
```

 

Remember to treat scope-derived authorities connected to the current principal identity!

#### Default User role

The ability to check if a user is authenticated is a common requirement for many applications. While the usage of the proper DSL expression can protect externally exposed methods and ensure that anonymous users won't be able to call the endpoints, sometimes it's useful to be able to check the current context within the lower levels.

In order to avoid custom code or the need to introspect the security context, we can assign to any authenticated user a default ``Role``, which can be checked via security expressions everywhere in the code.

The ``JwtDefaultUserAuthorityConverter`` class implements this approach, and grants every valid user a given authority.
By default, this authority is ``ROLE_USER``, but developers are free to change it to any valid privilege by calling the ``setDefaultRole(String defaultRole)`` method.

For example, configure the converter as:

```java

Converter<Jwt, AbstractAuthenticationToken> jwtTokenConverter() {
   JwtDefaultUserAuthorityConverter defaultUserConverter = new JwtDefaultUserAuthorityConverter();
   defaultUserConverter.setDefaultRole('MY_CUSTOM_ROLE');
   return new JwtAuthenticationConverter(defaultUserConverter, new JwtScopeAuthoritiesConverter());

```     

Each valid principal will possess the specific ``GrantedAuthority``:


```
i.s.a.s.p.SpacePermissionEvaluator       : user 17 authorities [ROLE_USER, SCOPE_openid, SCOPE_profile, SCOPE_profile.basicprofile.me, SCOPE_email, SCOPE_user.roles.me]


```


#### Default Client role

OAuth2 provides applications with the ability to directly authenticate *as themselves*, without any user associated. The ``client_credentials`` flow enables applications to directly call resource servers with their own identity, which is not associated to any specific user.

A common requirement for security-oriented applications is the ability to discriminate such access_tokens from the ones given to application by users. Unfortunately, JWTs usually do not specify the type of grant used to obtain them. As such, there is no easy way to detect client tokens.

A viable approach leverages a characteristic of ``audience`` field and the behavior of the most common Idps.
Usually, clients requesting an access_token are identified by a unique ``client_id``, which is also used as one of the *audiences* included in the token.

The specification identifies the client application (by client_id) and marks the recipients by including their ids inside the audience field. Most IdPs will also identify clients by using their unique clientid as ``subject``. 
We can thus leverage those information and derive an identification scheme which:

1. reads the ``sub`` from JWT
2. reads the ``aud`` field 
3. compares the two to identify client_credentials tokens

The possible (alternative) cases are:

1. ``subject`` is not contained within audience, meaning the subject probably identifies a user
2. ``subject`` matches the ``audience``, which is a single string, meaning the token is released to the same identity as the resource server inspecting the token. This could be the case for a frontend+backend application where the two share the same identity.
3. ``subject`` is contained as one of the audiences inside ``aud`` array. This is the case where the client accessing the resource server has a dedicated, separated identity.

Both cases #2 and #3 identify a client credentials access.

The library offers a ``JwtClientAuthoritiesConverter`` which applies the described algorithm and assigns a customizable authority when it detects a client access.

By default, the converter assigns the ``ROLE_CLIENT``. Developers can configure the role by setting the desired authority via ``setClientRole(String clientRole)``.

```java

Converter<Jwt, AbstractAuthenticationToken> jwtTokenConverter() {
   JwtClientAuthorityConverter clientConverter = new JwtClientAuthorityConverter();
   clientConverter.setClientRole('MY_CUSTOM_CLIENT_ROLE');
   return new JwtAuthenticationConverter(clientConverter);

```

Furthermore, by setting the ``clientId`` we can instruct the converter to assign an additional *client identity role* when the subject matches the client id.    

```java

Converter<Jwt, AbstractAuthenticationToken> jwtTokenConverter() {
   JwtClientAuthorityConverter clientConverter = new JwtClientAuthorityConverter(clientId);
   clientConverter.setClientRole('MY_CUSTOM_CLIENT_ROLE');
   clientConverter.setClientIdRole('MY_CUSTOM_CLIENT_IDENTITY_ROLE');
   return new JwtAuthenticationConverter(clientConverter);

```




#### Multitenancy (spaces)

When the Idp supports multiple tenants, we can write applications which properly support them by defining a ``namespace`` as a unique space dedicated to a single ``tenant``.

In AAC, such spaces are defined in a flexible and powerful way, either by ``component`` or by ``organization``.
This library supports any configuration, by providing developers with a specific ``NamespacedGrantedAuthority`` and the relative ``JwtNamespaceAwareAutoritiesRoleConverter``.

The idea is to define each privilege gained for a specific tenant as a *namespaced* one, which will be evaluated by the application only when the request matches the specific ``namespace``.

For example, a role defined in AAC as ``components/myapplication/tenant123:ROLE_MANAGER`` can be interpreted as a role:
* restricted to the component ``[myapplication]``
* available only for the namespace ``[tenant123]``

The ``JwtNamespaceAwareAutoritiesRoleConverter`` will translate this claim from JWT to a ``NamespacedGrantedAuthority`` with:
* ``space=tenant123``
* ``role=ROLE_MANAGER``

The authority will output 
```
getAuthority() = "tenant123:ROLE_MANAGER"
```

At any given time, consumers will be able to cast back the granted authority and directly inspect the space and/or role.
For example, the ``SpacePermissionEvaluator`` extracts the information to check for space roles. 


#### Components

AAC supports a complex multi-tenancy environment, where any given component has its own tenants.
This way, we can fine tune the creation of namespaces and restrict roles and accesses to specific scopes.

The library offers a ``JWTComponentAwareAuthoritiesRoleConverter``, which is a specialization of the namespace-aware converter, supporting the filtering of spaces and roles given a specific *component*.

By adopting the converter, an application will be able to filter out all the roles derived from the global mapping which do not match its own component *identificator*.
This will ensure that there will be no overlapping between components and that all the instructions which handle roles and authorities, and thus permissions, will act in accordance to the privileges granted inside the *component space*. Otherwise, every check will need to evaluate the matching by itself.

For example, consider the following roles expressed via JWT claims:

```
roles": [
    "components/resourcemanager/ROLE_ADMIN",
    "components/vault/tenant123:ROLE_USER",
    "components/goodtables/tenant123:ROLE_PROVIDER",

```

If our application is identified by ``goodtables``, we are interested only in roles defined within our namespace.

A naive implementation could look at the presence of the ``ROLE_ADMIN`` privilege to enable access to a protected method, and ignore the space. This way, the user could obtain a privilege which he does not possess.

Another possible error can derive from a naive parsing of roles and namespaces, which could derive a representation as
``[tenant123:ROLE_USER, tenant123:ROLE_PROVIDER]`` for the ``vault`` component, by mistakenly including roles assigned to the same user, same namespace but different component ``goodtables``.

By using the ``JWTComponentAwareAuthoritiesRoleConverter`` the authorities will be filtered right at extraction point, and all the subsequent checks will find only those matching the component, sanitized as needed.

For example, the result for ``vault``:

```java
    Converter<Jwt, AbstractAuthenticationToken> jwtTokenConverter() {
        return new JwtAuthenticationConverter(
                new JwtComponentAwareAuthoritiesRoleConverter('vault'));
    }

```

will be a list of authorities such as ``[tenant123:ROLE_USER]``, instead of something like ``[components/vault/tenant123:ROLE_USER, components/goodtables/tenant123:ROLE_PROVIDER]``.




### Roles
Technically speaking, ``Roles`` in Spring Security are just a specified *authority* whose name starts with ``ROLE_*``, for example ``ROLE_USER``. 
By adopting this library, we will instead look at ``Roles`` as a collection of *privileges* on entities. 

The idea is to translate a given *role* to a list of *actions* which can be performed on a specific kind of *object*. 

For example, the role ``ROLE_ADMIN`` could represent the set of actions ``{READ_ALL,READ,WRITE,WRITE_ALL}`` on the entity ``Registration``.

This approach enables the definition of roles which encompass the application-specific needs and are manageable via external Idp, without bringing the application logic and all the specific mappings to a centralized system. The advantages are the clear definition of privileges, the flexibility, the ability to share roles between components and the ease of administration.


In order to adopt the approach, a developer needs to write an implementation of the following interface for any given entity managed by the application.

```java
public interface RoleActionConverter<T> {

    public List<String> extractRoles(Authentication authentication, T entity);

    public List<String> allowedRoles(String action);

    public List<String> grantsActions(String role);
}
```

The implementation can be as specific (or generic) as needed. The library does not impose any specific naming or scheme.

* ``extractRoles`` should extract additional roles based on the user and the specific entity, for example ``ROLE_OWNER``
* ``allowedRoles`` lists all the roles allowed to perform a specific action
* ``grantsActions`` lists all the actions a given role can perform

Depending on the usage, the developer can implement any or all the methods. Do note that, when implementing both ``allowedRoles`` and ``grantsActions`` it is advisable to keep the two in sync, to avoid generating a split view on permissions.


#### DefaultRoleActionConverter

The library provides a default converter, implementing the given interface, which can be used as-is or as a base for custom development.

The ``DefaultRoleActionConverter<T>`` simply maps any given action to a single role (defaults to ``ROLE_USER``), and translates any role to an *empty list of actions*.

Developers are free to derive or specialize this class and implement their own logic, either generic (i.e. handling only roles <=> actions mapping) or specialized (evaluating in addition the specific entity ``<T>``).

For example, a common requirement is the ability to identify the *owners* of a specific resource, to grant them additional privileges in extension to the ones derived from their role.

Suppose that we have a simple entity ``Resource`` as :

```java

public class Resource {
   public String ownerId;
}

```

A custom ``ResourceRoleActionConverter`` could be:

```java
public class ResourceRoleActionConverter<Resource> implements RoleActionConverter {

    @Override
    public List<String> extractRoles(Authentication authentication, Resource entity) {
      if (entity.ownerId.equals(authentication.getName())) {
         return Collections.singletonList("ROLE_OWNER"); 
      }
      
      return Collections.emptyList();
    }

    @Override
    public List<String> allowedRoles(String action) {
        if("delete".equals(action)) {
         return Collections.singletonList("ROLE_OWNER");         
        }
        
        return Collections.singletonList("ROLE_USER");
    }
}


```

When checking permissions, we will thus be able to filter the ``delete`` action and enable only owners to perform it. 
This approach is more flexible and extensible than leveraging the basic expression system. 
Furthermore, it promotes a proper separation of concerns between ACLs and roles, useful when adopting RBAC. In case roles are not needed, the developer can avoid implementing the classes and still leverage the expression system to check *authorities* and *generic constraints*. 

### Permissions

In Spring security, permissions represents the ability to specify authorization constraints on entities. 
See https://docs.spring.io/spring-security/site/docs/5.2.2.RELEASE/reference/htmlsingle/#el-permission-evaluator for details.

Developers need to implement a custom ``PermissionEvaluator`` which will translate constraints required by annotations to specific checks on the ``Authentication`` object and eventually grant or deny the action.

The interface is:

```java

boolean hasPermission(Authentication authentication, Object targetDomainObject,
                            Object permission);

boolean hasPermission(Authentication authentication, Serializable targetId,
                            String targetType, Object permission);
                            
```

When joined with ``Roles`` as previously explained, we can develop complex RBAC systems able to discriminate access and authorizations.

The basic idea is to map the ``target`` to an entity class, and the ``permission`` to an object the user wants to perform on the specific instance of the entity.

For example:

```java
hasPermission(filterObject, 'read')
public getResource(String id) {...}
```

will invoke the permission evaluator ``hasPermission(authentication, filterObject, 'write')``.
If we include a custom ``RoleActionConverter`` we will be able to discover that only users with the ``ROLE_MANAGER`` are able to perform this action.

```java

 @Override
 public List<String> allowedRoles(String action) {
     if("write".equals(action)) {
      return Collections.singletonList("ROLE_MANAGER");         
     }
     
     return Collections.singletonList("ROLE_USER");
 }

```


The following code inside the permissionEvaluator will check the presence of the required role:

```java
List<String> roles = authentication.getAuthorities().stream().map(a -> (a.getAuthority()))
                .collect(Collectors.toList());
List<String> allowedRoles = roleActionConverter.allowedRoles(action);

return CollectionUtils.containsAny(roles, allowedRoles);

```


It is up to the developer to implement the application specific logic and mappings. 

 

In order to wire in an evaluator, it is necessary to provide Spring with a ``GlobalMethodSecurityConfiguration``.
For example:

```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {

    @Value("${spaces.enabled}")
    private boolean enabled;

    @Value("${spaces.list}")
    private List<String> spaces;

    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
        methodSecurityExpressionHandler.setPermissionEvaluator(permissionEvaluator());
        return methodSecurityExpressionHandler;
    }

    @Bean
    public PermissionEvaluator permissionEvaluator() {
        if (enabled) {
            return new SpacePermissionEvaluator(spaces);
        } else {
            return new PermitAllPermissionEvaluator();
        }
    }
}



```

Obviously, when using more than one evaluator for handling more than one resource *type*, it is mandatory to properly handle the distribution of requests to the various evaluators, or to write a global *generic* evaluator which either delegates the requests, or performs the checks independently of the type.

Given that every implementation should check the object type, and return ``false`` for unsupported objects, a simple strategy can interrogate each evaluator one-by-one and return ``true`` if anyone response positively. More sophisticated approaches can be designed to satisfy complex requirements.

Spring security offers a ``DenyAllPermissionEvaluator`` which will simply deny every request and block any access.
This library offers the complementary ``PermitAllPermissionEvaluator``, which will approve any request, useful for development and testing environments.

Another evaluator available is ``SpacePermissionEvaluator``, which will handle the multi-tenancy authorization requirements.


#### Space Permissions

In order to provide a *ready-to-use* solution for multi-tenancy, the library offers a ``SpacePermissionEvaluator`` able to check the permission <=> roles mapping in a multitenant environment as defined by AAC ``spaces``.


The idea is to leverage the authorities extractors provided for JWTs and obtain a list of roles prefixed with the ``namespace`` which identifies the specific tenant.

For example ``[tenant123:ROLE_PROVIDER, tenant456:ROLE_MEMBER]``.

By implementing a custom ``RoleActionConverter``, or by leveraging the default one, we can then adopt the ``SpacePermissionEvaluator`` and check if a given user has the privilege of executing an action within the space of a tenant.

For example:

```java
    @PreAuthorize("hasPermission(#spaceId, 'SPACE', 'READ')")
    public RegistrationDTO getRegistration(String spaceId,...) {}
```

will check via permission evaluator if the currently logged user has any role supporting the action ``READ`` within the namespace identified by ``spaceId``. 

The implementation will check any given authority prefixed with ``<spaceId>:`` for a supported role, and also consider all top-level roles as matching. This way, a superuser with role ``ROLE_ADMIN`` will be able to act as admin in any space.

 
Furthermore, the class supports the definition of a list of allowed spaces, which enables administrators in restricting access to the application to only a subset of the tenants defined in the environment. 








