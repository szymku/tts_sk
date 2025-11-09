# Security, API Design, Performance & DevOps Patterns: PHP vs. Go

**Part 4 of "Backend Design Patterns: PHP vs. Go"**

This document covers cross-cutting concerns that span all layers and services—security hardening, API design principles, performance optimization, and DevOps practices. These patterns complement the foundational patterns from earlier parts:

- [Part 1: GoF Design Patterns](backend-design-patterns-php-vs-go.md)
- [Part 2: Modern Backend & Microservice Patterns](microservices-patterns-php-vs-go.md)
- [Part 3: System Architecture Patterns](system-architecture-patterns-php-vs-go.md)
- [Part 5: Testing Patterns](testing-patterns-php-vs-go.md)

---

## Table of Contents

1. [Introduction & Context](#introduction--context)
2. [Security Patterns](#security-patterns)
   - [Authentication & Authorization](#authentication--authorization)
   - [Input Validation & Sanitization](#input-validation--sanitization)
   - [CSRF Protection](#csrf-protection)
   - [Rate Limiting](#rate-limiting)
   - [Secret Management](#secret-management)
   - [Security Headers & HTTPS](#security-headers--https)
3. [API Design Patterns](#api-design-patterns)
   - [RESTful API Design](#restful-api-design)
   - [GraphQL Patterns](#graphql-patterns)
   - [API Versioning](#api-versioning)
   - [Pagination Patterns](#pagination-patterns)
   - [Error Response Patterns](#error-response-patterns)
   - [Hypermedia & Self-Documenting APIs](#hypermedia--self-documenting-apis)
4. [Performance Patterns](#performance-patterns)
   - [Caching Strategies](#caching-strategies)
   - [Database Optimization](#database-optimization)
   - [Async Processing](#async-processing)
   - [Connection Pooling](#connection-pooling)
   - [Response Compression](#response-compression)
5. [DevOps & Deployment Patterns](#devops--deployment-patterns)
   - [CI/CD Pipelines](#cicd-pipelines)
   - [Deployment Strategies](#deployment-strategies)
   - [Infrastructure as Code](#infrastructure-as-code)
   - [Container Orchestration](#container-orchestration)
   - [Feature Flags](#feature-flags)
6. [Cross-Pattern Integration](#cross-pattern-integration)
7. [Pattern Selection Guide](#pattern-selection-guide)
8. [Conclusion](#conclusion)
9. [Continue the Series](#continue-the-series)
10. [References](#references)

---

## Introduction & Context

**Cross-cutting concerns** affect all parts of your application—authentication touches every endpoint, caching improves performance across services, API design shapes client integration, and deployment practices determine reliability.

Unlike structural patterns (Part 3) that organize code, or distributed patterns (Part 2) that coordinate services, cross-cutting patterns establish **quality attributes**:

```mermaid
flowchart TB
    Foundation[Part 1: GoF Patterns<br/>Code-level design]
    Distributed[Part 2: Microservices<br/>Service coordination]
    Architecture[Part 3: System Architecture<br/>Application structure]
    CrossCutting[Part 4: Cross-Cutting<br/>Quality attributes]
    Testing[Part 5: Testing<br/>Quality assurance]

    Foundation --> Architecture
    Distributed --> Architecture
    Architecture --> CrossCutting
    CrossCutting --> Testing

    CrossCutting --> Security[Security]
    CrossCutting --> API[API Design]
    CrossCutting --> Performance[Performance]
    CrossCutting --> DevOps[DevOps & Deployment]
```

**Why Part 4?**

- Parts 1-3 focus on *structure*; this part ensures that structure is **secure, well-designed, performant, and deployable**.
- Security vulnerabilities, clunky APIs, performance bottlenecks, and deployment failures often stem from missing cross-cutting patterns—not architectural flaws.
- PHP and Go have different ecosystems for these concerns (frameworks vs. libraries), requiring tailored approaches.

---

## Security Patterns

> **Quick Reference — Security Patterns 🔒**
> - `JWT/Session Auth`: Choose token-based for APIs, session-based for traditional web apps.
> - `RBAC`: Implement role-based access control for complex authorization.
> - `Input Validation`: Validate all inputs; sanitize outputs to prevent XSS/SQLi.
> - `CSRF Protection`: Use tokens for state-changing operations.
> - `Rate Limiting`: Protect against abuse with token bucket or sliding window.
> - `Secret Management`: Never commit secrets; use vaults or encrypted stores.
> - `Security Headers`: Enable CSP, HSTS, X-Frame-Options to harden responses.

### Authentication & Authorization

#### JWT vs Session-Based Auth

**Summary**: Authentication verifies identity; authorization determines permissions. Session-based stores state on server; JWT is stateless with signed tokens.

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant DB
    participant Cache

    Note over Client,Cache: Session-Based Auth
    Client->>Server: POST /login (credentials)
    Server->>DB: Verify credentials
    DB-->>Server: User data
    Server->>Cache: Store session data
    Server-->>Client: Set-Cookie: session_id
    Client->>Server: GET /api/profile (Cookie)
    Server->>Cache: Lookup session
    Cache-->>Server: Session data
    Server-->>Client: User profile

    Note over Client,Cache: JWT Auth
    Client->>Server: POST /login (credentials)
    Server->>DB: Verify credentials
    DB-->>Server: User data
    Server-->>Client: JWT token (signed)
    Client->>Server: GET /api/profile (Authorization: Bearer JWT)
    Server->>Server: Verify signature
    Server-->>Client: User profile
```

**PHP Example (Symfony + JWT)**

```php
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AuthController
{
    public function __construct(
        private JWTTokenManagerInterface $jwtManager,
        private UserPasswordHasherInterface $passwordHasher
    ) {}

    public function login(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $user = $this->userRepository->findOneBy(['email' => $data['email']]);

        if (!$user || !$this->passwordHasher->isPasswordValid($user, $data['password'])) {
            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        $token = $this->jwtManager->create($user);

        return new JsonResponse(['token' => $token]);
    }
}

// Protect routes with Security attribute
#[Route('/api/profile', methods: ['GET'])]
#[IsGranted('IS_AUTHENTICATED_FULLY')]
class ProfileController
{
    public function show(#[CurrentUser] UserInterface $user): JsonResponse
    {
        return new JsonResponse([
            'id' => $user->getId(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles()
        ]);
    }
}
```

**Go Example (JWT with jwt-go)**

```go
import (
    "github.com/golang-jwt/jwt/v5"
    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/bcrypt"
    "time"
)

type Claims struct {
    UserID uint   `json:"user_id"`
    Email  string `json:"email"`
    jwt.RegisteredClaims
}

func LoginHandler(c *gin.Context) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Invalid request"})
        return
    }

    user := findUserByEmail(req.Email) // Assume this function exists
    if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
        c.JSON(401, gin.H{"error": "Invalid credentials"})
        return
    }

    claims := &Claims{
        UserID: user.ID,
        Email:  user.Email,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, _ := token.SignedString([]byte("your-secret-key"))

    c.JSON(200, gin.H{"token": tokenString})
}

// JWT Middleware
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        if tokenString == "" {
            c.JSON(401, gin.H{"error": "Missing token"})
            c.Abort()
            return
        }

        tokenString = strings.TrimPrefix(tokenString, "Bearer ")

        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte("your-secret-key"), nil
        })

        if err != nil || !token.Valid {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Set("user_id", claims.UserID)
        c.Next()
    }
}
```

**When to Use:**

| Scenario | Recommendation |
| --- | --- |
| RESTful APIs, mobile apps | JWT (stateless, scalable) |
| Traditional web apps | Session-based (simpler, server-side revocation) |
| Microservices | JWT (no shared session store needed) |
| Need immediate logout | Session-based (or use JWT with blacklist) |

#### Role-Based Access Control (RBAC)

**Summary**: Grant permissions based on roles rather than individual users. Users inherit permissions from assigned roles.

```mermaid
graph LR
    User1[User: Alice] --> RoleAdmin[Role: Admin]
    User2[User: Bob] --> RoleEditor[Role: Editor]
    User3[User: Charlie] --> RoleViewer[Role: Viewer]

    RoleAdmin --> PermWrite[write]
    RoleAdmin --> PermRead[read]
    RoleAdmin --> PermDelete[delete]

    RoleEditor --> PermWrite
    RoleEditor --> PermRead

    RoleViewer --> PermRead
```

**PHP Example (Symfony Voter)**

```php
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class PostVoter extends Voter
{
    const EDIT = 'edit';
    const DELETE = 'delete';

    protected function supports(string $attribute, mixed $subject): bool
    {
        return in_array($attribute, [self::EDIT, self::DELETE]) && $subject instanceof Post;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        if (!$user instanceof User) {
            return false;
        }

        $post = $subject;

        return match($attribute) {
            self::EDIT => $this->canEdit($post, $user),
            self::DELETE => $this->canDelete($post, $user),
            default => false,
        };
    }

    private function canEdit(Post $post, User $user): bool
    {
        // Admin can edit any post; editor can edit own posts
        return in_array('ROLE_ADMIN', $user->getRoles()) || $post->getAuthor() === $user;
    }

    private function canDelete(Post $post, User $user): bool
    {
        // Only admins can delete
        return in_array('ROLE_ADMIN', $user->getRoles());
    }
}

// Usage in controller
#[Route('/posts/{id}/edit', methods: ['PUT'])]
class EditPostController
{
    public function __invoke(Post $post, Request $request): JsonResponse
    {
        $this->denyAccessUnlessGranted('edit', $post);

        // Edit logic here
        return new JsonResponse(['status' => 'updated']);
    }
}
```

**Go Example (Casbin)**

```go
import (
    "github.com/casbin/casbin/v2"
    "github.com/gin-gonic/gin"
)

// model.conf
// [request_definition]
// r = sub, obj, act
//
// [policy_definition]
// p = sub, obj, act
//
// [role_definition]
// g = _, _
//
// [policy_effect]
// e = some(where (p.eft == allow))
//
// [matchers]
// m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act

// policy.csv
// p, admin, post, write
// p, admin, post, delete
// p, editor, post, write
// p, viewer, post, read
// g, alice, admin
// g, bob, editor

func setupAuthorization() *casbin.Enforcer {
    enforcer, _ := casbin.NewEnforcer("model.conf", "policy.csv")
    return enforcer
}

func AuthorizeMiddleware(enforcer *casbin.Enforcer) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := c.GetString("user_email") // Set by auth middleware
        resource := c.Param("resource")
        action := c.Request.Method

        allowed, _ := enforcer.Enforce(user, resource, action)
        if !allowed {
            c.JSON(403, gin.H{"error": "Forbidden"})
            c.Abort()
            return
        }

        c.Next()
    }
}
```

**Trade-offs:**

| Aspect | Symfony Voter | Casbin (Go) |
| --- | --- | --- |
| Flexibility | High (custom logic in voters) | Medium (policy language) |
| External Management | Requires code changes | Policies in CSV/DB |
| Performance | Fast (in-memory) | Fast (cached policies) |
| Complexity | Low learning curve | Steeper (policy syntax) |

---

### Input Validation & Sanitization

**Summary**: Validate all inputs to prevent injection attacks (SQL injection, XSS, command injection). Never trust client data.

**Common Vulnerabilities:**

1. **SQL Injection**: Malicious SQL in user input
2. **Cross-Site Scripting (XSS)**: Injecting JavaScript into pages
3. **Command Injection**: Executing OS commands via input
4. **Path Traversal**: Accessing files outside allowed directories

**PHP Example (Symfony Validator)**

```php
use Symfony\Component\Validator\Constraints as Assert;

class CreateUserRequest
{
    #[Assert\NotBlank]
    #[Assert\Email]
    public string $email;

    #[Assert\NotBlank]
    #[Assert\Length(min: 8, max: 255)]
    #[Assert\PasswordStrength(minScore: Assert\PasswordStrength::STRENGTH_MEDIUM)]
    public string $password;

    #[Assert\NotBlank]
    #[Assert\Regex(pattern: '/^[a-zA-Z0-9_]+$/', message: 'Username can only contain letters, numbers, and underscores')]
    #[Assert\Length(min: 3, max: 20)]
    public string $username;

    public static function fromRequest(Request $request): self
    {
        $data = json_decode($request->getContent(), true);
        $dto = new self();
        $dto->email = $data['email'] ?? '';
        $dto->password = $data['password'] ?? '';
        $dto->username = $data['username'] ?? '';
        return $dto;
    }
}

class UserController
{
    public function create(Request $request, ValidatorInterface $validator): JsonResponse
    {
        $dto = CreateUserRequest::fromRequest($request);

        $errors = $validator->validate($dto);
        if (count($errors) > 0) {
            return new JsonResponse([
                'errors' => array_map(fn($e) => [
                    'field' => $e->getPropertyPath(),
                    'message' => $e->getMessage()
                ], iterator_to_array($errors))
            ], 400);
        }

        // Use parameterized queries (Doctrine ORM does this automatically)
        $user = new User($dto->email, $dto->password, $dto->username);
        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return new JsonResponse(['id' => $user->getId()], 201);
    }
}

// XSS Prevention: Twig auto-escapes by default
// {{ user.bio }} is automatically escaped
// {{ user.bio|raw }} disables escaping (use with caution!)
```

**Go Example (validator/v10)**

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/go-playground/validator/v10"
    "regexp"
)

type CreateUserRequest struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8,max=255"`
    Username string `json:"username" validate:"required,min=3,max=20,alphanum"`
}

func CreateUser(c *gin.Context) {
    var req CreateUserRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Invalid JSON"})
        return
    }

    validate := validator.New()
    if err := validate.Struct(req); err != nil {
        errors := make([]map[string]string, 0)
        for _, err := range err.(validator.ValidationErrors) {
            errors = append(errors, map[string]string{
                "field":   err.Field(),
                "message": err.Tag(),
            })
        }
        c.JSON(400, gin.H{"errors": errors})
        return
    }

    // Use parameterized queries (GORM and database/sql do this)
    db.Create(&User{
        Email:    req.Email,
        Password: hashPassword(req.Password),
        Username: req.Username,
    })

    c.JSON(201, gin.H{"status": "created"})
}

// XSS Prevention: Use html/template for rendering
import "html/template"

func RenderProfile(c *gin.Context) {
    tmpl := template.Must(template.New("profile").Parse("<p>{{.Bio}}</p>"))
    // Bio is automatically escaped
    tmpl.Execute(c.Writer, user)
}
```

**Best Practices:**

1. **Whitelist, not blacklist**: Validate expected formats, don't try to block all bad patterns
2. **Parameterized queries**: Never concatenate SQL with user input
3. **Output encoding**: Escape HTML/JS when rendering user content
4. **Type safety**: Use strongly-typed DTOs instead of accepting raw maps

---

### CSRF Protection

**Summary**: Cross-Site Request Forgery exploits authenticated sessions by tricking users into submitting malicious requests. Prevent with synchronizer tokens or SameSite cookies.

```mermaid
sequenceDiagram
    participant User
    participant Attacker
    participant Bank

    Note over User,Bank: CSRF Attack (No Protection)
    User->>Bank: Login (receives session cookie)
    Attacker->>User: Send email with malicious link
    User->>Bank: Click link (cookie auto-sent)
    Bank->>Bank: Process transfer (thinks it's legit)

    Note over User,Bank: CSRF Protection (Token)
    User->>Bank: GET /transfer-form
    Bank-->>User: Form with CSRF token
    User->>Bank: POST /transfer (token + cookie)
    Bank->>Bank: Verify token matches session
    Bank-->>User: Success
```

**PHP Example (Symfony)**

```php
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\FormBuilderInterface;

class TransferType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('amount', MoneyType::class)
            ->add('recipient', TextType::class);
        // CSRF protection is enabled by default in Symfony forms
    }
}

// In controller
public function transfer(Request $request): Response
{
    $form = $this->createForm(TransferType::class);
    $form->handleRequest($request);

    if ($form->isSubmitted() && $form->isValid()) {
        // CSRF token automatically validated
        $data = $form->getData();
        // Process transfer
    }

    return $this->render('transfer.html.twig', ['form' => $form]);
}

// For API endpoints without forms
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

public function apiTransfer(Request $request, CsrfTokenManagerInterface $csrfTokenManager): JsonResponse
{
    $token = $request->headers->get('X-CSRF-Token');

    if (!$csrfTokenManager->isTokenValid(new CsrfToken('transfer', $token))) {
        return new JsonResponse(['error' => 'Invalid CSRF token'], 403);
    }

    // Process request
}
```

**Go Example (gorilla/csrf)**

```go
import (
    "github.com/gorilla/csrf"
    "github.com/gin-gonic/gin"
)

func main() {
    router := gin.Default()

    // Apply CSRF protection middleware
    CSRF := csrf.Protect(
        []byte("32-byte-long-auth-key"),
        csrf.Secure(false), // Set true in production with HTTPS
    )

    router.Use(func(c *gin.Context) {
        // Wrap Gin with gorilla/csrf
        handler := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            c.Next()
        }))
        handler.ServeHTTP(c.Writer, c.Request)
    })

    router.GET("/transfer-form", func(c *gin.Context) {
        // Token is available via csrf.Token(r)
        c.HTML(200, "transfer.html", gin.H{
            "csrf_token": csrf.Token(c.Request),
        })
    })

    router.POST("/transfer", func(c *gin.Context) {
        // CSRF middleware automatically validates token
        // If invalid, returns 403 before reaching here

        var req TransferRequest
        c.ShouldBindJSON(&req)
        // Process transfer
    })

    router.Run(":8080")
}
```

**When to Use:**

- **Always** for state-changing operations (POST, PUT, DELETE) in traditional web apps
- **Optional** for pure APIs consumed by mobile/SPA (use CORS instead)
- **Not needed** for GET requests (should be idempotent)

---

### Rate Limiting

**Summary**: Restrict the number of requests a client can make to prevent abuse, DDoS attacks, and resource exhaustion. Common algorithms: Token Bucket, Leaky Bucket, Fixed/Sliding Window.

**Token Bucket Algorithm**: Each client has a bucket with tokens refilled at a constant rate. Each request consumes a token. When empty, requests are rejected.

```mermaid
flowchart LR
    Request[Incoming Request] --> Check{Tokens Available?}
    Check -->|Yes| Consume[Consume Token]
    Check -->|No| Reject[429 Too Many Requests]
    Consume --> Process[Process Request]
    Refill[Token Refill<br/>at fixed rate] --> Bucket[Token Bucket]
    Bucket --> Check
```

**PHP Example (Symfony RateLimiter)**

```php
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\HttpFoundation\Response;

class ApiController
{
    public function __construct(
        private RateLimiterFactory $anonymousApiLimiter
    ) {}

    #[Route('/api/search', methods: ['GET'])]
    public function search(Request $request): JsonResponse
    {
        $limiter = $this->anonymousApiLimiter->create($request->getClientIp());

        if (false === $limiter->consume(1)->isAccepted()) {
            return new JsonResponse([
                'error' => 'Too many requests'
            ], Response::HTTP_TOO_MANY_REQUESTS);
        }

        // Process search request
        return new JsonResponse($results);
    }
}

// config/packages/rate_limiter.yaml
// framework:
//     rate_limiter:
//         anonymous_api:
//             policy: 'token_bucket'
//             limit: 100
//             rate: { interval: '1 minute' }
//             storage_service: 'cache.redis'
```

**Go Example (golang.org/x/time/rate)**

```go
import (
    "github.com/gin-gonic/gin"
    "golang.org/x/time/rate"
    "sync"
)

type RateLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.Mutex
    rate     rate.Limit
    burst    int
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
    return &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
        rate:     r,
        burst:    b,
    }
}

func (rl *RateLimiter) GetLimiter(key string) *rate.Limiter {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    limiter, exists := rl.limiters[key]
    if !exists {
        limiter = rate.NewLimiter(rl.rate, rl.burst)
        rl.limiters[key] = limiter
    }

    return limiter
}

func RateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        limiter := rl.GetLimiter(c.ClientIP())

        if !limiter.Allow() {
            c.JSON(429, gin.H{"error": "Too many requests"})
            c.Abort()
            return
        }

        c.Next()
    }
}

func main() {
    router := gin.Default()

    // 100 requests per minute
    limiter := NewRateLimiter(rate.Limit(100.0/60.0), 100)
    router.Use(RateLimitMiddleware(limiter))

    router.GET("/api/search", func(c *gin.Context) {
        c.JSON(200, gin.H{"results": []string{"item1", "item2"}})
    })

    router.Run(":8080")
}
```

**When to Use:**

| Scenario | Algorithm | Configuration |
| --- | --- | --- |
| Public API | Token Bucket | 1000 req/hour, burst 50 |
| Login endpoint | Fixed Window | 5 req/15 min (prevent brute force) |
| Authenticated API | Sliding Window | 10,000 req/day per user |
| Webhooks | Leaky Bucket | Constant 10 req/sec |

---

### Secret Management

**Summary**: Never hardcode secrets (API keys, passwords, tokens) in code or commit them to version control. Use environment variables, secret managers, or encrypted stores.

**PHP Example (Symfony Secrets)**

```php
// Generate secret keys (run once)
// php bin/console secrets:generate-keys

// Set secrets (encrypted in config/secrets/prod/)
// php bin/console secrets:set DATABASE_PASSWORD
// php bin/console secrets:set STRIPE_API_KEY

// Access in code
class PaymentService
{
    public function __construct(
        #[Autowire('%env(STRIPE_API_KEY)%')]
        private string $stripeApiKey
    ) {}

    public function charge(int $amount): void
    {
        $stripe = new \Stripe\StripeClient($this->stripeApiKey);
        // Use API
    }
}

// AWS Secrets Manager integration
// config/packages/framework.yaml
// framework:
//     secrets:
//         vault_directory: '%kernel.project_dir%/config/secrets/%kernel.environment%'
//         local_dotenv_file: '%kernel.project_dir%/.env.local'
//         decrypt_env_vars: true

use Aws\SecretsManager\SecretsManagerClient;

class AwsSecretProvider
{
    private SecretsManagerClient $client;

    public function __construct()
    {
        $this->client = new SecretsManagerClient([
            'region' => 'us-east-1',
            'version' => 'latest',
        ]);
    }

    public function getSecret(string $secretName): string
    {
        $result = $this->client->getSecretValue(['SecretId' => $secretName]);
        return $result['SecretString'];
    }
}
```

**Go Example (Viper + HashiCorp Vault)**

```go
import (
    "github.com/spf13/viper"
    vault "github.com/hashicorp/vault/api"
)

// Using environment variables with Viper
func loadConfig() {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    viper.AutomaticEnv() // Read from environment variables

    viper.ReadInConfig()

    stripeKey := viper.GetString("STRIPE_API_KEY")
    dbPassword := viper.GetString("DATABASE_PASSWORD")
}

// HashiCorp Vault integration
type SecretManager struct {
    client *vault.Client
}

func NewSecretManager(address, token string) (*SecretManager, error) {
    config := vault.DefaultConfig()
    config.Address = address

    client, err := vault.NewClient(config)
    if err != nil {
        return nil, err
    }

    client.SetToken(token)

    return &SecretManager{client: client}, nil
}

func (sm *SecretManager) GetSecret(path string) (string, error) {
    secret, err := sm.client.Logical().Read(path)
    if err != nil {
        return "", err
    }

    if secret == nil || secret.Data["value"] == nil {
        return "", fmt.Errorf("secret not found")
    }

    return secret.Data["value"].(string), nil
}

// Usage
func main() {
    sm, _ := NewSecretManager("http://localhost:8200", "root-token")
    apiKey, _ := sm.GetSecret("secret/data/stripe/api_key")

    // Use apiKey
}
```

**Best Practices:**

1. **Never commit**: Add `.env`, `secrets/` to `.gitignore`
2. **Environment-specific**: Different secrets for dev/staging/prod
3. **Rotation**: Regularly rotate secrets; use Vault's dynamic secrets
4. **Least privilege**: Grant minimum required permissions
5. **Audit**: Log secret access for security monitoring

---

### Security Headers & HTTPS

**Summary**: HTTP security headers protect against common attacks (XSS, clickjacking, MIME sniffing). HTTPS encrypts traffic and enables modern web features.

**Key Headers:**

1. **Content-Security-Policy (CSP)**: Prevents XSS by whitelisting content sources
2. **Strict-Transport-Security (HSTS)**: Forces HTTPS for all requests
3. **X-Frame-Options**: Prevents clickjacking
4. **X-Content-Type-Options**: Prevents MIME type sniffing
5. **Referrer-Policy**: Controls referrer information

**PHP Example (nelmio/security-bundle)**

```php
// config/packages/nelmio_security.yaml
nelmio_security:
    # Forces HTTPS redirects
    forced_ssl:
        enabled: true
        hsts_max_age: 31536000 # 1 year
        hsts_subdomains: true

    # Clickjacking Protection
    clickjacking:
        paths:
            '^/.*': DENY

    # Content Security Policy
    csp:
        enabled: true
        report_uri: /csp-report
        default_src: ["'self'"]
        script_src:
            - "'self'"
            - "'unsafe-inline'" # Avoid in production; use nonces
            - "https://cdn.example.com"
        img_src:
            - "'self'"
            - "data:"
            - "https:"

    # Additional headers
    content_type:
        nosniff: true

    referrer_policy:
        enabled: true
        policies:
            - 'no-referrer-when-downgrade'
```

**Go Example (unrolled/secure)**

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/unrolled/secure"
)

func main() {
    router := gin.Default()

    secureMiddleware := secure.New(secure.Options{
        SSLRedirect:           true,
        SSLHost:               "example.com",
        STSSeconds:            31536000,
        STSIncludeSubdomains:  true,
        STSPreload:            true,
        FrameDeny:             true,
        ContentTypeNosniff:    true,
        BrowserXssFilter:      true,
        ContentSecurityPolicy: "default-src 'self'; script-src 'self' https://cdn.example.com; img-src 'self' data: https:",
        ReferrerPolicy:        "no-referrer-when-downgrade",
    })

    router.Use(func(c *gin.Context) {
        err := secureMiddleware.Process(c.Writer, c.Request)
        if err != nil {
            c.Abort()
            return
        }

        c.Next()
    })

    router.GET("/", func(c *gin.Context) {
        c.String(200, "Secure response")
    })

    // Use TLS
    router.RunTLS(":443", "cert.pem", "key.pem")
}
```

**HTTPS Best Practices:**

1. **Use Let's Encrypt**: Free automated certificates
2. **TLS 1.2+**: Disable older protocols
3. **Strong ciphers**: Prefer ECDHE, AES-GCM
4. **Certificate monitoring**: Alert before expiration

---

## API Design Patterns

> **Quick Reference — API Design Patterns 📡**
> - `REST`: Use HTTP verbs, status codes, and resource-oriented URIs.
> - `GraphQL`: Schema-first for flexible client queries; avoid N+1 with DataLoader.
> - `Versioning`: URL (`/v1/users`) for major changes, headers for minor.
> - `Pagination`: Cursor-based for large datasets, offset for simple cases.
> - `Error Responses`: RFC 7807 Problem Details for consistent error format.
> - `OpenAPI`: Auto-generate documentation from code annotations.

### RESTful API Design

**Summary**: REST (Representational State Transfer) uses HTTP methods to perform CRUD operations on resources. Follow REST principles for predictable, scalable APIs.

**Core Principles:**

1. **Resource-oriented**: URIs represent resources (`/users`, `/orders`)
2. **HTTP verbs**: GET (read), POST (create), PUT/PATCH (update), DELETE (delete)
3. **Status codes**: 2xx (success), 4xx (client error), 5xx (server error)
4. **Stateless**: Each request contains all necessary information

**PHP Example (Symfony + ApiPlatform)**

```php
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Post;
use ApiPlatform\Metadata\Put;
use ApiPlatform\Metadata\Delete;

#[ApiResource(
    operations: [
        new GetCollection(),
        new Get(),
        new Post(),
        new Put(),
        new Delete()
    ]
)]
class Product
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    private ?int $id = null;

    #[Assert\NotBlank]
    private string $name;

    #[Assert\Positive]
    private float $price;

    // Getters and setters
}

// Custom controller for complex operations
#[Route('/api/orders/{id}/ship', methods: ['POST'])]
class ShipOrderController
{
    public function __invoke(Order $order, OrderShippingService $service): JsonResponse
    {
        if ($order->getStatus() !== 'paid') {
            return new JsonResponse([
                'error' => 'Order must be paid before shipping'
            ], 400);
        }

        $service->ship($order);

        return new JsonResponse([
            'id' => $order->getId(),
            'status' => $order->getStatus(),
            'trackingNumber' => $order->getTrackingNumber()
        ], 200);
    }
}
```

**Go Example (Gin)**

```go
func setupRouter() *gin.Engine {
    router := gin.Default()

    products := router.Group("/api/products")
    {
        products.GET("", listProducts)      // GET /api/products
        products.GET("/:id", getProduct)    // GET /api/products/123
        products.POST("", createProduct)    // POST /api/products
        products.PUT("/:id", updateProduct) // PUT /api/products/123
        products.DELETE("/:id", deleteProduct) // DELETE /api/products/123
    }

    router.POST("/api/orders/:id/ship", shipOrder)

    return router
}

func listProducts(c *gin.Context) {
    var products []Product
    db.Find(&products)
    c.JSON(200, products)
}

func getProduct(c *gin.Context) {
    id := c.Param("id")
    var product Product

    if err := db.First(&product, id).Error; err != nil {
        c.JSON(404, gin.H{"error": "Product not found"})
        return
    }

    c.JSON(200, product)
}

func createProduct(c *gin.Context) {
    var product Product

    if err := c.ShouldBindJSON(&product); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    db.Create(&product)
    c.JSON(201, product)
}

func shipOrder(c *gin.Context) {
    id := c.Param("id")
    var order Order

    if err := db.First(&order, id).Error; err != nil {
        c.JSON(404, gin.H{"error": "Order not found"})
        return
    }

    if order.Status != "paid" {
        c.JSON(400, gin.H{"error": "Order must be paid before shipping"})
        return
    }

    shippingService.Ship(&order)

    c.JSON(200, gin.H{
        "id":             order.ID,
        "status":         order.Status,
        "trackingNumber": order.TrackingNumber,
    })
}
```

**HTTP Status Codes:**

| Code | Meaning | Use Case |
| --- | --- | --- |
| 200 OK | Success | GET, PUT successful |
| 201 Created | Resource created | POST successful |
| 204 No Content | Success, no body | DELETE successful |
| 400 Bad Request | Invalid input | Validation error |
| 401 Unauthorized | Authentication required | Missing/invalid token |
| 403 Forbidden | Insufficient permissions | User lacks access |
| 404 Not Found | Resource doesn't exist | GET /users/999 (not found) |
| 409 Conflict | Resource conflict | Duplicate email |
| 500 Internal Server Error | Server error | Unexpected exception |

---

### GraphQL Patterns

**Summary**: GraphQL allows clients to request exactly the data they need. Prevents over-fetching (REST returns too much) and under-fetching (multiple REST calls needed).

**Schema-First vs Code-First:**
- **Schema-First**: Write SDL (Schema Definition Language), generate code
- **Code-First**: Write code, generate schema

**PHP Example (overblog/graphql-bundle)**

```php
// config/graphql/types/User.types.yaml
User:
  type: object
  config:
    fields:
      id:
        type: ID!
      email:
        type: String!
      posts:
        type: [Post!]!
        resolve: '@=service("App\\GraphQL\\Resolver\\UserPostsResolver").resolve(value)'

// Resolver
class UserPostsResolver
{
    public function __construct(private PostRepository $postRepository) {}

    public function resolve(User $user): array
    {
        return $this->postRepository->findBy(['author' => $user]);
    }
}

// Query
# query.types.yaml
Query:
  type: object
  config:
    fields:
      user:
        type: User
        args:
          id:
            type: ID!
        resolve: '@=service("App\\GraphQL\\Resolver\\UserResolver").resolve(args)'

// Usage
// query {
//   user(id: "123") {
//     email
//     posts {
//       title
//       createdAt
//     }
//   }
// }
```

**Go Example (gqlgen - Code-First)**

```go
// schema.graphqls
type User {
  id: ID!
  email: String!
  posts: [Post!]!
}

type Post {
  id: ID!
  title: String!
  content: String!
  author: User!
}

type Query {
  user(id: ID!): User
  posts: [Post!]!
}

// Resolver implementation
type Resolver struct {
    DB *gorm.DB
}

func (r *Resolver) Query() QueryResolver {
    return &queryResolver{r}
}

type queryResolver struct{ *Resolver }

func (r *queryResolver) User(ctx context.Context, id string) (*model.User, error) {
    var user model.User
    if err := r.DB.Preload("Posts").First(&user, id).Error; err != nil {
        return nil, err
    }
    return &user, nil
}

func (r *queryResolver) Posts(ctx context.Context) ([]*model.Post, error) {
    var posts []*model.Post
    r.DB.Find(&posts)
    return posts, nil
}

// Field resolvers
type userResolver struct{ *Resolver }

func (r *userResolver) Posts(ctx context.Context, obj *model.User) ([]*model.Post, error) {
    // Use DataLoader to prevent N+1 queries
    loader := ctx.Value("postLoader").(*dataloader.Loader)
    result, err := loader.Load(ctx, dataloader.StringKey(obj.ID))()
    if err != nil {
        return nil, err
    }
    return result.([]*model.Post), nil
}
```

**Preventing N+1 Queries with DataLoader:**

```go
import "github.com/graph-gophers/dataloader/v7"

func PostLoader(db *gorm.DB) *dataloader.Loader {
    return dataloader.NewBatchedLoader(func(ctx context.Context, keys dataloader.Keys) []*dataloader.Result {
        userIDs := keys.Keys()
        var posts []*model.Post
        db.Where("user_id IN ?", userIDs).Find(&posts)

        // Group posts by user ID
        postsByUser := make(map[string][]*model.Post)
        for _, post := range posts {
            postsByUser[post.UserID] = append(postsByUser[post.UserID], post)
        }

        results := make([]*dataloader.Result, len(userIDs))
        for i, userID := range userIDs {
            results[i] = &dataloader.Result{Data: postsByUser[userID.(string)]}
        }
        return results
    })
}
```

**When to Use:**

| Scenario | REST | GraphQL |
| --- | --- | --- |
| Public API with diverse clients | ✅ | ✅ |
| Mobile apps (reduce bandwidth) | ❌ | ✅ |
| Simple CRUD | ✅ | ❌ |
| Complex nested queries | ❌ | ✅ |
| Caching requirements | ✅ (HTTP cache) | ❌ (harder to cache) |

---

### API Versioning

**Summary**: Versioning allows evolving APIs without breaking existing clients. Strategies: URL path, headers, content negotiation.

**Strategies:**

1. **URL Versioning**: `/v1/users`, `/v2/users`
2. **Header Versioning**: `Accept: application/vnd.myapi.v2+json`
3. **Query Parameter**: `/users?version=2`

**PHP Example (FOSRestBundle)**

```php
// URL versioning (recommended for major changes)
#[Route('/api/v1/users', name: 'api_v1_users')]
class UserV1Controller
{
    public function list(): JsonResponse
    {
        return new JsonResponse([
            ['id' => 1, 'name' => 'John Doe'] // Old format: single name field
        ]);
    }
}

#[Route('/api/v2/users', name: 'api_v2_users')]
class UserV2Controller
{
    public function list(): JsonResponse
    {
        return new JsonResponse([
            ['id' => 1, 'firstName' => 'John', 'lastName' => 'Doe'] // New format: split name
        ]);
    }
}

// Header-based versioning
class UserController
{
    #[Route('/api/users', name: 'api_users')]
    public function list(Request $request): JsonResponse
    {
        $acceptHeader = $request->headers->get('Accept');

        if (str_contains($acceptHeader, 'application/vnd.myapi.v2+json')) {
            return new JsonResponse([
                ['id' => 1, 'firstName' => 'John', 'lastName' => 'Doe']
            ]);
        }

        // Default to v1
        return new JsonResponse([
            ['id' => 1, 'name' => 'John Doe']
        ]);
    }
}
```

**Go Example**

```go
func main() {
    router := gin.Default()

    // URL versioning
    v1 := router.Group("/api/v1")
    {
        v1.GET("/users", listUsersV1)
    }

    v2 := router.Group("/api/v2")
    {
        v2.GET("/users", listUsersV2)
    }

    // Header-based versioning
    router.GET("/api/users", func(c *gin.Context) {
        accept := c.GetHeader("Accept")

        if strings.Contains(accept, "application/vnd.myapi.v2+json") {
            listUsersV2(c)
        } else {
            listUsersV1(c)
        }
    })

    router.Run(":8080")
}

func listUsersV1(c *gin.Context) {
    c.JSON(200, []map[string]interface{}{
        {"id": 1, "name": "John Doe"},
    })
}

func listUsersV2(c *gin.Context) {
    c.JSON(200, []map[string]interface{}{
        {"id": 1, "firstName": "John", "lastName": "Doe"},
    })
}
```

**Trade-offs:**

| Strategy | Pros | Cons |
| --- | --- | --- |
| URL | Simple, cacheable, clear | URL proliferation |
| Header | Clean URLs, standard HTTP | Less visible, harder to test |
| Query Param | Easy to implement | Not RESTful, cache issues |

**Recommendation**: Use **URL versioning** for major changes (breaking), **headers** for minor changes (additions).

---

### Pagination Patterns

**Summary**: Limit result sets to prevent overwhelming clients and servers. Strategies: Offset-based (simple), Cursor-based (scalable).

**Offset Pagination**: `?page=2&limit=20` → Skip 20, take 20

**Cursor Pagination**: `?cursor=encoded_id&limit=20` → Fetch after cursor

**PHP Example (ApiPlatform)**

```php
use ApiPlatform\Metadata\ApiResource;

// Offset pagination (default)
#[ApiResource(
    paginationEnabled: true,
    paginationItemsPerPage: 20,
    paginationMaximumItemsPerPage: 100
)]
class Product
{
    // ...
}

// GET /api/products?page=2
// Response:
// {
//   "hydra:member": [...],
//   "hydra:totalItems": 150,
//   "hydra:view": {
//     "hydra:first": "/api/products?page=1",
//     "hydra:last": "/api/products?page=8",
//     "hydra:next": "/api/products?page=3"
//   }
// }

// Cursor pagination (custom)
class ProductRepository extends ServiceEntityRepository
{
    public function findPaginated(?string $cursor, int $limit): array
    {
        $qb = $this->createQueryBuilder('p')
            ->setMaxResults($limit)
            ->orderBy('p.id', 'ASC');

        if ($cursor) {
            $qb->where('p.id > :cursor')
               ->setParameter('cursor', base64_decode($cursor));
        }

        return $qb->getQuery()->getResult();
    }

    public function getNextCursor(array $products): ?string
    {
        if (empty($products)) {
            return null;
        }

        $lastProduct = end($products);
        return base64_encode($lastProduct->getId());
    }
}

#[Route('/api/products/cursor', methods: ['GET'])]
class PaginatedProductController
{
    public function __invoke(Request $request, ProductRepository $repo): JsonResponse
    {
        $cursor = $request->query->get('cursor');
        $limit = min($request->query->getInt('limit', 20), 100);

        $products = $repo->findPaginated($cursor, $limit + 1);
        $hasMore = count($products) > $limit;

        if ($hasMore) {
            array_pop($products); // Remove extra item
        }

        $nextCursor = $hasMore ? $repo->getNextCursor($products) : null;

        return new JsonResponse([
            'data' => $products,
            'next_cursor' => $nextCursor,
            'has_more' => $hasMore
        ]);
    }
}
```

**Go Example**

```go
type PaginatedResponse struct {
    Data       []Product `json:"data"`
    NextCursor *string   `json:"next_cursor"`
    HasMore    bool      `json:"has_more"`
}

// Offset pagination
func listProductsOffset(c *gin.Context) {
    page := c.DefaultQuery("page", "1")
    limit := c.DefaultQuery("limit", "20")

    pageInt, _ := strconv.Atoi(page)
    limitInt, _ := strconv.Atoi(limit)

    if limitInt > 100 {
        limitInt = 100
    }

    var products []Product
    var total int64

    db.Model(&Product{}).Count(&total)
    db.Offset((pageInt - 1) * limitInt).Limit(limitInt).Find(&products)

    c.JSON(200, gin.H{
        "data":  products,
        "page":  pageInt,
        "limit": limitInt,
        "total": total,
    })
}

// Cursor pagination
func listProductsCursor(c *gin.Context) {
    cursor := c.Query("cursor")
    limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

    if limit > 100 {
        limit = 100
    }

    query := db.Order("id ASC").Limit(limit + 1)

    if cursor != "" {
        decodedCursor, _ := base64.StdEncoding.DecodeString(cursor)
        cursorID, _ := strconv.Atoi(string(decodedCursor))
        query = query.Where("id > ?", cursorID)
    }

    var products []Product
    query.Find(&products)

    hasMore := len(products) > limit
    if hasMore {
        products = products[:limit]
    }

    var nextCursor *string
    if hasMore && len(products) > 0 {
        lastID := products[len(products)-1].ID
        encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", lastID)))
        nextCursor = &encoded
    }

    c.JSON(200, PaginatedResponse{
        Data:       products,
        NextCursor: nextCursor,
        HasMore:    hasMore,
    })
}
```

**When to Use:**

| Pagination Type | Use Case | Pros | Cons |
| --- | --- | --- | --- |
| Offset | Small datasets, admin panels | Simple, jump to any page | Performance degrades with large offsets |
| Cursor | Large datasets, infinite scroll | Consistent performance, no skipped items | Can't jump to arbitrary page |

---

### Error Response Patterns

**Summary**: Consistent error responses improve client integration. RFC 7807 Problem Details provides a standard format.

**RFC 7807 Format:**

```json
{
  "type": "https://api.example.com/errors/validation-error",
  "title": "Validation Error",
  "status": 400,
  "detail": "Email address is already in use",
  "instance": "/api/users",
  "invalid_fields": [
    {"field": "email", "message": "Email already exists"}
  ]
}
```

**PHP Example**

```php
class ProblemDetails implements JsonSerializable
{
    public function __construct(
        private string $type,
        private string $title,
        private int $status,
        private string $detail,
        private string $instance,
        private array $extensions = []
    ) {}

    public function jsonSerialize(): array
    {
        return array_filter([
            'type' => $this->type,
            'title' => $this->title,
            'status' => $this->status,
            'detail' => $this->detail,
            'instance' => $this->instance,
        ] + $this->extensions);
    }
}

class ApiExceptionListener
{
    public function onKernelException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();

        $problem = match(true) {
            $exception instanceof ValidationException => new ProblemDetails(
                type: 'https://api.example.com/errors/validation-error',
                title: 'Validation Error',
                status: 400,
                detail: 'One or more fields are invalid',
                instance: $event->getRequest()->getPathInfo(),
                extensions: ['invalid_fields' => $exception->getErrors()]
            ),
            $exception instanceof EntityNotFoundException => new ProblemDetails(
                type: 'https://api.example.com/errors/not-found',
                title: 'Resource Not Found',
                status: 404,
                detail: $exception->getMessage(),
                instance: $event->getRequest()->getPathInfo()
            ),
            default => new ProblemDetails(
                type: 'https://api.example.com/errors/internal-error',
                title: 'Internal Server Error',
                status: 500,
                detail: 'An unexpected error occurred',
                instance: $event->getRequest()->getPathInfo()
            )
        };

        $response = new JsonResponse($problem, $problem->status);
        $response->headers->set('Content-Type', 'application/problem+json');

        $event->setResponse($response);
    }
}
```

**Go Example**

```go
type ProblemDetails struct {
    Type     string                 `json:"type"`
    Title    string                 `json:"title"`
    Status   int                    `json:"status"`
    Detail   string                 `json:"detail"`
    Instance string                 `json:"instance"`
    Extensions map[string]interface{} `json:"-"`
}

func (p ProblemDetails) MarshalJSON() ([]byte, error) {
    m := map[string]interface{}{
        "type":     p.Type,
        "title":    p.Title,
        "status":   p.Status,
        "detail":   p.Detail,
        "instance": p.Instance,
    }

    for k, v := range p.Extensions {
        m[k] = v
    }

    return json.Marshal(m)
}

func ErrorMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()

        if len(c.Errors) > 0 {
            err := c.Errors.Last().Err

            var problem ProblemDetails

            switch e := err.(type) {
            case *ValidationError:
                problem = ProblemDetails{
                    Type:     "https://api.example.com/errors/validation-error",
                    Title:    "Validation Error",
                    Status:   400,
                    Detail:   "One or more fields are invalid",
                    Instance: c.Request.URL.Path,
                    Extensions: map[string]interface{}{
                        "invalid_fields": e.Fields,
                    },
                }
            case *NotFoundError:
                problem = ProblemDetails{
                    Type:     "https://api.example.com/errors/not-found",
                    Title:    "Resource Not Found",
                    Status:   404,
                    Detail:   e.Message,
                    Instance: c.Request.URL.Path,
                }
            default:
                problem = ProblemDetails{
                    Type:     "https://api.example.com/errors/internal-error",
                    Title:    "Internal Server Error",
                    Status:   500,
                    Detail:   "An unexpected error occurred",
                    Instance: c.Request.URL.Path,
                }
            }

            c.Header("Content-Type", "application/problem+json")
            c.JSON(problem.Status, problem)
            c.Abort()
        }
    }
}
```

**Benefits:**
- **Consistency**: Clients parse errors the same way
- **Machine-readable**: `type` field allows automated handling
- **Extensible**: Add custom fields (`invalid_fields`)
- **Standard**: RFC 7807 is widely adopted

---

### Hypermedia & Self-Documenting APIs

**Summary**: Hypermedia (HATEOAS) embeds links in responses, making APIs discoverable. OpenAPI/Swagger generates interactive documentation.

**PHP Example (ApiPlatform with HAL)**

```php
#[ApiResource(
    formats: ['jsonld', 'jsonhal'],
    operations: [
        new Get(),
        new GetCollection()
    ]
)]
class Order
{
    #[ORM\Id]
    private int $id;

    private string $status;

    #[ORM\ManyToOne]
    private User $customer;

    // ...
}

// GET /api/orders/123 with Accept: application/hal+json
// {
//   "_links": {
//     "self": { "href": "/api/orders/123" },
//     "customer": { "href": "/api/users/456" },
//     "ship": { "href": "/api/orders/123/ship", "method": "POST" }
//   },
//   "id": 123,
//   "status": "paid",
//   "_embedded": {
//     "customer": {
//       "_links": { "self": { "href": "/api/users/456" } },
//       "id": 456,
//       "email": "john@example.com"
//     }
//   }
// }
```

**OpenAPI/Swagger Documentation:**

```php
use OpenApi\Attributes as OA;

#[OA\Info(version: '1.0.0', title: 'My API')]
#[OA\Server(url: 'https://api.example.com')]
class ApiController
{
}

#[Route('/api/users', methods: ['POST'])]
#[OA\Post(
    path: '/api/users',
    summary: 'Create a new user',
    requestBody: new OA\RequestBody(
        required: true,
        content: new OA\JsonContent(
            required: ['email', 'password'],
            properties: [
                new OA\Property(property: 'email', type: 'string', format: 'email'),
                new OA\Property(property: 'password', type: 'string', minLength: 8)
            ]
        )
    ),
    tags: ['Users'],
    responses: [
        new OA\Response(
            response: 201,
            description: 'User created',
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: 'id', type: 'integer'),
                    new OA\Property(property: 'email', type: 'string')
                ]
            )
        ),
        new OA\Response(response: 400, description: 'Validation error')
    ]
)]
class CreateUserController
{
    // ...
}

// Visit /api/doc for Swagger UI
```

**Go Example (swaggo/swag)**

```go
// @title My API
// @version 1.0
// @description API for managing users and orders
// @host api.example.com
// @BasePath /api

// @Summary Create a new user
// @Description Register a new user account
// @Tags Users
// @Accept json
// @Produce json
// @Param user body CreateUserRequest true "User data"
// @Success 201 {object} User
// @Failure 400 {object} ProblemDetails
// @Router /users [post]
func createUser(c *gin.Context) {
    var req CreateUserRequest
    c.ShouldBindJSON(&req)

    // ...
}

// Generate docs: swag init
// Serve: GET /swagger/index.html
```

**Benefits:**
- **Discoverability**: Clients navigate via links, no hardcoded URLs
- **Evolvability**: Add links without breaking clients
- **Documentation**: OpenAPI generates interactive docs
- **Testing**: Swagger UI allows manual testing

---

## Performance Patterns

> **Quick Reference — Performance Patterns ⚡**
> - `Cache-Aside`: Load data into cache on demand; invalidate on updates.
> - `HTTP Caching`: Use ETags, Cache-Control for browser/CDN caching.
> - `N+1 Prevention`: Use eager loading (Doctrine joins, GORM Preload).
> - `Background Jobs`: Offload slow tasks (email, reports) to queues.
> - `Connection Pooling`: Reuse DB/HTTP connections to reduce overhead.
> - `Response Compression`: Enable gzip for 70%+ size reduction.

### Caching Strategies

#### Cache-Aside (Lazy Loading)

**Summary**: Application checks cache first; on miss, loads from database and populates cache. Most common pattern.

```mermaid
sequenceDiagram
    participant App
    participant Cache
    participant DB

    App->>Cache: GET user:123
    Cache-->>App: null (miss)
    App->>DB: SELECT * FROM users WHERE id=123
    DB-->>App: User data
    App->>Cache: SET user:123 = data (TTL: 1h)
    App-->>App: Return data

    Note over App,Cache: Next request (cache hit)
    App->>Cache: GET user:123
    Cache-->>App: Cached data
```

**PHP Example (Symfony Cache + Redis)**

```php
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class UserService
{
    public function __construct(
        private CacheInterface $cache,
        private UserRepository $userRepository
    ) {}

    public function findById(int $id): ?User
    {
        return $this->cache->get("user_{$id}", function (ItemInterface $item) use ($id) {
            $item->expiresAfter(3600); // 1 hour TTL

            $user = $this->userRepository->find($id);

            if (!$user) {
                // Cache negative results for 5 minutes to prevent DB hammering
                $item->expiresAfter(300);
            }

            return $user;
        });
    }

    public function update(User $user): void
    {
        $this->userRepository->save($user);

        // Invalidate cache
        $this->cache->delete("user_{$user->getId()}");
    }
}

// config/packages/cache.yaml
// framework:
//     cache:
//         app: cache.adapter.redis
//         default_redis_provider: redis://localhost
```

**Go Example (go-redis)**

```go
import (
    "context"
    "encoding/json"
    "time"
    "github.com/go-redis/redis/v8"
)

type UserService struct {
    cache *redis.Client
    repo  *UserRepository
}

func (s *UserService) FindByID(ctx context.Context, id int) (*User, error) {
    cacheKey := fmt.Sprintf("user:%d", id)

    // Check cache
    cached, err := s.cache.Get(ctx, cacheKey).Result()
    if err == nil {
        var user User
        json.Unmarshal([]byte(cached), &user)
        return &user, nil
    }

    // Cache miss - fetch from DB
    user, err := s.repo.FindByID(id)
    if err != nil {
        return nil, err
    }

    // Store in cache
    userJSON, _ := json.Marshal(user)
    s.cache.Set(ctx, cacheKey, userJSON, 1*time.Hour)

    return user, nil
}

func (s *UserService) Update(ctx context.Context, user *User) error {
    err := s.repo.Save(user)
    if err != nil {
        return err
    }

    // Invalidate cache
    cacheKey := fmt.Sprintf("user:%d", user.ID)
    s.cache.Del(ctx, cacheKey)

    return nil
}
```

#### HTTP Caching

**Summary**: Leverage browser/CDN caching with ETags and Cache-Control headers. Reduces server load for static or infrequently changing resources.

**PHP Example**

```php
#[Route('/api/products/{id}', methods: ['GET'])]
class GetProductController
{
    public function __invoke(Product $product, Request $request): Response
    {
        $response = new JsonResponse($product);

        // ETag: Hash of resource
        $etag = md5(json_encode($product) . $product->getUpdatedAt()->getTimestamp());
        $response->setEtag($etag);

        // Cache-Control: Public, max-age 1 hour
        $response->setPublic();
        $response->setMaxAge(3600);

        // Check if client has fresh copy
        if ($response->isNotModified($request)) {
            return $response; // Returns 304 Not Modified
        }

        return $response;
    }
}

// Static assets (handled by Symfony)
// Cache-Control: public, max-age=31536000, immutable
```

**Go Example**

```go
func getProduct(c *gin.Context) {
    id := c.Param("id")
    var product Product
    db.First(&product, id)

    productJSON, _ := json.Marshal(product)
    etag := fmt.Sprintf(`"%x"`, md5.Sum(productJSON))

    // Check If-None-Match header
    if c.GetHeader("If-None-Match") == etag {
        c.Status(304) // Not Modified
        return
    }

    c.Header("ETag", etag)
    c.Header("Cache-Control", "public, max-age=3600")
    c.JSON(200, product)
}
```

**Cache-Control Directives:**

| Directive | Meaning |
| --- | --- |
| `public` | Cacheable by browsers and CDNs |
| `private` | Cacheable only by browsers (not CDNs) |
| `no-cache` | Revalidate with server before using |
| `no-store` | Never cache (sensitive data) |
| `max-age=3600` | Fresh for 1 hour |
| `immutable` | Never changes (versioned assets) |

---

### Database Optimization

#### N+1 Query Prevention

**Summary**: Avoid executing N queries in a loop. Use eager loading to fetch related data in a single query.

**Problem:**

```php
// N+1 query problem
$orders = $orderRepository->findAll(); // 1 query

foreach ($orders as $order) {
    echo $order->getCustomer()->getName(); // N queries (1 per order)
}
// Total: 1 + N queries
```

**PHP Solution (Doctrine Eager Loading)**

```php
// Solution 1: JOIN in query
class OrderRepository extends ServiceEntityRepository
{
    public function findAllWithCustomer(): array
    {
        return $this->createQueryBuilder('o')
            ->leftJoin('o.customer', 'c')
            ->addSelect('c')
            ->getQuery()
            ->getResult();
        // Single query with JOIN
    }
}

// Solution 2: Batch fetching
class OrderRepository extends ServiceEntityRepository
{
    public function findAllWithCustomerBatch(): array
    {
        return $this->createQueryBuilder('o')
            ->getQuery()
            ->setFetchMode(Order::class, 'customer', ClassMetadata::FETCH_EAGER)
            ->getResult();
        // 2 queries: 1 for orders, 1 for all customers
    }
}
```

**Go Solution (GORM Preload)**

```go
// Problem
var orders []Order
db.Find(&orders)

for _, order := range orders {
    fmt.Println(order.Customer.Name) // N+1 queries
}

// Solution 1: Preload
var orders []Order
db.Preload("Customer").Find(&orders)
// SELECT * FROM orders
// SELECT * FROM customers WHERE id IN (1,2,3...)

// Solution 2: Joins
var orders []Order
db.Joins("Customer").Find(&orders)
// SELECT orders.*, customers.* FROM orders LEFT JOIN customers ON...
```

**DataLoader Pattern (GraphQL):**

Already covered in [GraphQL Patterns](#graphql-patterns) section above.

#### Database Indexing

**Summary**: Add indexes to frequently queried columns to speed up lookups. Trade-off: faster reads, slower writes.

**PHP Example (Doctrine Migration)**

```php
final class AddUserEmailIndex extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        $this->addSql('CREATE INDEX idx_email ON users (email)');
        $this->addSql('CREATE INDEX idx_status_created ON orders (status, created_at)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP INDEX idx_email');
        $this->addSql('DROP INDEX idx_status_created');
    }
}

// Entity annotation
#[Entity]
#[Index(columns: ['email'], name: 'idx_email')]
#[Index(columns: ['status', 'created_at'], name: 'idx_status_created')]
class User
{
    // ...
}
```

**Go Example (GORM Migration)**

```go
func migrateDatabase(db *gorm.DB) {
    db.AutoMigrate(&User{}, &Order{})

    // Add indexes
    db.Exec("CREATE INDEX idx_email ON users (email)")
    db.Exec("CREATE INDEX idx_status_created ON orders (status, created_at)")
}

// Using struct tags
type User struct {
    ID    uint   `gorm:"primaryKey"`
    Email string `gorm:"uniqueIndex:idx_email"`
}

type Order struct {
    ID        uint   `gorm:"primaryKey"`
    Status    string `gorm:"index:idx_status_created,priority:1"`
    CreatedAt time.Time `gorm:"index:idx_status_created,priority:2"`
}
```

**When to Index:**

✅ **Do index:**
- Primary keys (automatic)
- Foreign keys
- Frequently filtered columns (`WHERE email = ?`)
- Sorting columns (`ORDER BY created_at`)
- Composite indexes for multi-column queries

❌ **Don't index:**
- Low-cardinality columns (e.g., `is_active` with only true/false)
- Columns with frequent updates (index maintenance overhead)
- Small tables (<1000 rows)

---

### Async Processing

**Summary**: Offload slow tasks (email sending, report generation, image processing) to background queues. Improves response times and user experience.

**PHP Example (Symfony Messenger)**

```php
// Message (Job)
class SendWelcomeEmail
{
    public function __construct(
        public readonly string $email,
        public readonly string $name
    ) {}
}

// Handler (Worker)
#[AsMessageHandler]
class SendWelcomeEmailHandler
{
    public function __construct(private MailerInterface $mailer) {}

    public function __invoke(SendWelcomeEmail $message): void
    {
        $email = (new Email())
            ->to($message->email)
            ->subject('Welcome!')
            ->html("<h1>Welcome {$message->name}!</h1>");

        $this->mailer->send($email);
    }
}

// Controller (Producer)
class RegisterController
{
    public function __construct(private MessageBusInterface $bus) {}

    #[Route('/register', methods: ['POST'])]
    public function register(Request $request): JsonResponse
    {
        $user = new User($request->get('email'), $request->get('password'));
        $this->entityManager->persist($user);
        $this->entityManager->flush();

        // Dispatch async message
        $this->bus->dispatch(new SendWelcomeEmail($user->getEmail(), $user->getName()));

        return new JsonResponse(['id' => $user->getId()], 201);
    }
}

// config/packages/messenger.yaml
// framework:
//     messenger:
//         transports:
//             async: '%env(MESSENGER_TRANSPORT_DSN)%' # amqp://localhost or redis://localhost
//         routing:
//             'App\Message\SendWelcomeEmail': async

// Run worker: php bin/console messenger:consume async
```

**Go Example (asynq)**

```go
import (
    "github.com/hibiken/asynq"
    "encoding/json"
)

// Task payload
type SendWelcomeEmailPayload struct {
    Email string `json:"email"`
    Name  string `json:"name"`
}

// Producer (enqueue task)
func registerUser(c *gin.Context) {
    var req RegisterRequest
    c.ShouldBindJSON(&req)

    user := &User{Email: req.Email, Password: req.Password}
    db.Create(user)

    // Enqueue async task
    client := asynq.NewClient(asynq.RedisClientOpt{Addr: "localhost:6379"})
    defer client.Close()

    payload, _ := json.Marshal(SendWelcomeEmailPayload{
        Email: user.Email,
        Name:  user.Name,
    })

    task := asynq.NewTask("email:welcome", payload)
    client.Enqueue(task)

    c.JSON(201, gin.H{"id": user.ID})
}

// Consumer (worker)
func handleWelcomeEmail(ctx context.Context, t *asynq.Task) error {
    var payload SendWelcomeEmailPayload
    json.Unmarshal(t.Payload(), &payload)

    // Send email
    sendEmail(payload.Email, "Welcome!", fmt.Sprintf("Welcome %s!", payload.Name))

    return nil
}

func main() {
    // Start worker
    srv := asynq.NewServer(
        asynq.RedisClientOpt{Addr: "localhost:6379"},
        asynq.Config{Concurrency: 10},
    )

    mux := asynq.NewServeMux()
    mux.HandleFunc("email:welcome", handleWelcomeEmail)

    srv.Run(mux)
}
```

**When to Use:**

| Task Type | Sync | Async |
| --- | --- | --- |
| Send email | ❌ | ✅ |
| Generate PDF report | ❌ | ✅ |
| Process uploaded image | ❌ | ✅ |
| Update database | ✅ | ❌ |
| Calculate total | ✅ | ❌ |

---

### Connection Pooling

**Summary**: Reuse database and HTTP connections instead of creating new ones for each request. Reduces overhead and improves throughput.

**PHP Example (Doctrine DBAL)**

```php
// config/packages/doctrine.yaml
doctrine:
    dbal:
        connections:
            default:
                url: '%env(resolve:DATABASE_URL)%'
                driver: 'pdo_mysql'
                server_version: '8.0'
                options:
                    # Connection pool settings
                    1002: 'SET NAMES utf8' # ATTR_INIT_COMMAND
                pooling: true
                max_connections: 10
```

**Go Example (database/sql)**

```go
import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

func setupDatabase() *sql.DB {
    db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/dbname")
    if err != nil {
        panic(err)
    }

    // Connection pool settings
    db.SetMaxOpenConns(25)                  // Max connections in pool
    db.SetMaxIdleConns(10)                  // Max idle connections
    db.SetConnMaxLifetime(5 * time.Minute)  // Max connection lifetime
    db.SetConnMaxIdleTime(5 * time.Minute)  // Max idle time before closing

    return db
}
```

**HTTP Client Pooling:**

**PHP Example**

```php
use Symfony\Component\HttpClient\HttpClient;

$client = HttpClient::create([
    'max_host_connections' => 6, // Max concurrent connections per host
    'timeout' => 30,
]);

// Reuses connections for multiple requests
$response1 = $client->request('GET', 'https://api.example.com/users/1');
$response2 = $client->request('GET', 'https://api.example.com/users/2');
```

**Go Example**

```go
var httpClient = &http.Client{
    Transport: &http.Transport{
        MaxIdleConns:        100,              // Total idle connections
        MaxIdleConnsPerHost: 10,               // Idle connections per host
        IdleConnTimeout:     90 * time.Second, // Idle timeout
        DisableKeepAlives:   false,            // Enable connection reuse
    },
    Timeout: 30 * time.Second,
}

func fetchUser(id int) (*User, error) {
    resp, err := httpClient.Get(fmt.Sprintf("https://api.example.com/users/%d", id))
    // Connection is reused
    defer resp.Body.Close()

    var user User
    json.NewDecoder(resp.Body).Decode(&user)
    return &user, err
}
```

**Recommended Settings:**

| Setting | Recommendation |
| --- | --- |
| Max Open Connections (DB) | 2-3× CPU cores for OLTP workloads |
| Max Idle Connections | 50% of max open connections |
| Max Connection Lifetime | 5-15 minutes (prevents stale connections) |
| HTTP Keep-Alive | Always enabled for external APIs |

---

### Response Compression

**Summary**: Compress HTTP responses (gzip, brotli) to reduce bandwidth usage. 70-90% size reduction for text-based content.

**PHP Example (Symfony)**

```php
// public/index.php - Enable at web server level (preferred)
// Or use middleware:

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

class CompressionListener
{
    public function onKernelResponse(ResponseEvent $event): void
    {
        $response = $event->getResponse();
        $request = $event->getRequest();

        $acceptEncoding = $request->headers->get('Accept-Encoding', '');

        if (strpos($acceptEncoding, 'gzip') !== false) {
            $content = $response->getContent();

            if (strlen($content) > 1024) { // Only compress if > 1KB
                $compressed = gzencode($content, 6); // Compression level 6

                $response->setContent($compressed);
                $response->headers->set('Content-Encoding', 'gzip');
                $response->headers->set('Content-Length', strlen($compressed));
            }
        }
    }
}

// Better: Configure Nginx
// gzip on;
// gzip_types text/plain text/css application/json application/javascript;
// gzip_min_length 1024;
```

**Go Example (gin-contrib/gzip)**

```go
import (
    "github.com/gin-contrib/gzip"
    "github.com/gin-gonic/gin"
)

func main() {
    router := gin.Default()

    // Apply gzip middleware
    router.Use(gzip.Gzip(gzip.DefaultCompression, gzip.WithExcludedPaths([]string{
        "/health", // Don't compress health checks
    })))

    router.GET("/api/products", func(c *gin.Context) {
        // Response is automatically compressed if client supports it
        c.JSON(200, largeProductList)
    })

    router.Run(":8080")
}
```

**When to Compress:**

✅ **Do compress:**
- JSON/XML responses
- HTML, CSS, JavaScript
- Text-based files

❌ **Don't compress:**
- Images (JPEG, PNG already compressed)
- Video/audio
- Small responses (<1KB overhead not worth it)
- Encrypted content (reduces security)

**Trade-offs:**

| Aspect | Gzip | Brotli |
| --- | --- | --- |
| Compression ratio | Good | Better (10-20% smaller) |
| Speed | Fast | Slower |
| Browser support | Universal | Modern browsers only |
| Use case | General | Static assets |

---

## DevOps & Deployment Patterns

> **Quick Reference — DevOps & Deployment 🚀**
> - `CI/CD`: Automate build, test, deploy with GitHub Actions, GitLab CI.
> - `Blue/Green`: Zero-downtime deployments by switching traffic between environments.
> - `Canary`: Gradual rollout to subset of users to detect issues early.
> - `Infrastructure as Code`: Terraform, Docker Compose for reproducible environments.
> - `Feature Flags`: Runtime toggles for gradual rollouts and A/B testing.

### CI/CD Pipelines

**Summary**: Continuous Integration and Continuous Deployment automate the software delivery pipeline, running tests on every commit and deploying to production automatically.

**PHP Example (GitHub Actions)**

```yaml
# .github/workflows/php.yml
name: PHP CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: password
          POSTGRES_DB: testdb
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v3

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
          extensions: mbstring, xml, pdo, pgsql
          coverage: xdebug

      - name: Install dependencies
        run: composer install --prefer-dist --no-progress

      - name: Run tests
        run: vendor/bin/phpunit --coverage-clover coverage.xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml

  deploy:
    needs: test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Deploy to production
        run: |
          echo "${{ secrets.SSH_PRIVATE_KEY }}" > deploy_key
          chmod 600 deploy_key
          ssh -i deploy_key user@prod-server "cd /var/www && git pull && composer install --no-dev && php bin/console cache:clear"
```

**Go Example (GitLab CI)**

```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - deploy

variables:
  POSTGRES_DB: testdb
  POSTGRES_USER: postgres
  POSTGRES_PASSWORD: password

test:
  stage: test
  image: golang:1.21
  services:
    - postgres:15
  variables:
    DATABASE_URL: "postgres://postgres:password@postgres:5432/testdb?sslmode=disable"
  script:
    - go mod download
    - go test -v -coverprofile=coverage.out ./...
    - go tool cover -func=coverage.out
  coverage: '/^total:\s+\(statements\)\s+(\d+\.\d+)%/'

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t myapp:$CI_COMMIT_SHA .
    - docker tag myapp:$CI_COMMIT_SHA myapp:latest
    - docker push myapp:$CI_COMMIT_SHA
    - docker push myapp:latest

deploy:
  stage: deploy
  only:
    - main
  image: alpine:latest
  before_script:
    - apk add --no-cache openssh-client
    - eval $(ssh-agent -s)
    - echo "$SSH_PRIVATE_KEY" | ssh-add -
  script:
    - ssh user@prod-server "docker pull myapp:$CI_COMMIT_SHA && docker-compose up -d"
```

**Best Practices:**

1. **Run tests on every commit**: Catch bugs early
2. **Automate deployments**: Reduce human error
3. **Use secrets management**: Never commit credentials
4. **Parallel jobs**: Speed up pipeline (e.g., lint, test, security scan)
5. **Deploy previews**: Create temporary environments for pull requests

---

### Deployment Strategies

**Summary**: Different deployment strategies balance risk and downtime. **Blue/Green** eliminates downtime, **Canary** reduces risk by gradual rollout, **Rolling** updates instances incrementally.

```mermaid
graph LR
    subgraph "Blue/Green Deployment"
        LB1[Load Balancer] --> Blue[Blue Environment<br/>v1.0]
        LB1 -.->|Switch traffic| Green[Green Environment<br/>v2.0]
    end

    subgraph "Canary Deployment"
        LB2[Load Balancer] -->|95%| Stable[Stable v1.0]
        LB2 -->|5%| Canary[Canary v2.0]
    end
```

**When to Use:**

| Strategy | Downtime | Risk | Rollback | Use Case |
| --- | --- | --- | --- | --- |
| **Blue/Green** | Zero | Medium | Instant (switch back) | Critical apps, databases |
| **Canary** | Zero | Low | Easy (reduce traffic) | High-traffic apps, A/B testing |
| **Rolling** | Zero | Medium | Slow (redeploy) | Stateless microservices |

**Blue/Green Deployment (Docker Compose)**

```yaml
# docker-compose.blue-green.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - app-blue
      - app-green

  app-blue:
    image: myapp:v1.0
    environment:
      - ENV=production
      - VERSION=blue

  app-green:
    image: myapp:v2.0
    environment:
      - ENV=production
      - VERSION=green
```

```nginx
# nginx.conf - Switch between blue and green
upstream backend {
    # server app-blue:8080;  # Old version
    server app-green:8080;   # New version (switch traffic here)
}

server {
    listen 80;
    location / {
        proxy_pass http://backend;
    }
}
```

**Canary Deployment (Kubernetes)**

```yaml
# canary-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-stable
spec:
  replicas: 9  # 90% of traffic
  selector:
    matchLabels:
      app: myapp
      version: stable
  template:
    metadata:
      labels:
        app: myapp
        version: stable
    spec:
      containers:
      - name: myapp
        image: myapp:v1.0

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-canary
spec:
  replicas: 1  # 10% of traffic
  selector:
    matchLabels:
      app: myapp
      version: canary
  template:
    metadata:
      labels:
        app: myapp
        version: canary
    spec:
      containers:
      - name: myapp
        image: myapp:v2.0

---
apiVersion: v1
kind: Service
metadata:
  name: myapp
spec:
  selector:
    app: myapp  # Routes to both stable and canary
  ports:
  - port: 80
    targetPort: 8080
```

**Monitoring Canary:**

```go
// Prometheus metrics for canary monitoring
import "github.com/prometheus/client_golang/prometheus"

var (
    httpRequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "Total HTTP requests",
        },
        []string{"version", "status"},
    )

    httpRequestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "http_request_duration_seconds",
            Help: "HTTP request latency",
        },
        []string{"version"},
    )
)

func init() {
    prometheus.MustRegister(httpRequestsTotal, httpRequestDuration)
}

// Middleware to track canary metrics
func CanaryMetrics(version string) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        c.Next()

        duration := time.Since(start).Seconds()
        status := strconv.Itoa(c.Writer.Status())

        httpRequestsTotal.WithLabelValues(version, status).Inc()
        httpRequestDuration.WithLabelValues(version).Observe(duration)
    }
}

// Alert if canary error rate > 5%
// PromQL: (rate(http_requests_total{version="canary",status=~"5.."}[5m]) / rate(http_requests_total{version="canary"}[5m])) > 0.05
```

---

### Infrastructure as Code

**Summary**: Define infrastructure (servers, databases, networks) in code for reproducibility and version control. Tools: Terraform (multi-cloud), Docker Compose (local dev), Ansible (configuration).

**PHP Example (Docker Compose for local development)**

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - ./src:/var/www/html
    environment:
      APP_ENV: dev
      DATABASE_URL: postgresql://user:password@postgres:5432/myapp
      REDIS_URL: redis://redis:6379
    ports:
      - "8000:80"
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
      POSTGRES_DB: myapp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./public:/var/www/html/public
    ports:
      - "80:80"
    depends_on:
      - app

volumes:
  postgres_data:
```

**Terraform Example (AWS infrastructure)**

```hcl
# main.tf - Deploy PHP app to AWS
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "myapp-vpc"
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "postgres" {
  identifier           = "myapp-db"
  engine              = "postgres"
  engine_version      = "15.3"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  db_name             = "myapp"
  username            = var.db_username
  password            = var.db_password
  skip_final_snapshot = true

  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
}

# ECS Fargate (for PHP app)
resource "aws_ecs_cluster" "main" {
  name = "myapp-cluster"
}

resource "aws_ecs_task_definition" "app" {
  family                   = "myapp"
  requires_compatibilities = ["FARGATE"]
  network_mode            = "awsvpc"
  cpu                     = "256"
  memory                  = "512"

  container_definitions = jsonencode([{
    name  = "app"
    image = "myapp:latest"
    environment = [
      { name = "APP_ENV", value = "production" },
      { name = "DATABASE_URL", value = "postgresql://${var.db_username}:${var.db_password}@${aws_db_instance.postgres.endpoint}/myapp" }
    ]
    portMappings = [{
      containerPort = 80
      protocol      = "tcp"
    }]
  }])
}

# Outputs
output "db_endpoint" {
  value = aws_db_instance.postgres.endpoint
}
```

**Go Example (Kubernetes deployment)**

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: myapp-secrets
              key: database-url
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: myapp-service
spec:
  selector:
    app: myapp
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

**Benefits:**
- **Reproducibility**: Spin up identical environments
- **Version control**: Track infrastructure changes in Git
- **Automation**: Deploy with `terraform apply` or `kubectl apply`
- **Documentation**: Infrastructure is self-documenting

---

### Container Orchestration

**Summary**: Kubernetes orchestrates containers across multiple servers, handling scaling, load balancing, and self-healing. Alternatives: Docker Swarm (simpler), AWS ECS (managed).

**Kubernetes Concepts:**

```mermaid
graph TB
    Cluster[Kubernetes Cluster]
    Cluster --> Node1[Node 1]
    Cluster --> Node2[Node 2]

    Node1 --> Pod1[Pod: myapp-abc]
    Node1 --> Pod2[Pod: myapp-def]
    Node2 --> Pod3[Pod: myapp-ghi]

    Pod1 --> Container1[Container: myapp:v1.0]
    Pod2 --> Container2[Container: myapp:v1.0]
    Pod3 --> Container3[Container: myapp:v1.0]

    Service[Service: myapp] --> Pod1
    Service --> Pod2
    Service --> Pod3
```

**PHP Example (Symfony on Kubernetes)**

```yaml
# k8s/php-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: symfony-app
spec:
  replicas: 5
  selector:
    matchLabels:
      app: symfony
  template:
    metadata:
      labels:
        app: symfony
    spec:
      containers:
      - name: php-fpm
        image: symfony-app:latest
        ports:
        - containerPort: 9000
        env:
        - name: APP_ENV
          value: "prod"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: url
        volumeMounts:
        - name: cache
          mountPath: /var/www/var/cache

      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
        volumeMounts:
        - name: nginx-config
          mountPath: /etc/nginx/nginx.conf
          subPath: nginx.conf
        - name: cache
          mountPath: /var/www/var/cache

      volumes:
      - name: nginx-config
        configMap:
          name: nginx-config
      - name: cache
        emptyDir: {}

---
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: symfony-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: symfony-app
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

**Go Example (Gin on Kubernetes with health checks)**

```go
// main.go - Kubernetes-ready Go app
package main

import (
    "context"
    "database/sql"
    "github.com/gin-gonic/gin"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"
)

var db *sql.DB

func main() {
    // Initialize database
    db, _ = sql.Open("postgres", os.Getenv("DATABASE_URL"))
    defer db.Close()

    router := gin.Default()

    // Health check endpoints for Kubernetes
    router.GET("/health", HealthCheck)
    router.GET("/ready", ReadinessCheck)

    // Application routes
    router.GET("/api/users", GetUsers)

    // Graceful shutdown
    srv := &http.Server{
        Addr:    ":8080",
        Handler: router,
    }

    go func() {
        srv.ListenAndServe()
    }()

    // Wait for interrupt signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    // Graceful shutdown with 30 second timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    srv.Shutdown(ctx)
}

// Liveness probe - is the app running?
func HealthCheck(c *gin.Context) {
    c.JSON(200, gin.H{"status": "healthy"})
}

// Readiness probe - can the app serve traffic?
func ReadinessCheck(c *gin.Context) {
    // Check database connection
    if err := db.Ping(); err != nil {
        c.JSON(503, gin.H{"status": "not ready", "error": "database unavailable"})
        return
    }

    c.JSON(200, gin.H{"status": "ready"})
}

func GetUsers(c *gin.Context) {
    // Application logic
}
```

**Helm Chart (Package manager for Kubernetes)**

```yaml
# Chart.yaml
apiVersion: v2
name: myapp
version: 1.0.0
description: My Go application

# values.yaml
replicaCount: 3

image:
  repository: myapp
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: LoadBalancer
  port: 80

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

```bash
# Deploy with Helm
helm install myapp ./myapp-chart
helm upgrade myapp ./myapp-chart --set replicaCount=5
```

---

### Feature Flags

**Summary**: Feature flags (toggles) enable runtime control of features without redeploying code. Use cases: gradual rollouts, A/B testing, emergency kill switches.

```mermaid
graph LR
    Request[User Request] --> FlagCheck{Feature Flag<br/>Enabled?}
    FlagCheck -->|Yes| NewFeature[New Feature Code]
    FlagCheck -->|No| OldFeature[Old Feature Code]

    NewFeature --> Response
    OldFeature --> Response[Response]
```

**PHP Example (Simple feature flags)**

```php
// Feature flag service
class FeatureFlagService
{
    public function __construct(
        private CacheInterface $cache,
        private EntityManagerInterface $em
    ) {}

    public function isEnabled(string $featureName, ?User $user = null): bool
    {
        return $this->cache->get("feature_{$featureName}", function (ItemInterface $item) use ($featureName, $user) {
            $item->expiresAfter(300); // 5 minutes

            $flag = $this->em->getRepository(FeatureFlag::class)
                ->findOneBy(['name' => $featureName]);

            if (!$flag || !$flag->isEnabled()) {
                return false;
            }

            // Percentage rollout
            if ($flag->getPercentage() < 100) {
                if (!$user) {
                    return false;
                }
                // Consistent hashing to ensure same user always gets same result
                $hash = crc32($user->getId() . $featureName) % 100;
                return $hash < $flag->getPercentage();
            }

            return true;
        });
    }
}

// Usage in controller
class ProductController extends AbstractController
{
    public function __construct(private FeatureFlagService $featureFlags) {}

    public function show(int $id): Response
    {
        $product = $this->productRepository->find($id);

        if ($this->featureFlags->isEnabled('new_product_ui', $this->getUser())) {
            return $this->render('product/show_new.html.twig', ['product' => $product]);
        }

        return $this->render('product/show.html.twig', ['product' => $product]);
    }
}

// Database entity
#[ORM\Entity]
class FeatureFlag
{
    #[ORM\Id, ORM\GeneratedValue, ORM\Column]
    private int $id;

    #[ORM\Column(length: 255, unique: true)]
    private string $name;

    #[ORM\Column]
    private bool $enabled = false;

    #[ORM\Column]
    private int $percentage = 0;  // 0-100

    #[ORM\Column]
    private ?\DateTimeImmutable $expiresAt = null;
}
```

**Go Example (Feature flags with LaunchDarkly SDK)**

```go
import (
    ld "github.com/launchdarkly/go-server-sdk/v6"
    "github.com/launchdarkly/go-server-sdk/v6/ldcontext"
)

var ldClient *ld.LDClient

func init() {
    var err error
    ldClient, err = ld.MakeClient(os.Getenv("LAUNCHDARKLY_SDK_KEY"), 5*time.Second)
    if err != nil {
        log.Fatal(err)
    }
}

// Feature flag middleware
func FeatureFlagMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get user from context (from JWT middleware)
        userID := c.GetString("user_id")

        // Create LaunchDarkly context
        context := ldcontext.NewBuilder(userID).
            Set("email", c.GetString("user_email")).
            Build()

        c.Set("ld_context", context)
        c.Next()
    }
}

// Check feature flag
func GetProduct(c *gin.Context) {
    ldContext := c.MustGet("ld_context").(ldcontext.Context)

    useNewUI, _ := ldClient.BoolVariation("new-product-ui", ldContext, false)

    if useNewUI {
        // New feature code
        c.JSON(200, gin.H{
            "product": product,
            "ui_version": "v2",
            "recommendations": GetMLRecommendations(product.ID),
        })
    } else {
        // Old feature code
        c.JSON(200, gin.H{
            "product": product,
            "ui_version": "v1",
        })
    }
}

// Gradual rollout with percentage
func GetCheckout(c *gin.Context) {
    ldContext := c.MustGet("ld_context").(ldcontext.Context)

    // Rollout to 10% of users
    newCheckout, _ := ldClient.BoolVariation("new-checkout-flow", ldContext, false)

    if newCheckout {
        return NewCheckoutHandler(c)
    }

    return OldCheckoutHandler(c)
}
```

**Feature Flag Best Practices:**

1. **Short-lived flags**: Remove flags after full rollout (avoid technical debt)
2. **Monitoring**: Track flag evaluations and performance impact
3. **Testing**: Test both flag states in CI
4. **Kill switches**: Use flags to quickly disable problematic features
5. **A/B testing**: Measure metrics for each variant

**When to Use:**

| Use Case | Example | Benefit |
| --- | --- | --- |
| Gradual rollout | Release to 10%, then 50%, then 100% | Reduce risk of bugs affecting all users |
| A/B testing | Test new checkout flow vs. old | Measure impact on conversion rate |
| Kill switch | Disable ML recommendations if slow | Emergency rollback without deploy |
| Permission-based | Premium features for paid users | Runtime entitlement control |

---

## Cross-Pattern Integration

**Real-World Scenario**: Building a secure, performant, tested e-commerce API

Let's combine patterns from all sections:

```mermaid
graph TB
    Client[Mobile App] -->|JWT Auth| Gateway[API Gateway]
    Gateway -->|Rate Limited| API[API Endpoint]
    API -->|Validate Input| Service[Order Service]
    Service -->|Cache-Aside| Cache[(Redis Cache)]
    Service -->|Connection Pool| DB[(PostgreSQL)]
    Service -->|Async Task| Queue[Message Queue]
    Queue -->|Worker| EmailService[Email Service]

    API -->|Distributed Tracing| Tracing[OpenTelemetry]
    API -->|Error Logging| Sentry[Exception Tracking]

    style Gateway fill:#f9f,stroke:#333
    style Cache fill:#9f9,stroke:#333
    style Queue fill:#9ff,stroke:#333
```

**Implementation Checklist:**

**Security** 🔒
- ✅ JWT authentication for stateless API
- ✅ RBAC for admin/customer roles
- ✅ Input validation with DTO constraints
- ✅ Rate limiting (100 req/min per IP)
- ✅ HTTPS with security headers (CSP, HSTS)

**Testing** 🧪
- ✅ Unit tests for business logic (AAA pattern)
- ✅ Integration tests with testcontainers
- ✅ Contract tests between services (Pact)
- ✅ Test data builders for fixtures

**API Design** 📡
- ✅ RESTful endpoints (`/api/v1/orders`)
- ✅ Cursor pagination for products
- ✅ RFC 7807 error responses
- ✅ OpenAPI documentation

**Performance** ⚡
- ✅ Redis cache-aside for product catalog
- ✅ Eager loading to prevent N+1 queries
- ✅ Async email sending via queue
- ✅ Connection pooling (DB, HTTP clients)
- ✅ Gzip compression for responses

**From Previous Parts:**
- Part 1: Repository pattern (data access)
- Part 2: Circuit breaker for payment service, distributed tracing
- Part 3: Hexagonal architecture (ports & adapters)

---

## Pattern Selection Guide

**Decision Matrix**: When to prioritize each pattern category

| Project Phase | Security | Testing | API Design | Performance |
| --- | --- | --- | --- | --- |
| **MVP/Startup** | 🔴 Critical (JWT, validation, HTTPS) | 🟡 Medium (unit tests) | 🟢 Nice-to-have (REST basics) | ⚪ Skip |
| **Growth** | 🔴 Critical (+RBAC, rate limiting) | 🟡 Medium (+integration) | 🟡 Medium (versioning, pagination) | 🟡 Medium (caching, N+1) |
| **Enterprise** | 🔴 Critical (full suite) | 🔴 Critical (+contract tests) | 🔴 Critical (OpenAPI, HAL) | 🔴 Critical (all optimizations) |

**Implementation Order:**

1. **Security First** (Week 1-2)
   - JWT/Session auth
   - Input validation
   - HTTPS + security headers

2. **Basic Testing** (Week 2-3)
   - Unit tests for business logic
   - Simple integration tests

3. **API Foundations** (Week 3-4)
   - REST conventions
   - Error handling (RFC 7807)
   - Basic pagination

4. **Performance Basics** (Week 4-5)
   - Fix N+1 queries
   - Add caching for read-heavy endpoints
   - Enable gzip compression

5. **Advanced Patterns** (Ongoing)
   - RBAC, rate limiting
   - Contract testing
   - Async processing
   - Connection pooling

---

## Conclusion

Cross-cutting patterns transform good architecture into **production-ready systems**:

- **Security patterns** protect users and data (authentication, input validation, rate limiting)
- **Testing patterns** ensure correctness and prevent regressions (unit, integration, contract tests)
- **API design patterns** improve developer experience (REST, versioning, pagination, error handling)
- **Performance patterns** scale to handle traffic (caching, N+1 prevention, async processing)

**Key Takeaways:**

1. **Security is non-negotiable**: Every public API needs auth, validation, and HTTPS
2. **Test strategically**: Focus on unit tests for logic, integration tests for data flow, contract tests for microservices
3. **Design for clients**: Consistent APIs (REST/GraphQL), clear errors (RFC 7807), good docs (OpenAPI)
4. **Optimize iteratively**: Profile first, then cache, fix N+1 queries, and offload to queues

**Integrating with Previous Parts:**

- **Part 1 (GoF Patterns)**: Use Repository (data access), Strategy (payment methods), Observer (event listeners)
- **Part 2 (Microservices)**: Add Circuit Breaker (payment service), Distributed Tracing (OpenTelemetry), Saga (order fulfillment)
- **Part 3 (Architecture)**: Apply security/testing/performance to Hexagonal or Clean Architecture
- **Part 4 (This Document)**: Cross-cutting concerns apply to **all layers and services**

The combination of solid architecture (Parts 1-3) and robust cross-cutting patterns (Part 4) creates systems that are **maintainable, secure, testable, and performant**.

---

## Continue the Series

This is **Part 4** of the "Backend Design Patterns: PHP vs. Go" series:

- [Part 1: GoF Design Patterns](backend-design-patterns-php-vs-go.md)
- [Part 2: Modern Backend & Microservice Patterns](microservices-patterns-php-vs-go.md)
- [Part 3: System Architecture Patterns](system-architecture-patterns-php-vs-go.md)
- **Part 4: Security, API Design, Performance & DevOps Patterns** (this document)
- [Part 5: Testing Patterns](testing-patterns-php-vs-go.md)
- [Part 6: Naming Conventions & Class Role Patterns](naming-conventions-php-vs-go.md)
- [Part 7: Domain-Driven Design (DDD) Guide](domain-driven-design-guide.md)
- [Part 8: Data Persistence Patterns: SQL vs NoSQL](data-persistence-patterns-sql-vs-nosql.md)

---

## References

**Security:**
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [RFC 7807: Problem Details for HTTP APIs](https://tools.ietf.org/html/rfc7807)
- [Symfony Security Best Practices](https://symfony.com/doc/current/security.html)

**Testing:**
- [Martin Fowler: Testing Strategies](https://martinfowler.com/testing/)
- [Pact: Consumer-Driven Contract Testing](https://docs.pact.io/)
- [PHPUnit Documentation](https://phpunit.de/)
- [Go Testing Package](https://pkg.go.dev/testing)

**API Design:**
- [REST API Tutorial](https://restfulapi.net/)
- [GraphQL Best Practices](https://graphql.org/learn/best-practices/)
- [OpenAPI Specification](https://swagger.io/specification/)
- [API Platform Documentation](https://api-platform.com/)

**Performance:**
- [High Performance Browser Networking](https://hpbn.co/)
- [Database Indexing Explained](https://use-the-index-luke.com/)
- [Redis Cache Patterns](https://redis.io/docs/manual/patterns/)
- [Go Performance Tips](https://github.com/dgryski/go-perfbook)
