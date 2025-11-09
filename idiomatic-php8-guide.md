# Idiomatic PHP 8.3 Guide for Symfony 7 & Laravel

> Target: PHP 8.3, Symfony 7.x, Laravel 11.x; Audience: backend/API engineers shipping production web services.

## Table of Contents
- Purpose & Principles
- PHP 8.3 Language Idioms
- Project & Package Conventions
- HTTP & API Best Practices
- Persistence & Transactions
- Asynchrony & Integration
- Security Baselines
- Observability & Resilience
- Testing with PHPUnit
- Symfony 7 Idioms
- Laravel Idioms
- Popular Libraries (Curated)
- References & Further Study

---

## Purpose & Principles
- Treat PHP 8.3 as a typed, modern language: embrace strict typing, immutability, and compiler/runtime diagnostics.
- Prefer small, testable services with clear contracts. Hide framework details behind application boundaries.
- Automate quality gates (static analysis, tests, coding standards) in CI.
- Document assumptions with attributes (routing, validation, DI) and PHPDoc only for surface API contracts.
- Invest in developer experience: runnable teardown-less tests, repeatable fixtures, fast feedback loops.

---

## PHP 8.3 Language Idioms
- **Strict types & PSR-12**: add `declare(strict_types=1);` to every file and let `phpcs`/`php-cs-fixer` enforce style.
- **Attributes beat annotations**: leverage native attributes for routing, DI, validation.
  ```php
  <?php
  declare(strict_types=1);

  use Attribute;

  #[Attribute(Attribute::TARGET_METHOD)]
  final class Audit
  {
      public function __construct(public readonly string $action) {}
  }
  ```
- **Enums for domain invariants**: express discrete sets with methods, avoid magic strings.
  ```php
  enum Currency: string
  {
      case EUR = 'EUR';
      case USD = 'USD';

      public function symbol(): string
      {
          return match ($this) {
              self::EUR => '€',
              self::USD => '$',
          };
      }
  }
  ```
- **Readonly by default**: favour `readonly` properties/classes for value objects, DTOs, config.
  ```php
  readonly class Money
  {
      public function __construct(
          public Currency $currency,
          public int $minorUnits,
      ) {}
  }
  ```
- **Constructor property promotion**: remove boilerplate; combine with visibility and types.
- **Union & intersection types**: model optional dependencies or mixed behaviour explicitly (`LoggerInterface&ResetInterface`).
- **`match` and nullsafe** operators**: avoid nested conditionals.
  ```php
  $status = match (true) {
      $total->minorUnits === 0 => 'empty',
      $total->minorUnits < 0 => 'refund',
      default => 'charge',
  };

  $postcode = $request->getUser()?->address?->postcode;
  ```
- **Named arguments & default values**: clarify intent in builder/factory calls.
- **First-class callables**: pass method references to higher-order functions.
- **Exception boundaries**: throw domain-specific exceptions; convert to HTTP problem documents at controllers.
- **Collections**: Symfony `ArrayCollection`, Laravel `Collection`; consider `webmozart/assert` for guards.
- **Date/Time**: prefer `DateTimeImmutable`; centralise conversions; for Laravel use Carbon (extends `DateTimeImmutable` in 11.x).
- **Randomness**: use `Random\Randomizer` with explicit engine (`SecureRandom` for tokens).
- **Generators**: lazily stream large datasets (`yield from`). Combine with Symfony Messenger chunking.
- **Attributes for deprecation**: mark code with `#[Deprecated(reason: ..., replacement: ...)]`.

---

## Project & Package Conventions
- **Composer hygiene**:
  - Separate runtime (`require`) vs dev (`require-dev`) deps.
  - Declare `config.platform.php = 8.3.0` to stabilise builds.
  - Add scripts for CI: `"lint": "phpcs"`, `"stan": "phpstan analyse"`, `"test": "phpunit"`.
- **Autoloading**: PSR-4 align with namespace root; avoid mixing `src/` and `app/` for domain code.
- **Environment separation**:
  - Symfony: `config/packages/<env>/...` plus `dotenv`. Keep secrets in `vault secrets:list`.
  - Laravel: `.env` per environment, override with secret stores (e.g., AWS Parameter Store, Vault).
- **Configuration pattern**: expose immutable config DTOs.
  ```php
  readonly class HttpConfig
  {
      public function __construct(
          public string $host,
          public int $port,
          public int $requestTimeoutMs,
      ) {}

      public static function fromEnv(array $env): self
      {
          return new self(
              $env['APP_HOST'] ?? '0.0.0.0',
              (int) ($env['APP_PORT'] ?? 8080),
              (int) ($env['HTTP_TIMEOUT_MS'] ?? 2000),
          );
      }
  }
  ```
- **Dependency inversion**: controllers/services depend on interfaces located in `Domain` or `Application` layers; frameworks adapt via service container bindings.
- **DTOs vs entities**: serialise HTTP payloads with DTOs (record-like `readonly class` or `scalar object`) distinct from persistence entities.
- **Serialization & validation**: centralise with Symfony Serializer + Validator or Laravel Resources + FormRequests; keep invariants at boundaries.

---

## HTTP & API Best Practices
- **Controller boundaries**: controllers orchestrate application services, no business logic.
- **Request validation**:
  - Symfony: use a request DTO with `#[AsController]` service, apply `#[Assert]` constraints.
    ```php
    #[AsController]
    final class CreateOrderAction
    {
        public function __invoke(CreateOrderRequest $request, OrderService $service): JsonResponse
        {
            $order = $service->create($request->toCommand());
            return new JsonResponse(OrderResource::fromDomain($order), Response::HTTP_CREATED);
        }
    }
    ```
  - Laravel: extend `FormRequest`; rely on `validated()` payload; return API Resources.
- **Response shaping**: use Symfony normalizers or Laravel API Resources to hide persistence schema.
- **Pagination**: expose `page[size]`, `page[number]` (JSON:API) or `cursor`. Include `Link` headers. Provide stable ordering.
- **Versioning**: default to URI-less versioning (content negotiation via `Accept: application/vnd.acme.v1+json`); if necessary, namespaced routes/groups.
- **Error format**: return RFC 9457 problem+json with detail, type, instance.
- **Idempotency & retries**: accept `Idempotency-Key` header, persist in DB/Redis to deduplicate.
- **Caching & conditional requests**: implement `ETag`/`Last-Modified`; leverage Symfony HttpCache or Laravel cache middleware.
- **Rate limiting & CORS**: configure per-client quotas; use Laravel `RateLimiter` and Symfony `RateLimiter` component; allow granular origins.
- **Documentation**: generate OpenAPI via API Platform (Symfony) or `laravel-openapi`/`l5-swagger`; keep docs in CI.

---

## Persistence & Transactions
- **Doctrine ORM (Symfony)**:
  - Keep entities lean; use embeddables for value objects.
  - Repositories expose intent (`findByOrderNumber`, `save`). Avoid exposing `EntityManager`.
    ```php
    final class OrderRepository
    {
        public function __construct(private EntityManagerInterface $em) {}

        public function save(Order $order): void
        {
            $this->em->persist($order);
            $this->em->flush();
        }

        public function findById(Uuid $id): ?Order
        {
            return $this->em->getRepository(Order::class)->find($id);
        }
    }
    ```
  - Use `#[ORM\Version]` for optimistic locking, `#[ORM\Index]` for hot queries. Prefer migrations with Doctrine Migrations.
  - For read-heavy workload, combine QueryBuilder projections with DTO hydration to avoid entity inflation.
- **Eloquent (Laravel)**:
  - Custom scopes to encapsulate query fragments.
    ```php
    final class Order extends Model
    {
        use HasFactory;

        protected $fillable = ['customer_id', 'status', 'total_minor'];

        public function scopeActive(Builder $query): Builder
        {
            return $query->where('status', 'active');
        }
    }
    ```
  - Use attribute casting (`protected $casts`) for enums (`OrderStatus::class`), `AsCollection`, `AsEncryptedArrayObject`.
  - Prefer `DTO + Model::fill()` rather than mass-assigning raw request payloads.
- **Transactions**:
  - Symfony: wrap in `transactional()` or `EntityManagerInterface::wrapInTransaction`.
  - Laravel: `DB::transaction(fn () => ...)`.
  - Emit domain events inside transactions but outbox them for asynchronous dispatch.
- **N+1 prevention**: enable Doctrine `EXTRA_LAZY`, use `with()`/`loadMissing()` in Laravel; use clockwork or debug toolbar to inspect queries.
- **Soft deletes**: use Doctrine filters or Laravel `SoftDeletes` trait when business rules require.
- **Outbox pattern**: persist integration events to `outbox_events` table and process with Messenger worker or Laravel queue worker.

---

## Asynchrony & Integration
- **Queues**:
  - Symfony Messenger with transports (AMQP, Redis, Doctrine). Configure `messenger.yaml` per transport (high vs default priority).
  - Laravel Queue workers (Redis, SQS); monitor with Horizon.
- **Jobs & retries**: configure exponential backoff, max attempts; prefer idempotent handlers.
  ```php
  final class SendInvoiceNotification implements ShouldQueue
  {
      use Dispatchable, InteractsWithQueue, Queueable;

      public int $tries = 5;
      public function backoff(): array { return [30, 120, 600]; }

      public function handle(InvoiceMailer $mailer): void
      {
          $mailer->send(/* ... */);
      }
  }
  ```
- **Events**:
  - Distinguish domain events (in-process) from integration events (external). Symfony: use `EventDispatcherInterface`; Laravel: `Event::listen()` or queued listeners.
  - Serialize integration events with versioned payloads, publish through queues or webhooks.
- **Mail & notifications**: rely on Symfony Mailer/Laravel Notifications; configure async transport (e.g., `Symfony\Component\Mailer\Transport\RoundRobinTransport`) or queue.
- **Scheduling**:
  - Symfony: `Scheduler` component (PHP 8.2+), or rely on cron invoking `bin/console app:task`.
  - Laravel: define schedules in `app/Console/Kernel.php`, run `php artisan schedule:work`.
- **File storage**: unify via Flysystem adapters (S3, local, Azure). In Laravel use `Storage::disk('s3')`; in Symfony wrap `League\Flysystem\FilesystemOperator`.
- **Caching**: Symfony Cache pools with tags (Redis, Memcached); Laravel cache with tags, atomic locks for distributed mutex.

---

## Security Baselines
- **Authentication**:
  - Symfony: Security bundle with `AuthenticatorInterface`, password hashing via `PasswordHasherInterface`. Use `symfonycasts/reset-password-bundle` for flows.
  - Laravel: `laravel/fortify` for UI-less auth, `sanctum` for SPA/token, `passport` for OAuth2.
- **Authorization**:
  - Symfony voters evaluate rich objects. Cache unanimous decisions sparingly.
  - Laravel policies and gates; register via `AuthServiceProvider`.
- **Password storage**: use `argon2id` (`password_hash`) or Symfony `PasswordHasher`. Rotate via `needsRehash`.
- **CSRF & session**: enable CSRF middleware for web; for API token flows prefer stateless guards.
- **Input validation**: combine syntactic (FormRequest/Validator) with semantic (domain services). Reject unexpected fields.
- **Secrets management**: Symfony Vault or environment secrets; Laravel `.env` fallback with AWS Secrets Manager / Doppler. Never check `.env` into VCS.
- **Auditing**: capture critical actions with Monolog channel or Laravel observers; store `actor_id`, `ip`, `user_agent`.
- **Security headers**: use `nelmio/security-bundle` (Symfony) or Laravel `secure-headers` middleware for CSP, HSTS, frame guards.
- **Supply chain**: lock dependencies (`composer.lock`), run `composer audit`, subscribe to `FriendsOfPHP/security-advisories`.

---

## Observability & Resilience
- **Logging**:
  - Use Monolog structured handlers (JSON). Symfony: configure channels (`config/packages/monolog.yaml`). Laravel: `config/logging.php` stack channels.
  - Include correlation IDs (`X-Request-Id`); generate if absent.
- **Metrics & tracing**:
  - Instrument with OpenTelemetry PHP SDK. Export to OTLP collector; wrap HTTP clients with middleware for spans.
  - Laravel: `open-telemetry/opentelemetry-laravel`; Symfony: `open-telemetry/opentelemetry-symfony-sdk`.
- **Health checks**: expose `/healthz` with aggregated checks (database, queue). Symfony: `symfony/ux-live-component` or custom command; Laravel: `spatie/laravel-health`.
- **Feature flags**: use `symfony/feature-flags` or `laravel/pennant`; store state in Redis or config.
- **Circuit breakers & retries**: `php-http/client-common` plugin, `symfony/http-client` retry strategies, or `laravel-retry` macros. Always bound by timeout (`HttpClientInterface` `timeout`, Guzzle with `connect_timeout`).
- **Graceful shutdown**: ensure queue workers listen for SIGTERM, finish jobs, flush metrics. Laravel `Queue::looping` hooks; Symfony Messenger `--sleep` & `--time-limit`.
- **Backpressure**: combine rate limiters with queue max length alerts; auto-scale workers via Horizon or Kubernetes.

---

## Testing with PHPUnit
- **Test pyramid**: ratio ~70% unit, 20% integration, 10% end-to-end (API/browser).
- **Structure**:
  - Symfony: `tests/Unit`, `tests/Functional`, `tests/Integration`.
  - Laravel: `tests/Unit`, `tests/Feature`. Use Pest if team prefers BDD syntax.
- **Unit tests**: isolate domain services with doubles (`phpspec/prophecy`, `mockery/mockery`).
  ```php
  final class MoneyFormatterTest extends TestCase
  {
      public function testFormatsCurrency(): void
      {
          $formatter = new MoneyFormatter();
          self::assertSame('€12.00', $formatter->format(new Money(Currency::EUR, 1200)));
      }
  }
  ```
- **HTTP/feature tests**:
  - Symfony: `WebTestCase`, `HttpKernelBrowser`, assert JSON with `assertJsonContains`.
  - Laravel: `Illuminate\Foundation\Testing\TestCase`, `actingAs`, `assertJson`.
  ```php
  public function testCreatesOrder(): void
  {
      $response = $this->postJson('/api/orders', [
          'customerId' => Uuid::v4()->toRfc4122(),
          'totalMinor' => 1200,
      ]);

      $response->assertCreated()
          ->assertJsonPath('data.attributes.status', 'pending');
  }
  ```
- **Database testing**: run migrations once per test suite; use SQLite in-memory only when behaviour matches (beware JSON, enum differences). Prefer transactional fixtures (`RefreshDatabase` trait in Laravel, Doctrine `DAMADoctrineTestBundle`).
- **Factories & builders**: Laravel Model factories; Symfony use `zenstruck/foundry`.
- **Coverage & quality**:
  - Code coverage with Xdebug or PCOV; enforce thresholds in CI.
  - Mutation testing via `infection/infection`.
  - Static analysis with PHPStan/Psalm; enforce max level feasible (PHPStan level 8).
- **Continuous integration**: run `composer validate`, `composer audit`, coding standards, static analysis, unit + integration suites.

---

## Symfony 7 Idioms
- **Autowiring + attributes**: rely on constructor autowiring; annotate routes with `#[Route]`. Controllers as services, no inheritance from `AbstractController` unless needed.
  ```php
  #[Route('/orders', methods: ['POST'])]
  final class CreateOrderController
  {
      public function __construct(private readonly OrderService $service) {}

      public function __invoke(#[MapRequestPayload] CreateOrderRequest $request): JsonResponse
      {
          $order = $this->service->create($request->toCommand());
          return new JsonResponse(OrderResource::fromDomain($order), Response::HTTP_CREATED);
      }
  }
  ```
- **Request DTO mapping**: use `#[MapQueryParameter]`, `#[MapRequestPayload]` to bind and validate.
- **Service configuration**: default `services.yaml` autowires `App\` namespace; narrow with `bind` for primitives.
- **HTTP client**: inject `HttpClientInterface`; configure retry & timeout per client in `framework.http_client.scoped_clients`.
- **Event subscribers**: implement `EventSubscriberInterface` for cross-cutting concerns (audit logging, metrics).
- **Messenger**: separate buses (`command.bus`, `event.bus`). Configure `failure_transport`, add middleware for logging/metrics.
- **Cache**: use named cache pools; inject `CacheInterface` per concern to avoid key collisions.
- **Env-based config**: use `env()` placeholders; validate via `symfony/runtime`. Keep `.env.local.php` out of version control.
- **DX tooling**: `bin/console debug:*` commands, VarDumper, Symfony profiler in dev.

---

## Laravel Idioms
- **Route organisation**: group by domain, apply middleware per group. Use route names for URL generation.
- **Form requests**: encapsulate validation + authorisation.
  ```php
  final class CreateOrderRequest extends FormRequest
  {
      public function rules(): array
      {
          return [
              'customerId' => ['required', 'uuid'],
              'totalMinor' => ['required', 'integer', 'min:0'],
          ];
      }

      public function authorize(): bool
      {
          return $this->user()->can('create', Order::class);
      }
  }
  ```
- **Resources & transformers**: extend `JsonResource` to present domain models. Wrap collections with pagination metadata.
- **Eloquent attributes**: use accessors/mutators (`protected function casts(): array`) to map to enums, custom value objects.
- **Service container**: register bindings in `AppServiceProvider::register`, e.g., `$this->app->bind(OrderRepository::class, DoctrineOrderRepository::class);`.
- **Jobs/events/listeners**: prefer queued listeners for heavy work; use sync bus for domain events.
- **Queues & Horizon**: configure queue names (`high`, `default`, `low`); monitor concurrency, retry. Use `Supervisor` definitions in `config/horizon.php`.
- **Task scheduling**: declare in `schedule(Schedule $schedule)` with `->runInBackground()` for async tasks.
- **Policies & gates**: map in `AuthServiceProvider::$policies`; use `Gate::define` for coarse rules.
- **Testing helpers**: `TestCase` traits (`WithoutMiddleware`, `WithFaker`, `RefreshDatabase`). Use `artisan` commands to seed test data.
- **Configuration caching**: `php artisan config:cache`, `route:cache`, `event:cache` in deployment workflows.

---

## Popular Libraries (Curated)
- **HTTP & APIs**: `symfony/http-client`, `guzzlehttp/guzzle`, `nyholm/psr7`, `lcobucci/jwt`.
- **Persistence**: `doctrine/orm`, `doctrine/dbal`, `laravel-doctrine/orm`, `spatie/laravel-query-builder`, `ramsey/uuid`.
- **Caching & storage**: `symfony/cache`, `predis/predis`, `phpredis/phpredis`, `league/flysystem`, `spatie/laravel-responsecache`.
- **Queues & messaging**: `symfony/messenger`, `enqueue/enqueue`, `laravel/horizon`, `laravel/pulse`, `php-amqplib/php-amqplib`, `aws/aws-sdk-php`.
- **Validation & forms**: `symfony/validator`, `spatie/laravel-data`, `spatie/laravel-validation-rules`, `symfony/form`.
- **Serialization**: `symfony/serializer`, `jms/serializer`, `league/fractal`, `spatie/laravel-json-api-paginate`.
- **Security**: `symfonycasts/reset-password-bundle`, `scheb/two-factor-bundle`, `laravel/sanctum`, `laravel/passport`, `defuse/php-encryption`.
- **Observability**: `monolog/monolog`, `sentry/sentry-symfony`, `sentry/sentry-laravel`, `open-telemetry/opentelemetry-php`, `spatie/laravel-activitylog`.
- **Testing & QA**: `phpunit/phpunit`, `pestphp/pest`, `mockery/mockery`, `infection/infection`, `phpstan/phpstan`, `vimeo/psalm`, `friendsofphp/php-cs-fixer`, `squizlabs/php_codesniffer`, `rector/rector`, `nunomaduro/larastan`.
- **API tooling**: `api-platform/core`, `nelmio/api-doc-bundle`, `darkaonline/l5-swagger`, `laravel-json-api/laravel`, `spiral/roadrunner-http` for high-performance runtime, `bref/bref` for serverless deployment.
- **Dev workflow**: `symfony/maker-bundle`, `symfony/panther`, `laravel/telescope`, `barryvdh/laravel-debugbar`, `roave/security-advisories`.

---

## References & Further Study
- PHP FIG standards: PSR-1/4/7/12/18/23/24.
- Symfony Docs: service container, Messenger, HttpClient, Security.
- Laravel Docs: HTTP resources, queues, events, testing, Scout.
- OWASP ASVS & Cheat Sheets for security checklists.
- Doctrine ORM performance tuning guide.
- API Platform and JSON:API specification.
- OpenTelemetry PHP instrumentation guides.


