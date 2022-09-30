<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Security\Authenticator;

use _PHPStan_3bfe2e67c\Nette\Neon\Exception;
use Firebase\JWT\JWT;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use League\Bundle\OAuth2ServerBundle\Security\Exception\OAuth2AuthenticationException;
use League\Bundle\OAuth2ServerBundle\Security\Exception\OAuth2AuthenticationFailedException;
use League\Bundle\OAuth2ServerBundle\Security\Passport\Badge\ScopeBadge;
use League\Bundle\OAuth2ServerBundle\Security\User\NullUser;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * @author Mathias Arlaud <mathias.arlaud@gmail.com>
 */
final class OAuth2Authenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface
{
    /**
     * @psalm-suppress UndefinedTrait
     * @psalm-suppress MethodSignatureMismatch
     */
    use ForwardCompatAuthenticatorTrait;

    /**
     * @var HttpMessageFactoryInterface
     */
    private $httpMessageFactory;

    /**
     * @var ResourceServer
     */
    private $resourceServer;

    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    private $authorizationValidator;

    /**
     * @var string
     */
    private $rolePrefix;

    private $accessTokenRepo;

    /**
     * @var Configuration
     */
    private $jwtConfiguration;

    public function __construct(
        HttpMessageFactoryInterface $httpMessageFactory,
        ResourceServer $resourceServer,
        UserProviderInterface $userProvider,
        string $rolePrefix,
        AccessTokenRepositoryInterface $accessTokenRepo,
        KernelInterface $kernel
    ) {
        $this->httpMessageFactory = $httpMessageFactory;
        $this->resourceServer = $resourceServer;
        $this->userProvider = $userProvider;
        $this->rolePrefix = $rolePrefix;
        $this->accessTokenRepo = $accessTokenRepo;
        $this->kernel = $kernel;
    }

    public function supports(Request $request): ?bool
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText('empty', 'empty')
        );

        $cryptKey = new CryptKey($this->kernel->getProjectDir() . '/config/keys/public.key');

        $this->jwtConfiguration->setValidationConstraints(
            \class_exists(StrictValidAt::class)
                ? new StrictValidAt(new SystemClock(new \DateTimeZone(\date_default_timezone_get())))
                : new ValidAt(new SystemClock(new \DateTimeZone(\date_default_timezone_get()))),
            new SignedWith(
                new Sha256(),
                InMemory::plainText($cryptKey->getKeyContents(), $cryptKey->getPassPhrase() ?? '')
            )
        );

        $header = $request->headers->get('Authorization', '');
        $jwt = \trim((string) \preg_replace('/^\s*Bearer\s/', '', $header));

        try {
            // Attempt to parse the JWT
            $token = $this->jwtConfiguration->parser()->parse($jwt);
        } catch (\Lcobucci\JWT\Exception $exception) {
            return false;
        }

        try {
            // Attempt to validate the JWT
            $constraints = $this->jwtConfiguration->validationConstraints();
            $this->jwtConfiguration->validator()->assert($token, ...$constraints);
        } catch (RequiredConstraintsViolated $exception) {
            return false;
        }

        return 0 === strpos($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new Response('', 401, ['WWW-Authenticate' => 'Bearer']);
    }

    /**
     * {@inheritdoc}
     *
     * @return Passport
     */
    public function doAuthenticate(Request $request) /* : Passport */
    {
        try {
            $psr7Request = $this->resourceServer->validateAuthenticatedRequest($this->httpMessageFactory->createRequest($request));
        } catch (OAuthServerException $e) {
            throw OAuth2AuthenticationFailedException::create('The resource server rejected the request.', $e);
        }

        /** @var string $userIdentifier */
        $userIdentifier = $psr7Request->getAttribute('oauth_user_id', '');

        /** @var string $accessTokenId */
        $accessTokenId = $psr7Request->getAttribute('oauth_access_token_id');

        /** @var list<string> $scopes */
        $scopes = $psr7Request->getAttribute('oauth_scopes', []);

        /** @var string $oauthClientId */
        $oauthClientId = $psr7Request->getAttribute('oauth_client_id', '');

        $userLoader = function (string $userIdentifier): UserInterface {
            if ('' === $userIdentifier) {
                return new NullUser();
            }
            if (!method_exists($this->userProvider, 'loadUserByIdentifier')) {
                /** @psalm-suppress DeprecatedMethod */
                return $this->userProvider->loadUserByUsername($userIdentifier);
            }

            return $this->userProvider->loadUserByIdentifier($userIdentifier);
        };

        $passport = new SelfValidatingPassport(new UserBadge($userIdentifier, $userLoader), [
            new ScopeBadge($scopes),
        ]);

        $passport->setAttribute('accessTokenId', $accessTokenId);
        $passport->setAttribute('oauthClientId', $oauthClientId);

        return $passport;
    }

    /**
     * @return OAuth2Token
     *
     * @psalm-suppress DeprecatedClass
     */
    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        if (!$passport instanceof Passport) {
            throw new \RuntimeException(sprintf('Cannot create a OAuth2 authenticated token. $passport should be a %s', Passport::class));
        }

        $token = $this->createToken($passport, $firewallName);
        $token->setAuthenticated(true);

        return $token;
    }

    /**
     * @return OAuth2Token
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        /** @var string $accessTokenId */
        $accessTokenId = $passport->getAttribute('accessTokenId');

        /** @var ScopeBadge $scopeBadge */
        $scopeBadge = $passport->getBadge(ScopeBadge::class);

        /** @var string $oauthClientId */
        $oauthClientId = $passport->getAttribute('oauthClientId', '');

        $token = new OAuth2Token($passport->getUser(), $accessTokenId, $oauthClientId, $scopeBadge->getScopes(), $this->rolePrefix);
        if (method_exists(AuthenticatorInterface::class, 'createAuthenticatedToken') && !method_exists(AuthenticatorInterface::class, 'createToken')) {
            // symfony 5.4 only
            /** @psalm-suppress TooManyArguments */
            $token->setAuthenticated(true, false);
        }

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        if ($exception instanceof OAuth2AuthenticationException) {
            return new Response($exception->getMessage(), $exception->getStatusCode(), $exception->getHeaders());
        }

        throw $exception;
    }
}
