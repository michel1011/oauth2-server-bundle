<?php
/**
 * OAuth 2.0 Refresh token grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\Bundle\OAuth2ServerBundle\Grant;

use DateInterval;
use Doctrine\ORM\EntityManagerInterface;
use Exception;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestRefreshTokenEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Refresh token grant.
 */
class RefreshTokenGrant extends AbstractGrant
{

    private $entityManager;
    private $oldRefreshToken = false;

    /**
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(RefreshTokenRepositoryInterface $refreshTokenRepository, EntityManagerInterface $entityManager)
    {
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->entityManager = $entityManager;

        $this->refreshTokenTTL = new DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $oldRefreshToken = $this->validateOldRefreshToken($request, $client->getIdentifier());
        $scopes = $this->validateScopes(
            $this->getRequestParameter(
                'scope',
                $request,
                \implode(self::SCOPE_DELIMITER_STRING, $oldRefreshToken['scopes'])
            )
        );

        // The OAuth spec says that a refreshed access token can have the original scopes or fewer so ensure
        // the request doesn't include any new scopes
        foreach ($scopes as $scope) {
            if (\in_array($scope->getIdentifier(), $oldRefreshToken['scopes'], true) === false) {
                throw OAuthServerException::invalidScope($scope->getIdentifier());
            }
        }

        // Expire old tokens

        if (!$this->oldRefreshToken)
            $this->accessTokenRepository->revokeAccessToken($oldRefreshToken['access_token_id']);

        if ($this->revokeRefreshTokens) {


            if (!$this->oldRefreshToken) {
                $this->refreshTokenRepository->revokeRefreshToken($oldRefreshToken['refresh_token_id']);
            } else {
                $fosRefreshToken = $this->entityManager->getRepository('App\Entity\RefreshToken')->find($oldRefreshToken['refresh_token_id']);
                $this->entityManager->remove($fosRefreshToken);
                $this->entityManager->flush();
            }
        }

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $oldRefreshToken['user_id'], $scopes);
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));
        $responseType->setAccessToken($accessToken);


        // Issue and persist new refresh token if given
        if ($this->revokeRefreshTokens) {
            $refreshToken = $this->issueRefreshToken($accessToken);

            if ($refreshToken !== null) {
                $this->getEmitter()->emit(new RequestRefreshTokenEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request, $refreshToken));
                $responseType->setRefreshToken($refreshToken);
            }
        }

        return $responseType;
    }

    /**
     * @param ServerRequestInterface $request
     * @param string                 $clientId
     *
     * @throws OAuthServerException
     *
     * @return array
     */
    protected function validateOldRefreshToken(ServerRequestInterface $request, $clientId)
    {
        $encryptedRefreshToken = $this->getRequestParameter('refresh_token', $request);
        if (!\is_string($encryptedRefreshToken)) {
            throw OAuthServerException::invalidRequest('refresh_token');
        }

        //Custom code for old tokens

        $foundToken = $this->entityManager->getRepository('App\Entity\RefreshToken')->findOneBy(['token' => $encryptedRefreshToken]);
        if ($foundToken) {
            if ($clientId !== $foundToken->getClientId()) {
                $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
                throw OAuthServerException::invalidRefreshToken('Token is not linked to client');
            }

            if (time() > $foundToken->getExpiresAt()) {
                throw OAuthServerException::invalidRefreshToken('Token has expired');
            }
            $this->oldRefreshToken = true;
            $refreshTokenData = [
                'expires_time' => $foundToken->getExpiresAt(),
                'client_id' => $foundToken->getClient()->getId() . '_' . $foundToken->getClient()->getRandomId(),
                'refresh_token_id' => $foundToken->getId(),
                'scopes' => ['ROLE_USER'],
                'user_id' => $foundToken->getUser()->getUserIdentifier()
            ];
        } else {
            // Validate refresh token
            try {
                $refreshToken = $this->decrypt($encryptedRefreshToken);
            } catch (Exception $e) {
                throw OAuthServerException::invalidRefreshToken('Cannot decrypt the refresh token', $e);
            }

            $refreshTokenData = \json_decode($refreshToken, true);
            if ($refreshTokenData['client_id'] !== $clientId) {
                $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
                throw OAuthServerException::invalidRefreshToken('Token is not linked to client');
            }

            if ($refreshTokenData['expire_time'] < \time()) {
                throw OAuthServerException::invalidRefreshToken('Token has expired');
            }

            if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenData['refresh_token_id']) === true) {
                throw OAuthServerException::invalidRefreshToken('Token has been revoked');
            }
        }




        return $refreshTokenData;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'refresh_token';
    }
}
