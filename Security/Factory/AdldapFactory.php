<?php


namespace Riper\Security\ActiveDirectoryBundle\Security\Factory;


use Riper\Security\ActiveDirectoryBundle\Exception\WrongTokenException;
use Riper\Security\ActiveDirectoryBundle\Service\AdldapService;
use Riper\Security\ActiveDirectoryBundle\Token\FaultyToken;
use Symfony\Component\Security\Core\SecurityContext;

class AdldapFactory
{

    /**
     * @var SecurityContext
     */
    private $securityContext;

    /**
     * @var AdldapService
     */
    private $adldapService;

    public function __construct(SecurityContext $securityContext, AdldapService $adldapService)
    {
        $this->securityContext = $securityContext;
        $this->adldapService = $adldapService;
    }


    public function getAuthenticatedAdLdap()
    {
        $token = $this->securityContext->getToken();
        if ($token instanceof FaultyToken) {
            throw new WrongTokenException(
                'The token is not the right one. Did you forget to set "keep_password_in_token" to "true" in bundle configuration ?'
            );
        }
        $adldap = $this->adldapService->getInstance();
        $adldap->authenticate($token->getUsername(), $token->getCredentials());
    }

}