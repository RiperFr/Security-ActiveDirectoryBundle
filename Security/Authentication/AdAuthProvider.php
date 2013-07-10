<?php

namespace Ztec\Security\ActiveDirectoryBundle\Security\Authentication;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Ztec\Security\ActiveDirectoryBundle\Security\User\adUserProvider;
use Ztec\Security\ActiveDirectoryBundle\Security\User\adUser;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Ztec\Security\ActiveDirectoryBundle\Service\AdldapService;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class AdAuthProvider implements AuthenticationProviderInterface
{

    /**
     * @var \Ztec\Security\ActiveDirectoryBundle\Security\User\adUserProvider
     */
    private $userProvider;
    private $messageBadCredentials = 'The credentials are wrong';

    public function __construct(adUserProvider $userProvider, $config, AdldapService $AdldapService, ContainerInterface $Container)
    {
        $this->userProvider = $userProvider;
        $this->config = $config;
        $this->AdldapService = $AdldapService;

        $this->container = $Container;
        $settings = $Container->getParameter('ztec.security.active_directory.settings');

        if (isset($settings['message_bad_credentials'])) {
            $this->messageBadCredentials = $settings['message_bad_credentials'];
        }
    }

    /**
     * Attempts to authenticates a TokenInterface object.
     *
     * @param TokenInterface $token The TokenInterface instance to authenticate
     *
     * @return TokenInterface An authenticated TokenInterface instance, never null
     *
     * @throws AuthenticationException if the authentication fails
     */
    public function authenticate(TokenInterface $token)
    {
        $Adldap = $this->AdldapService->getInstance();
        $User = $this->userProvider->loadUserByUsername($token->getUsername());
        if ($User instanceof adUser) {
            if (!$Adldap->authenticate($User->getUsername(), $token->getCredentials())) {
                throw new BadCredentialsException($this->messageBadCredentials);
            }
            $User->setPassword($token->getCredentials());
            $this->userProvider->fetchData($User, $Adldap);
        }

        $newToken = new UsernamePasswordToken(
            $User,
            $token->getCredentials(),
            "ztec.security.active.directory.user.provider",
            $User->getRoles()
        );

        return $newToken;
    }

    /**
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token A TokenInterface instance
     *
     * @return Boolean true if the implementation supports the Token, false otherwise
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken;
    }
}
