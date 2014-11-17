<?php

namespace Ztec\Security\ActiveDirectoryBundle\Security\Authentication;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Translation\TranslatorInterface;
use Ztec\Security\ActiveDirectoryBundle\Security\User\adUserProvider;
use Ztec\Security\ActiveDirectoryBundle\Security\User\adUser;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Ztec\Security\ActiveDirectoryBundle\Service\AdldapService;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class AdAuthProvider implements AuthenticationProviderInterface
{

    /**
     * @var \Ztec\Security\ActiveDirectoryBundle\Security\User\adUserProvider
     */
    private $userProvider;
    /**
     * @var TranslatorInterface
     */
    private $translator;

    public function __construct(
        adUserProvider $userProvider,
        array $config,
        AdldapService $AdldapService,
        TranslatorInterface $translator,
        $tokenClass
    ) {
        $this->userProvider  = $userProvider;
        $this->config        = $config;
        $this->AdldapService = $AdldapService;
        $this->translator    = $translator;
        $this->tokenClass    = $tokenClass;
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
        $User   = $this->userProvider->loadUserByUsername($token->getUsername());
        if ($User instanceof adUser) {
            if (!$Adldap->authenticate($User->getUsername(), $token->getCredentials())) {
                $msg = $this->translator->trans(
                    'ztec.security.active_directory.wrong_credential'
                ); //'The credentials are wrong'
                throw new BadCredentialsException($msg);
            }
            $this->userProvider->fetchData($User, $token, $Adldap);
        }

        $newToken = new $this->tokenClass(
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
