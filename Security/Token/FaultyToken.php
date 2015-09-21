<?php
namespace Riper\Security\ActiveDirectoryBundle\Security\Token;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class FaultyToken extends UsernamePasswordToken
{


    /**
     * This method cut of the behaviour in order to keep the password in the token
     * This is a bad practice, but is the only simple way to keep the password and reuse it after
     * For active directory authentication
     */
    public function eraseCredentials()
    {

    }
}