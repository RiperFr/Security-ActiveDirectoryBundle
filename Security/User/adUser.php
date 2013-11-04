<?php

namespace Ztec\Security\ActiveDirectoryBundle\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

class adUser implements UserInterface
{
    /** @var string */
    private $username;

    /** @var string */
    private $password;

    /** @var string */
    private $salt;

    /** @var string */
    private $roles;

    /** @var string */
    private $displayName;

    /** @var string */
    private $email;

    public function __construct($username, $password, array $roles)
    {
        $this->username = $username;
        $this->password = $password;
        $this->salt = '';
        $this->roles = $roles;
    }

    /**
     * Returns the password used to authenticate the user.
     *
     * This should be the encoded password. On authentication, a plain-text
     * password will be salted, encoded, and then compared to this value.
     *
     * @return string The password
     */
    public function getPassword()
    {
        return $this->password;
    }

    public function setPassword($password)
    {
        $this->password = $password;
    }

    /**
     * Returns the salt that was originally used to encode the password.
     *
     * This can return null if the password was not encoded using a salt.
     *
     * @return string The salt
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * Returns the username used to authenticate the user.
     *
     * @return string The username
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Returns the display name of the authenticated user.
     *
     * @return string
     */
    public function getDisplayName() {
        return $this->displayName;
    }

    /**
     * Set the display name of the authenticated user.
     *
     * @param string $displayName
     */
    public function setDisplayName($displayName) {
        $this->displayName = $displayName;
    }

    /**
     * Returns the email address of the authenticated user.
     *
     * @return string
     */
    public function getEmail() {
        return $this->email;
    }

    /**
     * Set the email address of the authenticated user.
     *
     * @param string $email
     */
    public function setEmail($email) {
        $this->email = $email;
    }

    /**
     * Removes sensitive data from the user.
     *
     * This is important if, at any given point, sensitive information like
     * the plain-text password is stored on this object.
     *
     * @return void
     */
    public function eraseCredentials()
    {
        //return void;
    }

    /**
     * Returns the roles granted to the user.
     *
     * <code>
     * public function getRoles()
     * {
     *     return array('ROLE_USER');
     * }
     * </code>
     *
     * Alternatively, the roles might be stored on a ``roles`` property,
     * and populated in any number of different ways when the user object
     * is created.
     *
     * @return array Role[] The user roles
     */
    public function getRoles()
    {
        return  $this->roles;
    }

    public function setRoles(array $roles)
    {
        $this->roles = $roles;
    }
}
