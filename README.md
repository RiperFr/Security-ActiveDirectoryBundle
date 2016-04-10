Riper/Security/ActiveDirectory
======================================

This package is a bundle for Symfony 2. It uses the standard form_login security model to authenticate user from an Active Directory domain.
It uses LDAP as communication layer, so you need the LDAP extension installed on your server to make it work.


[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/RiperFr/Security-ActiveDirectoryBundle/badges/quality-score.png?b=v2.x)](https://scrutinizer-ci.com/g/RiperFr/Security-ActiveDirectoryBundle/?branch=v2.x)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/3628b49a-0ab1-4412-94cf-328809040af1/big.png)](https://insight.sensiolabs.com/projects/3628b49a-0ab1-4412-94cf-328809040af1)

Requirements
----------------
php 5.3.0

php_ldap

ssl configuration for LDAP. see http://adldap.sourceforge.net/wiki/doku.php?id=ldap_over_ssl

Compatible with Symfony 2 starting from 2.1


Installation
----------------

You need to add a package to your dependency list :

    // composer.json
    "riper/security-active_directory": "2.*"

You need to enable the bundle into your kernel

    // app/AppKernel.php
    new Riper\Security\ActiveDirectoryBundle\RiperActiveDirectoryBundle(),

You need to configure your domain specific information

    // app/config/config.yml or app/config/parameters.yml
    parameters:
        riper.security.active_directory.settings:
            account_suffix : riper.fr # without the @ at the beginning
            base_dn : DC=RIPER,DC=FR #The DN of the domain
            domain_controllers : [ baudrive.kim.riper.fr ] #Servers to use for ldap connection (Random)
            admin_username: #Null to use the userConnection
            admin_password: #Null to use the userConnection
            keep_password_in_token: false #Set to true if you want to re-use the adldap instance to make further queries (This is a security issue because the password is kept in session)
            real_primarygroup : true #For Linux compatibility.
            use_ssl : false #Set it true need configuration of the server to be useful
            use_tls : false #Set it true need configuration of the server to be useful
            recursive_grouproles: false #recursive group roles
            username_validation_pattern: /^[a-z0-9-.]+$/i #Regex that check the final username value (extracted from patterns below). Must be compliant with your Active Directory username policy.
            username_patterns: #username is extracted from the string the user put into the login form
              - /([^@]*)@riper.fr/i  # like toto@riper.fr
              - /RIPER\\(.*)/i #like RIPER\toto
              - /RIPER.FR\\(.*)/i #like RIEPER.FR\toto
              - /(.*)/i #like toto

You need to add security parameters

    // app/config/security.yml
    encoders:
        Riper\Security\ActiveDirectoryBundle\Security\User\AdUser : plaintext #Active directory does not support encrypted password yet

    providers:
        my_active_directory_provider :
              id: riper.security.active.directory.user.provider

    firewalls:
        secured_area:
            active_directory: #Replace the 'form_login' line with this
                    check_path: /demo/secured/login_check
                    login_path: /demo/secured/login


Useful information
----------------------

Roles are got from Active directory. The name is transformed to match the ROLE system of Symfony2

    Domain User => ROLE_DOMAIN_USER
    Administrators => ROLE_ADMINISTRATORS

Nested Groups are not supported yet. Enabling the option wont affect the Role check.

SSL part of the lib isn't used yet and haven't been tested with Symfony
