Ztec/Security/ActiveDirectory
======================================

This package is a bundle for symfony 2.1. It use the standard form_login security model to authenticate user from an Active Directory domain.
It use LDAP as communication layer. So you need the LDAP extension installed on your server to make it work.

Requirements
----------------
php 5.2.4

php_ldap

ssl configuration for LDAP. see see http://adldap.sourceforge.net/wiki/doku.php?id=ldap_over_ssl

Symfony 2.1


Installation
----------------

You need to add a package to your dependency list :

    //composer.json
    "ztec/security-active_directory": "dev-master"

You need to enable the bundle into your kernel

    //app/AppKernel.php
    new Ztec\Security\ActiveDirectoryBundle\ZtecSecurityActiveDirectoryBundle(),

You need to configure your domain specific information

    //app/config/config.yml or app/config/parameters.yml
    parameters:
        ztec.security.active_directory.settings:
            account_suffix : riper.fr # without the @ at the beginning
            base_dn : DC=RIPER,DC=FR #The DN of the domain
            domain_controllers : [ baudrive.kim.riper.fr ] #Servers to use for ldap connection (Random)
            admin_username: #Null to use the userConnection
            admin_password: #Null to use the userConnection
            real_primarygroup : true #For Linux compatibility.
            use_ssl : false #Set it true need configuration of the server to be usefull
            use_tls : false #Set it true need configuration of the server to be usefull
			recursive_grouproles: false #recursive group roles
            username_patterns: #username is extracted from the string the user put into the login form
              - /([^@]*)@riper.fr/i  # like toto@riper.fr
              - /RIPER\\(.*)/i #like RIPER\toto
              - /RIPER.FR\\(.*)/i #like RIEPER.FR\toto
              - /(.*)/i #like toto

You need to add security parameters

    //app/config/security.yml
    encoders:
        Ztec\Security\ActiveDirectoryBundle\Security\User\adUser : plaintext #Active directory does not support encrypted password yet

    providers:
        my_active_directory_provider :
              id: ztec.security.active.directory.user.provider

    firewalls:
        secured_area:
            active_directory: #Replace the 'form_login' line with this
                    check_path: /demo/secured/login_check
                    login_path: /demo/secured/login


Useful information
----------------------

Roles are got from Active directory. The name is transform to match the ROLE system of Symfony2

    Domain User => ROLE_DOMAIN_USER
    Administrators = ROLE_ADMINISTRATORS

Nested Group are not supported yet. Enabling the option wont affect the Role check

SSL part of the lib isn't used yet and haven't been tested with Symfony
