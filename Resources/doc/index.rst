Active Directory authentication bundle
============

To use this bundle, place it into your vendors with composer

add this config to the main app/config
    ztec.security.active_directory.settings:
            account_suffix : riper.fr # without the @ at the beginning
            base_dn : DC=RIPER,DC=FR #The DN of the domain
            domain_controllers : [ DC.riper.fr ] #Servers to use for ldap connexion (Random)
            admin_username: #Null to use the userConnexion
            admin_password: #Null to use the userConnexion
            real_primarygroup : true #For Linux compatibility.
            use_ssl : false #Set it true need configuration of the server to be usefull
            use_tls : false #Set it true need configuration of the server to be usefull
            recursive_groups : false #Used Only for group test (not userInfo)
            sso : false
            username_patterns: #Define pattern allowed. The first selector is the username
              - /([^@]*)@riper.fr/i
              - /RIPER\\(.*)/i
              - /RIPER.FR\\(.*)/i
              - /(.*)/i