<?php

namespace Riper\Security\ActiveDirectoryBundle\Service;

use adLDAP\adLDAP;

class AdldapService
{
    /**
     * @var adLDAP The instance of adLdap used for each call of the service
     */
    private $adLdap;

    /**
     * @var array The Active Directory parameters (see riper.security.active_directory.settings)
     */
    private $parameters;

    /**
     * Constructor for the service.
     *
     * @param array $parameters Active Directory parameters
     */
    public function __construct(array $parameters)
    {
        $parameters['account_suffix'] = '@' . $parameters['account_suffix'];
        $this->parameters = $parameters;
    }

    /**
     * Returns an adLDAP instance.
     *
     * @return adLDAP The instance of the adLdap (lib)
     */
    public function getInstance()
    {
        $this->adLdap = new adLDAP($this->parameters);

        return $this->adLdap;
    }
}
