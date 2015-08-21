<?php

namespace Riper\Security\ActiveDirectoryBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Riper\Security\ActiveDirectoryBundle\Security\Factory\AdAuthFactory;

class RiperActiveDirectoryBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new AdAuthFactory());
    }
}
