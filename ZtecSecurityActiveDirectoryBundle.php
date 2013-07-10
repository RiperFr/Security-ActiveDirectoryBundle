<?php

namespace Ztec\Security\ActiveDirectoryBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Ztec\Security\ActiveDirectoryBundle\Security\Factory\AdAuthFactory;

class ZtecSecurityActiveDirectoryBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new AdAuthFactory());
    }
}
