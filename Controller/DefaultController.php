<?php

namespace Ztec\Security\ActiveDirectoryBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class DefaultController extends Controller
{
    public function indexAction($name)
    {
        return $this->render('ZtecSecurityActiveDirectoryBundle:Default:index.html.twig', array('name' => $name));
    }
}
