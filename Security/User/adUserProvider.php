<?php
namespace Ztec\Security\ActiveDirectoryBundle\Security\User;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Ztec\Security\ActiveDirectoryBundle\Service\AdldapService;
use adLDAP\adLDAP ;

class adUserProvider implements UserProviderInterface
{
    private $usernamePatterns = array() ;
    public function __construct(ContainerInterface $Container, AdldapService $AdldapService)
    {
        $this->container = $Container;
        $this->AdldapService = $AdldapService ;
        $config = $Container->getParameter('ztec.security.active_directory.settings');
        if (isset($config['username_patterns']) && is_array($config['username_patterns'])) {
            foreach ($config['username_patterns'] as $pat) {
                array_push($this->usernamePatterns, $pat);
            }
        }
    }


    /**
     * Loads the user for the given username.
     *
     * This method must throw UsernameNotFoundException if the user is not
     * found.
     *
     * @param string $username The username
     *
     * @return adUser
     *
     * @see UsernameNotFoundException
     *
     * @throws UsernameNotFoundException if the user is not found
     *
     */
    public function loadUserByUsername($username)
    {

        $user = new adUser($this->getUsernameFromString($username),'42',array());
        return $user;
        //throw new UsernameNotFoundException(sprintf('Username "%s" does not exist.', $username));
    }

    public function getUsernameFromString($string)
    {
        $username = $string;
        foreach ($this->usernamePatterns as $pattern) {
            if ($username == $string && preg_match($pattern, $string, $results)) {
                $username = $results[1];
                break;
            }
        }
        $username = strtolower($username);
        /*echo $username ;*/
        if (preg_match('/^[a-z0-9-.]+$/i', $username) == true) {
            /* echo 'ok';
             exit();*/
            return $username;
        }
        /*echo 'bad';
        exit();*/
        throw new \InvalidArgumentException('The username does not match any rules');
    }

    /**
     * Refreshes the user for the account interface.
     *
     * It is up to the implementation to decide if the user data should be
     * totally reloaded (e.g. from the database), or if the UserInterface
     * object can just be merged into some internal array of users / identity
     * map.
     * @param UserInterface $user
     *
     * @return UserInterface
     *
     * @throws UnsupportedUserException if the account is not supported
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof adUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }
        $newUser = $this->loadUserByUsername($user->getUsername());
        $newUser->setPassword($user->getPassword()); //we reset the password
        return $newUser;
    }


    public function fetchData(adUser $adUser, adLDAP $adLdap){
        $connected = $adLdap->connect();
        $isAD = $adLdap->authenticate($adUser->getUsername(),$adUser->getPassword());
        if(!$isAD || !$connected){
            throw new \Exception('Active directory dit not respond well '.var_export($isAD,1). ' - '.var_export($connected,1));
        }
        $user = $adLdap->user()->infoCollection($adUser->getUsername());
        //$userInfo = $adLdap->user_info($this->username);

        if ($user) {
            $groups = array();
            //$allGroups = $adLdap->search_groups(ADLDAP_SECURITY_GLOBAL_GROUP,true);
            foreach($user->memberOf as $k=>$group){
                if($k !== 'count'){
                    $reg = '#CN=([^,]*)#' ;
                    preg_match_all($reg,$group,$out);
                    $groups[] = $out[1][0] ;
                    /* if(array_key_exists($out[1][0],$allGroups)){
                         $groups[$out[1][0]] = $allGroups[$out[1][0]];
                     }*/
                }
            }
            /** End Fetching */

            $roles = array('USER','Domain_users');
            $sfRoles = array();
            foreach($groups as $r){
                $sfRoles[] = 'ROLE_'.strtoupper(str_replace(' ','_',$r));
            }
            $adUser->setRoles($sfRoles);
            return TRUE ;
        }
    }

    /**
     * Whether this provider supports the given user class
     *
     * @param string $class
     *
     * @return Boolean
     */
    public function supportsClass($class)
    {
        return $class === 'Ztec\Security\ActiveDirectoryBundle\Security\User\adUser';
    }
}