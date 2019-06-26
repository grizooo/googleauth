<?php
namespace Sitegeist\GoogleAuth\Controller;

/*
 * This file is part of the Sitegeist.GoogleAuth package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use \Neos\Flow\Mvc\Controller\ActionController;
use League\OAuth2\Client\Provider\Google;
use Neos\Flow\Log\SecurityLoggerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Annotations as Flow;
use Neos\Neos\Domain\Model\User;
use Neos\Neos\Domain\Service\UserService;
use Neos\ContentRepository\Domain\Model\Workspace;
use Neos\ContentRepository\Domain\Repository\WorkspaceRepository;
use Neos\Neos\Utility\User as UserUtility;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Utility\Algorithms;


/**
 * @Flow\Scope("singleton")
 */
class LoginController extends ActionController
{
    /**
     * @var AccountRepository
     * @Flow\Inject
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var WorkspaceRepository
     */
    protected $workspaceRepository;

    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;


    /**
     * @Flow\InjectConfiguration(package="Sitegeist.GoogleAuth")
     * @var array
     */
    protected $settingsConfiguration;

    /**
     * @Flow\InjectConfiguration(package="Neos.Neos", path="userInterface.backendLoginForm.backgroundImage")
     * @var array
     */
    protected $settingsWallpaper;


    /**
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $logger;

    /**
     * @var Google
     */
    protected $googleAuth;



    /**
     * @return void
     */
    public function authenticateAction()
    {
        $arguments = $this->request->getArguments();
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        $this->googleAuth = new Google($this->settingsConfiguration['credentials']);

        if (!empty($arguments['error'])) {

            // Got an error, probably user denied access
            exit('Got error: ' . htmlspecialchars($arguments['error'], ENT_QUOTES, 'UTF-8'));

        } elseif (empty($arguments['code'])) {

            // If we don't have an authorization code then get one
            $authUrl = $this->googleAuth->getAuthorizationUrl();
            $_SESSION['oauth2state'] = $this->googleAuth->getState();
            header('Location: ' . $authUrl);
            exit;

        } elseif (empty($arguments['state']) || (isset($_SESSION['oauth2state']) && $arguments['state'] !== $_SESSION['oauth2state'])) {

            // State is invalid, possible CSRF attack in progress
            unset($_SESSION['oauth2state']);
            exit('Invalid state');

        } else {

            // Try to get an access token (using the authorization code grant)
            $token = $this->googleAuth->getAccessToken('authorization_code', [
                'code' => $arguments['code']
            ]);

            try {

                // We got an access token, let's now get the owner details
                $ownerDetails = $this->googleAuth->getResourceOwner($token);

                // Use these details to create a new profile
                $this->view->assign('name', $ownerDetails->getName());

                $password = Algorithms::generateRandomToken(32);

                $credentials = array(
                    "firstname" => $ownerDetails->getFirstName(),
                    "lastname" => $ownerDetails->getLastName(),
                    "username" => $ownerDetails->getEmail(),
                    "password" => $password
                );

                $this->createAccountForCredentials($credentials);
                $this->view->assign('username', $ownerDetails->getEmail());
                $this->view->assign('password', $password);

                $this->attachWallpaperFromSettings();

            } catch (\Exception $e) {
                $this->logger->log('Google authentication failed: ' . $e->getMessage(), LOG_ALERT);
                exit('Google authentication failed: ' . $e->getMessage());
            }

        }
    }

    /**
     *  Attaching wallpaper from configuration to view
     */
    private function attachWallpaperFromSettings() {
        $wallpaperPath = str_replace('resource://', '/_Resources/Static/Packages/', $this->settingsWallpaper);
        $wallpaperPath = str_replace('Public/', '', $wallpaperPath);

        $wallpaperBody = 'background-image: url(' . $wallpaperPath . ');';
        $this->view->assign('wallpaperBody', $wallpaperBody);

        $wallpaperHead = '.neos-login-box:before {' . $wallpaperBody . '}';
        $this->view->assign('wallpaperHead', $wallpaperHead);
    }


    /**
     * Create a new account for the given credentials. Return null if you
     * do not want to create a new account, that is, only authenticate
     * existing accounts from the database and fail on new logins.
     *
     * @param array $credentials array containing username and password
     * @return void
     */
    protected function createAccountForCredentials(array $credentials)
    {
        $user = $this->userService->getUser($credentials['username'], 'Neos.Neos:Backend');
        $roles = $this->getRoles($credentials['username']);
        if ($user) {
            //update password
            $this->userService->activateUser($user);
            $this->userService->setUserPassword($user, $credentials['password']);
            $this->persistenceManager->persistAll();
            $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($credentials['username'], 'Neos.Neos:Backend');
            $this->userService->setRolesForAccount($account, $roles);
        } else {
            //add user
            $user = $this->userService->createUser(
                $credentials['username'],
                $credentials['password'],
                $credentials['firstname'],
                $credentials['lastname'],
                $roles,
                'Neos.Neos:Backend'
            );
            $this->persistenceManager->persistAll();

            //create workspace
            $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($credentials['username'], 'Neos.Neos:Backend');
            $this->createPersonalWorkspace($user, $account);
        }

        $account->setExpirationDate(new \DateTime('+1 minutes'));
        $this->accountRepository->update($account);
        $this->persistenceManager->persistAll();

    }

    /**
     * @param null $username
     * @return array
     */
    protected function getRoles($username = null) {
        $roles = array();
        if ($username !== null) {
            $roles = $this->settingsConfiguration['roles']['default'];
            if (in_array($username, $this->settingsConfiguration['admins'])) {
                $roles = array_merge($roles, $this->settingsConfiguration['roles']['admin']);
            }
        }
        return $roles;
    }


    /**
     * Creates a personal workspace for the given user's account if it does not exist already.
     *
     * @param User $user The new user to create a workspace for
     * @param Account $account The user's backend account
     * @throws IllegalObjectTypeException
     */
    protected function createPersonalWorkspace(User $user, Account $account)
    {
        $userWorkspaceName = UserUtility::getPersonalWorkspaceNameForUsername($account->getAccountIdentifier());
        $userWorkspace = $this->workspaceRepository->findByIdentifier($userWorkspaceName);
        if ($userWorkspace === null) {
            $liveWorkspace = $this->workspaceRepository->findByIdentifier('live');
            if (!($liveWorkspace instanceof Workspace)) {
                $liveWorkspace = new Workspace('live');
                $liveWorkspace->setTitle('Live');
                $this->workspaceRepository->add($liveWorkspace);
            }

            $userWorkspace = new Workspace($userWorkspaceName, $liveWorkspace, $user);
            $userWorkspace->setTitle((string)$user->getName());
            $this->workspaceRepository->add($userWorkspace);
        }
    }


}
