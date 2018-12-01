<?php
// wee-auth.php for PHPMYADMIN version 4.0.5

//##################################

if (version_compare(PHP_VERSION, '5.2.0', 'lt')) {
    die('PHP 5.2+ is required');
}

if (!defined('E_DEPRECATED')) {
    define('E_DEPRECATED', 8192);
}

define('PHPMYADMIN', true);

require './libraries/Error_Handler.class.php';
$GLOBALS['error_handler'] = new PMA_Error_Handler();
$cfg['Error_Handler']['display'] = true;
if (version_compare(phpversion(), '5.3', 'lt')) {
    @ini_set('zend.ze1_compatibility_mode', false);
}

if (version_compare(phpversion(), '5.4', 'lt')) {
    @ini_set('magic_quotes_runtime', false);
}

require './libraries/core.lib.php';
require './libraries/sanitizing.lib.php';

if (! function_exists('mb_detect_encoding')) {
    PMA_warnMissingExtension('mbstring', $fatal = true);
}

require './libraries/Theme.class.php';
require './libraries/Theme_Manager.class.php';
require './libraries/Config.class.php';
require './libraries/relation.lib.php';
require './libraries/Tracker.class.php';
require './libraries/Table.class.php';
require './libraries/Types.class.php';

if (! defined('PMA_MINIMUM_COMMON')) {
    include_once './libraries/Util.class.php';
    include_once './libraries/js_escape.lib.php';
    include_once './libraries/url_generating.lib.php';
    include_once 'libraries/Response.class.php';
}

$PMA_PHP_SELF = PMA_getenv('PHP_SELF');
$_PATH_INFO = PMA_getenv('PATH_INFO');
if (! empty($_PATH_INFO) && ! empty($PMA_PHP_SELF)) {
    $path_info_pos = strrpos($PMA_PHP_SELF, $_PATH_INFO);
    if ($path_info_pos + strlen($_PATH_INFO) === strlen($PMA_PHP_SELF)) {
        $PMA_PHP_SELF = substr($PMA_PHP_SELF, 0, $path_info_pos);
    }
}
$PMA_PHP_SELF = htmlspecialchars($PMA_PHP_SELF);

$variables_whitelist = array (
    'GLOBALS',
    '_SERVER',
    '_GET',
    '_POST',
    '_REQUEST',
    '_FILES',
    '_ENV',
    '_COOKIE',
    '_SESSION',
    'error_handler',
    'PMA_PHP_SELF',
    'variables_whitelist',
    'key'
);
$__redirect = null;
if (isset($_POST['usesubform'])) {
    // if a subform is present and should be used
    // the rest of the form is deprecated
    $subform_id = key($_POST['usesubform']);
    $subform    = $_POST['subform'][$subform_id];
    $_POST      = $subform;
    $_REQUEST   = $subform;
    if (isset($_POST['redirect'])
        && $_POST['redirect'] != basename($PMA_PHP_SELF)
    ) {
        $__redirect = $_POST['redirect'];
        unset($_POST['redirect']);
    }
    unset($subform_id, $subform);
} else {
    $_REQUEST = array_merge($_GET, $_POST);

    if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc()) {
        PMA_arrayWalkRecursive($_GET, 'stripslashes', true);
        PMA_arrayWalkRecursive($_POST, 'stripslashes', true);
        PMA_arrayWalkRecursive($_COOKIE, 'stripslashes', true);
        PMA_arrayWalkRecursive($_REQUEST, 'stripslashes', true);
    }
}

date_default_timezone_set(@date_default_timezone_get());

if (! function_exists('preg_replace')) {
    PMA_warnMissingExtension('pcre', true);
}

if (! function_exists('json_encode')) {
    PMA_warnMissingExtension('json', true);
}

$GLOBALS['PMA_Config'] = new PMA_Config(CONFIG_FILE);
// THIS FILLS THE GLOBALS TABLE

if (!defined('PMA_MINIMUM_COMMON')) {
    $GLOBALS['PMA_Config']->checkPmaAbsoluteUri();
}

$GLOBALS['PMA_Config']->enableBc();

//##################################

require './libraries/session.inc.php';

$GLOBALS['db'] = '';
if (PMA_isValid($_REQUEST['db'])) {
    $GLOBALS['db'] = $_REQUEST['db'];
    $GLOBALS['url_params']['db'] = $GLOBALS['db'];
}

$GLOBALS['table'] = '';
if (PMA_isValid($_REQUEST['table'])) {
    $GLOBALS['table'] = $_REQUEST['table'];
    $GLOBALS['url_params']['table'] = $GLOBALS['table'];
}

if (PMA_isValid($_REQUEST['selected_recent_table'])) {
    $recent_table = json_decode($_REQUEST['selected_recent_table'], true);
    $GLOBALS['db'] = $recent_table['db'];
    $GLOBALS['url_params']['db'] = $GLOBALS['db'];
    $GLOBALS['table'] = $recent_table['table'];
    $GLOBALS['url_params']['table'] = $GLOBALS['table'];
}

$GLOBALS['sql_query'] = '';
if (PMA_isValid($_REQUEST['sql_query'])) {
    $GLOBALS['sql_query'] = $_REQUEST['sql_query'];
}

require './libraries/select_lang.lib.php';

if ($GLOBALS['text_dir'] == 'ltr') {
    $GLOBALS['cell_align_left']  = 'left';
    $GLOBALS['cell_align_right'] = 'right';
} else {
    $GLOBALS['cell_align_left']  = 'right';
    $GLOBALS['cell_align_right'] = 'left';
}

$GLOBALS['PMA_Config']->checkPermissions();

if ($GLOBALS['PMA_Config']->error_config_file) {
    $error = '[strong]' . __('Failed to read configuration file') . '[/strong]'
        . '[br][br]'
        . __('This usually means there is a syntax error in it, please check any errors shown below.')
        . '[br][br]'
        . '[conferr]';
    trigger_error($error, E_USER_ERROR);
}
if ($GLOBALS['PMA_Config']->error_config_default_file) {
    $error = sprintf(
        __('Could not load default configuration from: %1$s'),
        $GLOBALS['PMA_Config']->default_source
    );
    trigger_error($error, E_USER_ERROR);
}
if ($GLOBALS['PMA_Config']->error_pma_uri) {
    trigger_error(
        __('The [code]$cfg[\'PmaAbsoluteUri\'][/code] directive MUST be set in your configuration file!'),
        E_USER_ERROR
    );
}


if (! defined('PMA_MINIMUM_COMMON')) {
    if (isset($_REQUEST['server'])
        && (is_string($_REQUEST['server']) || is_numeric($_REQUEST['server']))
        && ! empty($_REQUEST['server'])
        && ! empty($cfg['Servers'][$_REQUEST['server']])
    ) {
        $GLOBALS['server'] = $_REQUEST['server'];
        $cfg['Server'] = $cfg['Servers'][$GLOBALS['server']];
    } else {
        if (!empty($cfg['Servers'][$cfg['ServerDefault']])) {
            $GLOBALS['server'] = $cfg['ServerDefault'];
            $cfg['Server'] = $cfg['Servers'][$GLOBALS['server']];
        } else {
            $GLOBALS['server'] = 0;
            $cfg['Server'] = array();
        }
    }
    $GLOBALS['url_params']['server'] = $GLOBALS['server'];

    if (function_exists('mb_convert_encoding')
        && $lang == 'ja'
    ) {
        include_once './libraries/kanji-encoding.lib.php';
    } // end if

    $GLOBALS['PMA_Config']->setCookie('pma_lang', $GLOBALS['lang']);
    if (isset($GLOBALS['collation_connection'])) {
        $GLOBALS['PMA_Config']->setCookie(
            'pma_collation_connection',
            $GLOBALS['collation_connection']
        );
    }
    $_SESSION['PMA_Theme_Manager']->setThemeCookie();

    if (! empty($cfg['Server'])) {

        include_once './libraries/database_interface.lib.php';

        include_once './libraries/logging.lib.php';

        $cache_key = 'server_' . $GLOBALS['server'];
        if (isset($_SESSION['cache'][$cache_key]['userprefs']['LoginCookieValidity'])) {
            $value = $_SESSION['cache'][$cache_key]['userprefs']['LoginCookieValidity'];
            $GLOBALS['PMA_Config']->set('LoginCookieValidity', $value);
            $GLOBALS['cfg']['LoginCookieValidity'] = $value;
            unset($value);
        }
        unset($cache_key);
        
	// Gets the authentication library that fits the $cfg['Server'] settings
        // and run authentication

        $cfg['Server']['auth_type'] = strtolower($cfg['Server']['auth_type']);

        $auth_class = "Authentication" . ucfirst($cfg['Server']['auth_type']);
        if (! file_exists('./libraries/plugins/auth/' . $auth_class . '.class.php')) {
            PMA_fatalError(
                __('Invalid authentication method set in configuration:')
                . ' ' . $cfg['Server']['auth_type']
            );
        }
        include_once  './libraries/plugins/auth/' . $auth_class . '.class.php';
        $plugin_manager = null;
        $auth_plugin = new $auth_class($plugin_manager);

        if (! $auth_plugin->authCheck()) {
            /* Force generating of new session on login */
            PMA_secureSession();
            $auth_plugin->auth();
        } else {
            $auth_plugin->authSetUser();
        }
    }
}

//$USERID = $GLOBALS['cfg']['Server']['user']; echo "<h1>".$USERID."</h1>";exit; 

//##################################
//print_r($_COOKIE);
if (isset($_COOKIE['pmaUser-1'])||($_COOKIE['pmaPass-1'])) {
     //$USERID = $GLOBALS['default_server']['user']; 
     $USERID = $GLOBALS['cfg']['Server']['user']; 
     // $_COOKIE is not valid source for the user id as it changes
     // $USERID = substr( $_COOKIE['pmaUser-1'],0,6);
     $GPGDIR = $GPGDIR."/".$USERID;
     if (! is_dir($GPGDIR)){
               mkdir ($GPGDIR,0700);     
     }
}     
else {
     die ("Not logged in.");
}
?>
