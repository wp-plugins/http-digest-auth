<?php
/*
Plugin Name: HTTP Digest Authentication
Plugin URI: http://jesin.tk/wordpress-plugins/http-digest-authentication/
Description: Secure your <strong>wp-login.php</strong> page with <a href="http://en.wikipedia.org/wiki/Digest_access_authentication">HTTP Digest Authentication</a> without the need of Web server config changes or additional modules.
Version: 1.2
Author: Jesin
Author URI: http://jesin.tk
License: GPLv2 or later
*/

if ( !defined( 'DB_NAME' ) )
{
	header( 'HTTP/1.0 403 Forbidden' );
	die;
}

define( 'HTTP_DIGEST_AUTH_VERSION', '1.1' );

if( !class_exists('HTTP_Digest_Auth_plugin') )
{
	class HTTP_Digest_Auth_plugin
	{
		var $digestParts;
		var $slug;
		var $basename;

		function __construct()
		{
			$this->basename = plugin_basename( __FILE__ );
			$this->slug = str_replace( array( basename( __FILE__ ), '/' ), '', $this->basename );

			add_action( 'init', array( $this, 'plugin_init') );

			//Create default usernames and passwords for all users
			register_activation_hook( __FILE__ , array( $this, 'plugin_activate' ) );

			//Check if the HTTP credentials and WordPress credentials are for the same user
			add_action( 'wp_authenticate', array( $this, 'http_check' ) );

			//Create default HTTP credentials when a new user registers
			add_action( 'user_register', array( $this, 'add_user_credentials' ) );

			//Clear the HTTP Digest realm when a user logs out
			add_action( 'wp_logout', array( $this, 'clear_realm' ) );

			//Show the HTTP username in the wp-login.php form
			add_action( 'login_form', array ( $this, 'show_logged_in' ) );

			//Display HTTP credentials when a new user registers
			add_filter( 'login_message', array( $this, 'message_registration' ) );
		}

		function plugin_activate()
		{
			//Create default HTTP Digest credentials for all users when the plugin is activated
			$users = get_users();
			foreach( $users as $user )
			{
				$username = get_user_meta( $user->ID, $this->slug.'_username' );
				$password = get_user_meta( $user->ID, $this->slug.'_password' );
				$anyone = get_user_meta( $user->ID, $this->slug.'_anyone' );

				if( empty( $username ) && empty( $password ) && empty( $anyone ) ) :
					add_user_meta( $user->ID, $this->slug.'_username', $user->user_login );
					add_user_meta( $user->ID, $this->slug.'_password', $this->encrypt( $user->user_login, 'password' ) );
					add_user_meta( $user->ID, $this->slug.'_anyone', '0' );
				endif;
			}
		}

		function plugin_init()
		{
			load_plugin_textdomain( $this->slug, false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );

			//Create a session to store the HTTP Digest username and realm
			if( !session_id() )
				session_start();

			//Prompt for HTTP authentication for the wp-login.php page and NOT the register page
			if( in_array( $GLOBALS['pagenow'], array('wp-login.php') ) && ( !isset( $_GET['action'] ) || 'register' != $_GET['action'] ) )
				$this->HTTP_Digest_Authenticate();
		}

		function user_credentials()
		{
			//Fetch the HTTP credentials from the database, decrypt them and return as an array
			$users = get_users();
			$credentials = array();
			$_SESSION['http_to_ID'] = array();

			foreach( $users as $user )
			{
				$username = get_user_meta( $user->ID, $this->slug.'_username', TRUE );
				$password = get_user_meta( $user->ID, $this->slug.'_password', TRUE );
				$credentials[$username] = $this->decrypt( $user->user_login, $password );
				$_SESSION['http_to_ID'][$username]['ID'] = $user->ID;
				$_SESSION['http_to_ID'][$username]['anyone'] = get_user_meta( $user->ID, $this->slug.'_anyone', TRUE );
			}

			return $credentials;
		}

		//Function which handles the HTTP Digest Auth process
		function HTTP_Digest_Authenticate()
		{
			//Generate a unique realm for each session
			if( !isset( $_SESSION['unique_realm'] ) )
				$_SESSION['unique_realm'] = base64_encode( time() );

			$realm = 'HTTP Auth Session '.$_SESSION['unique_realm'];

			// Just a random id
			$nonce = uniqid();

			// Get the digest from the http header
			$digest = $this->getDigest();

			// If there was no digest, show login
			if ( is_null( $digest ) )
				$this->requireLogin( $realm, $nonce );

			$this->digestParts = $this->digestParse( $digest );

			$users = $this->user_credentials();

			if ( ! isset( $users[ $this->digestParts['username'] ] ) )
				$this->requireLogin( $realm, $nonce );

			// Based on all the info we gathered we can figure out what the response should be
			$A1 = md5( $this->digestParts['username'] . ':' . $realm . ':' . ( isset($users[$this->digestParts['username']]) ? $users[$this->digestParts['username']] : NULL ) );
			$A2 = md5( $_SERVER['REQUEST_METHOD'].':'.$this->digestParts['uri'] );

			$validResponse = md5("{$A1}:{$this->digestParts['nonce']}:{$this->digestParts['nc']}:{$this->digestParts['cnonce']}:{$this->digestParts['qop']}:{$A2}");

			//Credentials aren't valid so prompt for credentials again
			if( $this->digestParts['response'] != $validResponse  )
				$this->requireLogin( $realm, $nonce );

			//Authentication success store the required data in Session variables
			$_SESSION['http_to_ID']['current_ID'] = $_SESSION['http_to_ID'][$this->digestParts['username']]['ID'];
			$_SESSION['http_to_ID']['current_user'] = $this->digestParts['username'];
			$_SESSION['http_to_ID']['current_anyone'] = $_SESSION['http_to_ID'][$this->digestParts['username']]['anyone'];
			
		}

		//Retrieve the authentication information from the request headers
		function getDigest()
		{
			$digest = NULL;

			if( isset( $_SERVER['PHP_AUTH_DIGEST'] ) )
				$digest = $_SERVER['PHP_AUTH_DIGEST'];

			elseif( isset( $_SERVER['HTTP_AUTHENTICATION'] ) )
				if ( 0 === strpos( strtolower( $_SERVER['HTTP_AUTHENTICATION'] ), 'digest' ) )
					$digest = substr( $_SERVER['HTTP_AUTHORIZATION'], 7 );

			return $digest;
		}

		//Make the browser prompt the user for credentials
		function requireLogin( $realm, $nonce )
		{
			header('WWW-Authenticate: Digest realm="' . $realm . '",qop="auth",nonce="' . $nonce . '",opaque="' . md5($realm) . '"');
			header('HTTP/1.0 401 Unauthorized');

			if ( isset( $_GET['checkemail'] ) && 'registered' == $_GET['checkemail'] )
				$uname = ( isset( $_SESSION['newuser'] ) ? $_SESSION['newuser'] : sprintf( __( '%sYour %s Username%s', $this->slug ), '&lt;<em>', 'WordPress', '</em>&gt;' ) );
			else
				$uname = sprintf( __( '%sYour %s Username%s', $this->slug ), '&lt;<em>', 'WordPress', '</em>&gt;' );

			$err_txt = sprintf( __( 'Valid credentials required to view this page.%s If you have not changed the default HTTP credentials try using %s', $this->slug ), '<br />', '<br />' );
			$err_txt .= '<ul>';
			$err_txt .= '<li>' . sprintf( __( 'Username: %s', $this->slug ), $uname ) . '</li>';
			$err_txt .= '<li>' . sprintf( __( 'Password: %s', $this->slug ), 'password' ) . '</li>';
			$err_txt .= '</ul>';
			wp_die( $err_txt, __( 'Access Denied', $this->slug ), array('response' => 401) );
		}

		//Parse the authentication information sent in the client request
		function digestParse( $digest )
		{
			$needed_parts = array( 'nonce' => 1,
				'nc' => 1,
				'cnonce' => 1,
				'qop' => 1,
				'username' => 1,
				'uri' => 1,
				'response' => 1
			);
			$data = array();
			$keys = implode( '|', array_keys( $needed_parts ) );
			preg_match_all( '@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $digest, $matches, PREG_SET_ORDER );

			foreach ($matches as $m)
			{
				$data[$m[1]] = str_replace( '\"', '', $m[3] ? $m[3] : $m[4]) ;
				unset( $needed_parts[$m[1]] );
			}

			return $needed_parts ? false : $data;
		}

		//Create default HTTP credentials when a new user registers
		function add_user_credentials( $user_ID )
		{
			$user = get_userdata( $user_ID );
			$username = get_user_meta( $user->ID, $this->slug.'_username' );
			$password = get_user_meta( $user->ID, $this->slug.'_password' );
			$anyone = get_user_meta( $user->ID, $this->slug.'_anyone' );

			if( empty( $username ) && empty( $password ) && empty( $anyone ) ) :
				$http_uname = $this->http_username( $user_ID, $user->user_login );
				add_user_meta( $user->ID, $this->slug.'_username', $http_uname );
				add_user_meta( $user->ID, $this->slug.'_password', $this->encrypt( $user->user_login, 'password' ) );
				add_user_meta( $user->ID, $this->slug.'_anyone', '0' );
			endif;

			if( isset( $_REQUEST['action'] ) && ( 'register' == $_REQUEST['action'] || 'createuser' == $_REQUEST['action'] ) )
				$_SESSION['newuser'] = $http_uname;
		}

		//Make the HTTP username unique by adding a number to it
		function http_username( $ID, $username, $n = 0 )
		{
			$generated = $n > 0 ? ( $username . $n ) : $username;
			$users = get_users( array ( 'exclude' => array( $ID ) ) );

			foreach( $users as $user ):
				if( get_user_meta( $user->ID, $this->slug.'_username', TRUE ) == $generated )
				{
					return $this->http_username( $ID, $username, $n + 1 );
				}
			endforeach;

			return $generated;
		}

		//Display HTTP credentials when a new user registers
		function message_registration( $message )
		{
			if ( isset( $_GET['checkemail'] ) && 'registered' == $_GET['checkemail'] )
			{
				$message .= '<p class="message">' . sprintf( __( "Your HTTP credentials are %sUsername: %sPassword: %s", $this->slug ), '<br /><br />', $_SESSION['newuser'] . '<br />', 'password</p>' );
				unset( $_SESSION['newuser'] );
			}

			return $message;
		}

		//Check if the HTTP credentials and WordPress credentials are for the same user
		function http_check( $username )
		{
			if( !username_exists($username) )
				return;

			$user_details = get_user_by( 'login', $username );

			if( $user_details->ID != $_SESSION['http_to_ID']['current_ID'] && '0' == $_SESSION['http_to_ID']['current_anyone'] )
				wp_die( __( 'Your WordPress credentials do not match with the HTTP digest credentials', $this->slug ), '', array( 'back_link' => TRUE ) );

			return;
		}

		//When the user logs out clear the realm
		function clear_realm()
		{
			if( !session_id() )
				session_start();

			//session_destroy();
			unset( $_SESSION['unique_realm'] );

			wp_die( sprintf( __( 'You&#39;ve successfully logged out of both WordPress and HTTP Digest.<br /><br />You may safely close the window.<br /><br /><a href="%s">Login again</a>' ), wp_login_url() ), 'Logged out', array( 'response' => 200 ) );
		}

		//Display the HTTP username on the wp-login.php form
		function show_logged_in()
		{
			echo '<p style="font-size:24px;margin:10px 0px;line-height:24px">';
			printf( __( 'HTTP login: %s' ), '<strong>' . $_SESSION['http_to_ID']['current_user'] . '</strong>' );
			echo '</p>';
			echo '<p style="margin-bottom:10px;text-align:right"><a title="Logout ' . $_SESSION['http_to_ID']['current_user'] . '" href="' . wp_logout_url() . '">Logout</a></p>';
		}

		//Custom function which encrypts the HTTP password before storing it in the database
		function encrypt( $key, $string )
		{
			if( !function_exists( 'mcrypt_encrypt' ) )
				return $string;

			return base64_encode( mcrypt_encrypt( MCRYPT_RIJNDAEL_256, md5( $key ), $string, MCRYPT_MODE_CBC, md5( md5( $key ) ) ) );
		}

		//Custom function which decrypts the HTTP password
		function decrypt( $key, $encrypted )
		{
			if( !function_exists( 'mcrypt_decrypt' ) )
				return $encrypted;

			$decrypted = rtrim( mcrypt_decrypt( MCRYPT_RIJNDAEL_256, md5( $key ), base64_decode( $encrypted ), MCRYPT_MODE_CBC, md5( md5( $key ) ) ), "\0" );
			if( $encrypted == $this->encrypt( $key, $decrypted ) )
				return $decrypted;
			else
				return $encrypted;
		}
	}

	$http_digest_auth_plugin = New HTTP_Digest_Auth_plugin;
}

if( is_admin() )
	require_once dirname( __FILE__ ) . '/admin-options.php';
