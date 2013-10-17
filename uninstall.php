<?php
// if we're not uninstalling..
if( !defined( 'WP_UNINSTALL_PLUGIN' ) )
	exit();

//Delete the credentials of all users
require_once dirname( __FILE__ ) . '/plugin.php';
$users = get_users();
delete_option( $http_digest_auth_plugin->slug. '_plugin' );
foreach( $users as $user )
{
	delete_user_meta( $user->ID, $http_digest_auth_plugin->slug . '_username' );
	delete_user_meta( $user->ID, $http_digest_auth_plugin->slug . '_password' );
	delete_user_meta( $user->ID, $http_digest_auth_plugin->slug . '_anyone' );
}