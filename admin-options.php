<?php
if ( !defined( 'HTTP_DIGEST_AUTH_VERSION' ) )
{
	header( 'HTTP/1.0 403 Forbidden' );
	die;
}

if( !class_exists( 'HTTP_Digest_Auth_plugin_admin' ) )
{
	class HTTP_Digest_Auth_plugin_admin extends HTTP_Digest_Auth_plugin
	{
		function __construct()
		{
			parent::__construct();

			//Add input boxes in the 'Your Profile' section
			add_action( 'show_user_profile', array( $this , 'user_profile' ) );

			//Save the user credentials in the database when the form is submitted
			add_action( 'personal_options_update', array( $this, 'process_user_option_update' ) );
			
			//Remove HTTP credentials from the database if a user is deleted
			add_action( 'delete_user', array( $this, 'remove_user_meta' ) );

			//Display an admin notice when the plugin is activated for the first time
			add_action( 'admin_notices', array( $this, 'admin_notice' ), 9999 );
		}

		//Add additional fields to the 'Your Profile' section
		function user_profile( $user )
		{
			$checked = checked( get_user_meta( $user->ID, $this->slug.'_anyone', TRUE ), '1', FALSE );
			wp_nonce_field( $this->slug . '_user_profile_update', $this->slug . '_nonce' );

			?>
			<h3 id="<?php echo $this->slug; ?>"><?php _e ( 'HTTP Digest Authentication credentials', $this->slug ); ?></h3>
			<p><?php _e( 'Changing the username and/or password will prompt you for the new credentials when you logout.', $this->slug ); ?></p>
			<table class="form-table">
				<tr>
					<th><label for="<?php echo $this->slug; ?>_username"><?php _e( 'Username:', $this->slug ); ?></label></th>
					<td>
						<input id="<?php echo $this->slug; ?>_username" type="text" class="regular-text" name="<?php echo $this->slug; ?>_username" value="<?php echo get_user_meta( $user->ID, $this->slug.'_username', TRUE ); ?>" />
						<span class="description"><?php printf( __( 'Allowed characters %s, everything else will be removed.', $this->slug ), '<code>A-Z a-z 0-9</code> and underscores' ); ?></span>
					</td>
				</tr>
				<tr>
					<th><label for="<?php echo $this->slug; ?>_password"><?php _e( 'Password:', $this->slug ); ?></label></th>
					<td><input id="<?php echo $this->slug; ?>_password" type="password" class="regular-text" name="<?php echo $this->slug; ?>_password" value="" />
					<span class="description"><?php _e( 'If you would like to change the password type a new one else leave it blank.', $this->slug ); ?></span></td>
				</tr>
				<tr>
					<th>&nbsp;</th>
					<td>
						<input <?php echo $checked; ?> type="checkbox" value="<?php echo get_user_meta( $user->ID, $this->slug.'_anyone', TRUE ); ?>" name="<?php echo $this->slug; ?>_anyone" id="<?php echo $this->slug; ?>_anyone" />
						<label for="<?php echo $this->slug; ?>_anyone">
						<?php _e( 'Anyone can use these credentials', $this->slug ); ?>
						</label>
						<span class="description"><br /><?php printf( __( 'By default only the WordPress user %s will be able to login if these credentials are used to view %s. %s
						Checking this option will allow any user to login to WordPress after entering these credentials.', $this->slug ), '<strong>'.$user->user_login.'</strong>','wp-login.php' ,'<br />' ); ?></span>
					</td>
				</tr>
			</table>
<?php	}

		//Validate and save the credentials in the database
		function process_user_option_update( $user_ID )
		{
			$user_details = get_userdata( $user_ID );
			$users = get_users( array ( 'exclude' => array( $user_ID ) ) );

			foreach( $users as $user )
			{
				if( get_user_meta( $user->ID, $this->slug.'_username', TRUE ) == $_POST[$this->slug.'_username'] )
					wp_die( __( 'HTTP Username already exists please choose something else', $this->slug ), '', array( 'back_link' => TRUE ) );
			}

			check_admin_referer( $this->slug . '_user_profile_update', $this->slug . '_nonce' );

			//Remove all special characters from the username
			preg_match_all( '/[0-9a-z_]/i', $_POST[$this->slug.'_username'], $matches );
			$username = implode( $matches[0] );
			update_user_meta( $user_ID, $this->slug.'_username', ( !empty( $username ) ? $username : $user_details->user_login ) );

			//If the password fiel isn't empty encrypt and save it in the database
			if( isset( $_POST[$this->slug.'_password'] ) && !empty( $_POST[$this->slug.'_password'] ) )
				update_user_meta( $user_ID, $this->slug.'_password', $this->encrypt( $user_details->user_login, $_POST[$this->slug.'_password'] ) );

			$anyone = ( isset( $_POST[$this->slug.'_anyone'] ) ? '1' : '0' );
			update_user_meta( $user_ID, $this->slug.'_anyone', $anyone );
		}
		
		//Remove HTTP credentials from the database when a user is deleted
		function remove_user_meta( $user_ID )
		{
			delete_user_meta( $user_ID, $this->slug . '_username' );
			delete_user_meta( $user_ID, $this->slug . '_password' );
			delete_user_meta( $user_ID, $this->slug . '_anyone' );
		}
		
		
		function admin_notice()
		{
			//Display an admin notice when the plugin is activated for the first time
			if( !get_option( $this->slug . '_plugin' ) )
			{
				$list = '<ul>
						<li>Username: &lt;WordPress Username&gt;</li>
						<li>Password: password</li>
						</ul>' ;
				echo '<div class="updated"><h2>';
				_e( 'Read This!', $this->slug );
				echo '</h2><p>';
				printf( __( 'Thanks for using this plugin. A default HTTP username/password has been created for all users as follows %s', $this->slug ), $list );
				_e( 'You will be prompted for these credentials the first time you logout after enabling this plugin.', $this->slug );
				echo '</p><p>';
				if( function_exists( 'get_edit_user_link' ) )
					$profile_link = array( '&gt; <a href="' . get_edit_user_link(). '#' . $this->slug . '">', '</a>' );
				else
					$profile_link = array( '&gt; ', '' );
				printf( __( 'Change your HTTP Username/Password by going to Users %sYour Profile%s', $this->slug ), $profile_link[0], $profile_link[1] );
				echo '</p></div>';
				add_option( $this->slug . '_plugin', '1', '', 'no' );
			}

			//Display the HTTP credentials once when a new user is added.
			if( isset( $_SESSION['newuser'] ) )
			{
				$list = '<ul>
						<li>Username: '. $_SESSION['newuser'] .'</li>
						<li>Password: password</li>
						</ul>' ;
				echo '<div class="updated">' . sprintf( __( 'HTTP credentials of the new user %s',$this->slug ), $list ) . '</div>';
				unset( $_SESSION['newuser'] );
			}
		}
	}

	$http_digest_auth_plugin_admin = new HTTP_Digest_Auth_plugin_admin;
}
