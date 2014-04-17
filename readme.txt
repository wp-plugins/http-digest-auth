=== HTTP Digest Authentication ===
Contributors: jesin
Tags: Auth, authenticate, hacking, http digest, login, password, secure, security, security plugin, two factor auth
Requires at least: 3.1.0
Tested up to: 3.9
Stable tag: 1.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Protect your wp-login.php page with HTTP Digest Authentication without the need of adding web server modules or changing config files.

== Description ==

This plugin adds an additional layer of protection for the **wp-login.php** page using [HTTP Digest Authentication](http://en.wikipedia.org/wiki/Digest_access_authentication) with the PHP [header()](http://php.net/header) function.  
So it doesn't require configuring web server files like *.htaccess* or [*.htdigest*](http://jesin.tk/tools/htdigest-generator-tool/) and works on all web hosting environments.  

**Important:** If you already have a plugin which does HTTP Authentication please deactivate it before activating this plugin. Similarly if you have configured your web server to do HTTP authentication on the wp-login.php file please remove it before using this plugin.

If you are using FastCGI PHP this plugin may keep prompting for the credentials even if you enter the right pair, in this case use the following in your __`.htaccess`__ file

	<IfModule mod_setenvif.c>
	SetEnvIfNoCase ^Authorization$ "(.+)" PHP_AUTH_DIGEST=$1
	</IfModule>

= Advantages of HTTP Digest Authentication =

* Digest Authentication is very much safer than HTTP Basic Authentication whose credentials can be easily decoded with a [base64 decoder](http://www.base64decode.org/).
* From Wikipedia on [HTTP Basic Authentication](http://en.wikipedia.org/wiki/Basic_access_authentication):

>*The BA (Basic Authentication) mechanism provides no confidentiality protection for the transmitted credentials. They are merely encoded with BASE64 in transit, but not encrypted or hashed in any way.*

* Digest Authentication on the other hand uses [MD5](http://jesin.tk/tools/md5-encryption-tool/) on the credentials making it "one way" 
* Uses server and client [nonce](http://en.wikipedia.org/wiki/Cryptographic_nonce)s to prevent replay attacks

= Features of the HTTP Digest Auth plugin =

* Works using PHP header() function and doesn't require modification of service config files (like .htaccess, nginx.conf etc)
* Supports HTTP credentials for each WordPress user
* Clears the HTTP Digest credentials when the user logs out of WordPress (more on this in the FAQ)
* Verifies if both the HTTP and WordPress credentials are of the same user (this is the default behavior and can be changed)
* Works on all major Web Servers (Tested on Apache, Nginx and Lighttpd)

= Plugin Behavior =

* When this plugin is activated for the first time all WordPress users will have the following Digest credentials  
Username: &lt;WordPress username&gt;  
Password: password  
This can be changed from **Users > Your Profile**.
* After activating this plugin for the first time you'll be prompted for HTTP credentials when you logout
* Similarly if you change your HTTP username or password you'll be prompted for this when you logout

The [HTTP Digest Authentication Plugin](http://jesin.tk/wordpress-plugins/http-digest-authentication/) official homepage.

== Installation ==
1. Unzip and upload the `http-digest-auth` folder to the `/wp-content/plugins/` directory.
2. Activate the <strong>HTTP Digest Authentication</strong> plugin through the 'Plugins' menu in WordPress.
3. Configure a HTTP username/password by going to `Users > Your Profile` page.
4. You'll be prompted for these credentials when you logout after activating the plugin for the first time.

== Frequently Asked Questions ==

= How does HTTP logout work? =
When you access the *wp-login.php* page a portion of the realm is generated and stored in a session variable so the realm looks like "HTTP Auth Session MTM4MTc0NzU3OQ=="  
When you logout of WordPress this session variable is deleted and a new realm is generated, hence the browser prompts you for credentials.

= How are the HTTP Digest credentials stored? =
The username is stored in the `wp_usermeta` table in plain-text. The password is stored in a two-way encryption format in the same table. It is encrypted and decrypted with the [mcrypt_encrypt()](http://php.net/mcrypt_encrypt) and [mcrypt_decrypt()](http://php.net/mcrypt_decrypt) functions.

= But I saw the plain-text password in my database =
That means your PHP installation doesn't have the mcrypt extension. To check if this is the case go to your `<?php phpinfo(); ?>` and check if there is a section called mcrypt. If there isn't one in your VPS/Dedicated server install it

on Debian/Ubuntu

`apt-get install php5-mcrypt`

on Centos/Fedora

`yum install php5-mcrypt`

After installation change the password (or enter the same password in Your Profile) to encrypt it.

Shared hosting users needn't worry about this as any decent host should already have this installed.

= Help! I forgot my HTTP Digest credentials =
You can find your username by executing the following MySQL query.
>``SELECT meta_value FROM `wp_usermeta` WHERE meta_key = 'http-digest-auth_username' and user_id = (SELECT ID from wp_users where user_login = 'WordPress_Username');``

Remember to replace `wp_` with your actual database prefix and `WordPress_Username` with your login name.

The password can be reset with the following query
>``UPDATE `wp_usermeta` SET meta_value = 'password' WHERE meta_key = 'http-digest-auth_password' and user_id = (SELECT ID from wp_users where user_login = 'admin');``

This will set the HTTP password to `password`. Login and change it immediately.

= What does the "Anyone can use these credentials" option do? =
By default if you access the **wp-login.php** page using your HTTP credentials, only YOUR WordPress username can login.
This security measure can be disabled by ticking this option.

= Are the HTTP credentials stored in the database even after this plugin is deactivated/deleted? =
Deactivating this plugin doesn't affect the credentials but deleting the plugin erases all HTTP user credentials leaving no trace of it in the database.

== Changelog ==

= 1.1 =
* Reduced repetitive code with inheritance
* `.htaccess` rules for FastCGI PHP

= 1.0 =
* Initial version

== Screenshots ==
1. Logging in using HTTP digest credentials
2. The WordPress login page with the HTTP username
3. Setting a HTTP Digest username and password via Users > Your Profile
4. Logged out of WordPress
5. Trying to login with someone else's WordPress username
