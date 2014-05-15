<?php

	/** Licence...
	 * 
	 * 
	 */
	
	
	/********
	 * Configuration section
	 */
	
	$config = array();
	
	
	// Default values for flags
	
	$config['flags'] = array (
		'remove_scripts'  => false,
		'accept_cookies'  => true,
		'show_referer'    => true,
		'session_cookies' => true
	);
	
	
	// Put here the hosts blacklisted by the server.
	// /!\ Parsed as a regular expression. Don't forget to escape characters.
	$config['hosts_blacklisted'] = array(
		
		// Avoid loading localhost, to avoid a visitor to read the localhost of your own server
		'#^127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost#i',
		
	);
	
	
	// Put here all the translations if you want a localized version
	
	$config['translations'] = array(
		'remove_scripts' => array('Remove client-side scripting (I.E, Javascript)', 'Remove client-side scripting'), 
		'accept_cookies' => array('Allow cookies to be stored', 'Allow cookies to be stored'), 
		'show_referer' => array('Send my referer to the websites', 'Send my referer to the websites'), 
		'base64_encode' => array('Use Base64 encoding of URLs', 'Base64'), 
		'session_cookies' => array('Store cookies for this session only ', 'Store cookies for this session only ') 
	);
	
	
	/*
	 * End of configuration.
	 * Don't change anything below, except if you know what you do!
	 **************************/
	
	
	session_name('prx');
	session_start(); 
	
	require_once('lib/ConfigManager.php');
	require_once('lib/RessourceLoader.php');
	require_once('lib/UIManager.php');
	
	$config['system'] = array(
		'ssl' => extension_loaded('openssl') and version_compare(PHP_VERSION, '4.3.0', '>='),
		'uploads' => ini_get('file_uploads'),
		'gzip' => extension_loaded('zlib') and !ini_get('zlib.output_compression'),
		'stripslashes' => get_magic_quotes_gpc()
	);
	
	// Easy access to the config from everywhere
	ConfigManager::setConfig($config);
	
	
	$ressource = new RessourceLoader();
	$ui = new UIManager();
	
	$ressource->load();
	
	if(!$ressource->exists()) { // Display home screen
		echo $ui->home();
		exit;
	}
	
	if(!$ressource->isProxyfiable()) { // Raw display
		
		$ressource->setHeaders();
		echo $ressource->render();
		
		exit;
	}
	
	$ressource->proxify();
	
	$ressource->setHeaders();
	echo $ui->injectUI($ressource->render());
	
	exit;