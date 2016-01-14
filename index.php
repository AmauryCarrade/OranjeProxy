<?php
/*
	+-----------------------+-----------------------------------------------------------------------+
	|  Script               | PHProxy   +   SabzProxy                                               |
	|  Author               | Abdullah Arif                                                         |
	|  Modifier             | Forgetful  (Hamid R) + Timo Van Neerden + Amaury Carrade + Machou     |
	|  Last Modified        | 14 january 2016                                                       |
	+-----------------------+-----------------------------------------------------------------------+
	|  This program is free software; you can redistribute it and/or                                |
	|  modify it under the terms of the GNU General Public License                                  |
	|  as published by the Free Software Foundation; either version 2                               |
	|  of the License, or (at your option) any later version.                                       |
	|                                                                                               |
	|  This program is distributed in the hope that it will be useful,                              |
	|  but WITHOUT ANY WARRANTY; without even the implied warranty of                               |
	|  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                |
	|  GNU General Public License for more details.                                                 |
	|                                                                                               |
	|  You should have received a copy of the GNU General Public License                            |
	|  along with this program; if not, write to the Free Software                                  |
	|  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.                  |
	+-----------------------------------------------------------------------------------------------+
*/

// TRANSLATIONS
//

// Please, if you want translate it, add copy one array with your language key (Russian > "ru", Spain > "es"...)
// Find all identification codes here : http://www.metamodpro.com/browser-language-codes
$translations = array(
	'en' => array(
		'remove_scripts' => array('Remove client-side scripting (I.E, JavaScript)', 'Remove client-side scripting'),
		'accept_cookies' => array('Allow cookies to be stored', 'Allow cookies to be stored'),
		'show_referer' => array('Send my referer to the websites', 'Send my referer to the websites'),
		'base64_encode' => array('Use Base64 encoding of URLs', 'Base64'),
		'session_cookies' => array('Store cookies for this session only ', 'Store cookies for this session only '),
		
		'home' => 'Home',
		'gotothepage' => 'Go to the page',
		'gotothesite' => 'Go to the site',

		'error-url-blacklisted' => 'The URL you\'re attempting to access is blacklisted by this server. Please select another URL.',
		'error-cookie-disabled' => 'Cookies are disabled for this website; they are required.',
		'error-url-malformed' => 'The URL you entered is malformed. Please check whether you entered the correct URL or not.',
		'error-unreachable' => 'It was not possible to reach the server at <strong>%s</strong>.<br />Please check the address does not contain a typo, or the site still exists.<br /><br /><small>Error no. %s: %s.</small>',
		
		'username-password-invite' => 'Enter your username and password for "%s" on %s',
		'username' => 'Username',
		'password' => 'Password',
		'login' => 'Login'
	),
	
	'fr' => array(
		'remove_scripts' => array('Désactiver les différents scripts côté client (I.E, JavaScript)', 'Désactiver les scripts client'),
		'accept_cookies' => array('Autoriser les cookies à être stockés', 'Autoriser les cookies'),
		'show_referer' => array('Envoyer l\'URL référente aux sites internet', 'Envoyer l\'URL référente'),
		'base64_encode' => array('Utiliser l\'encodage Base64 pour les URLs', 'Base64'),
		'session_cookies' => array('Stocker les cookies pour cette session uniquement', 'Stocker les cookies pour cette session uniquement'),
		
		'home' => 'Accueil',
		'gotothepage' => 'Aller à la page',
		'gotothesite' => 'Aller sur le site',

		'error-url-blacklisted' => 'Cette URL est dans la liste noire du proxy. Veuillez entrer une autre URL.',
		'error-cookie-disabled' => 'Les cookies sont désactivés pour ce site ; ils sont nécessaire à son fonctionnement.',
		'error-url-malformed' => ' L\'URL que vous avez entrée est invalide. Vérifiez que vous avez tapé la bonne URL.',
		'error-unreachable' => 'Le serveur à l\'adresse <strong>%s</strong> est injoignable.<br />Vérifiez que vous n\'avez pas fait de faute de frappe, et que le site existe toujours.<br /><br /><small>Erreur n<sup>o</sup> %s : %s.</small>',
		
		'username-password-invite' => 'Entrez votre nom d\'utilisateur et mot de passe pour "%s" sur %s',
		'username' => 'Nom d\'utilisateur',
		'password' => 'Mot de passe',
		'login' => 'Se connecter'
	),
);


// CONFIGURABLE OPTIONS
//

// Default values
$_flags = array (
	'remove_scripts'	=> false,
	'accept_cookies'	=> true,
	'show_referer'		=> true,
	'base64_encode'		=> true,
	'session_cookies'	=> true
);


// Put here the hosts blacklisted by the server.
// /!\ Parsed as a regular expression. Don't forget to escape characters.
$_hosts_blacklisted = array(
	// empêche de lire le localhost (plus pratique pour éviter qu'un visiteur lise de localhost de votre serveur, donc votre serveur)
	'#^127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost#i',
);

//
// END OF CONFIGURABLE OPTIONS.
//



// Loading translations

function get_language($accepted_languages, $sDefault = 'en')
{
	if(!empty($_SERVER['HTTP_ACCEPT_LANGUAGE']))
	{
		$aBrowserLanguages = explode(',', $_SERVER['HTTP_ACCEPT_LANGUAGE']);
		foreach($aBrowserLanguages as $sBrowserLanguage)
		{
			$sLang = strtolower(substr($sBrowserLanguage, 0, 2));

			if(in_array($sLang, $accepted_languages)) {
				return $sLang;
			}
		}
	}

	return $sDefault;
}

$_labels = $translations[get_language(array_keys($translations))];




function vd($var) { var_dump($var); }

session_name('prx');
session_start(); 

// Random key for URL (prevent from blocking)
if(!isset($_SESSION['urlKey']) || empty($_SESSION['urlKey'])) {
	$_SESSION['urlKey'] = substr(urlencode(sha1(uniqid(mt_rand(), true))), 0, 6);
}
$q  = $_SESSION['urlKey'];
$hl = substr(urlencode(sha1($q)), 0, 8);


// Calculate HMAC-SHA1 according to RFC2104
// http://www.ietf.org/rfc/rfc2104.txt
function hmacsha1($key,$data) {
	$blocksize = 64;
	$hashfunc = 'sha1';
	if (strlen($key) > $blocksize) $key = pack('H*', $hashfunc($key));
	$key = str_pad($key, $blocksize, chr(0x00));
	$ipad = str_repeat(chr(0x36), $blocksize);
	$opad = str_repeat(chr(0x5c), $blocksize);
	$hmac = pack('H*', $hashfunc(($key^$opad).pack('H*', $hashfunc(($key^$ipad).$data))));
	return bin2hex($hmac);
}

// Simple XOR encryption taken from:
// http://www.jonasjohn.de/snippets/php/xor-encryption.htm
function XOREncryption($InputString, $KeyPhrase) {
	$KeyPhraseLength = strlen($KeyPhrase);

	// Loop trough input string
	for ($i = 0; $i < strlen($InputString); $i++) {
		$rPos = $i % $KeyPhraseLength; // Get key phrase character position
		$r = ord($InputString[$i]) xor ord($KeyPhrase[$rPos]); // Magic happens here:
		$InputString[$i] = chr($r); // Replace characters
	}

	return $InputString;
}

// Helper functions, using base64 to
// create readable encrypted texts: 
function XOREncrypt64($InputString, $KeyPhrase){
	$InputString = XOREncryption($InputString, $KeyPhrase);
	$InputString = base64_encode($InputString);

	return $InputString;
}

function XORDecrypt64($InputString, $KeyPhrase){
	$InputString = base64_decode($InputString);
	$InputString = XOREncryption($InputString, $KeyPhrase);

	return $InputString;
}


if (!isset($_SESSION['randomkey'])) {
  $_SESSION['randomkey'] = sha1(uniqid('',true) . '_' . mt_rand());
}


$_iflags = '';
$_system = array(
	'ssl' => extension_loaded('openssl') and version_compare(PHP_VERSION, '4.3.0', '>='),
	'uploads' => ini_get('file_uploads'),
	'gzip' => extension_loaded('zlib') and !ini_get('zlib.output_compression'),
	'stripslashes' => get_magic_quotes_gpc()
);

$_proxify = array(
	'text/html' => 1,
	'application/xml+xhtml' => 1,
	'application/xhtml+xml' => 1,
	'text/css' => 1
);

$_http_host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
$_http_s = ( (isset($_ENV['HTTPS']) and $_ENV['HTTPS'] == 'on') or $_SERVER['SERVER_PORT'] == 443) ? 'https' : 'http';
$_http_port = ($_SERVER['SERVER_PORT'] != 80 and $_SERVER['SERVER_PORT'] != 443 ? ':' . $_SERVER['SERVER_PORT'] : '');
$_script_url = $_http_s . '://' . $_http_host.$_http_port.$_SERVER['PHP_SELF'];

$_script_base  = substr($_SERVER['SCRIPT_NAME'], strrpos($_SERVER['SCRIPT_NAME'],"/")+1);

/////////////////


$_socket = null;
$_request_method = $_SERVER['REQUEST_METHOD'];
$_post_body = '';
$_set_cookie = array();

//
// FUNCTION DECLARATIONS
//


function add_cookie($name, $value, $expires = 0) {
	return rawurlencode(rawurlencode($name)) . '=' . rawurlencode(rawurlencode($value)).(empty($expires) ? '' : '; expires=' . gmdate('D, d-M-Y H:i:s \G\M\T', $expires)) . '; path=/; domain=.' . $GLOBALS['_http_host'];
}

function set_post_vars($array, $parent_key = null) {
	$temp = array();
	foreach ($array as $key => $value) {
		$key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
		if (is_array($value)) {
			$temp = array_merge($temp, set_post_vars($value, $key));
		}
		else {
			$temp[$key] = urlencode($value);
		}
	}

	return $temp;
}

function set_post_files($array, $parent_key = null) {
	$temp = array();
	foreach ($array as $key => $value) {
		$key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
		if (is_array($value)) {
			$temp = array_merge_recursive($temp, set_post_files($value, $key));
		}
		elseif (preg_match('#^([^\[\]]+)\[(name|type|tmp_name)\]#', $key, $m)) {
			$temp[str_replace($m[0], $m[1], $key)][$m[2]] = $value;
		}
	}

	return $temp;
}

function url_parse($url, & $container) {
	$temp = @parse_url($url);

	if (!empty($temp)) {
		$temp['port_ext'] = '';
		$temp['base'] = $temp['scheme'] . '://' . $temp['host'];

		// ajoute le port si donné
		if (isset($temp['port'])) {
			$temp['base'] .= $temp['port_ext'] = ':' . $temp['port'];
		}
		// port SSL (443) si https, 80 sinon.
		else {
			$temp['port'] = $temp['scheme'] === 'https' ? 443 : 80;
		}
		// si le path existe, on le garde, sinon c'est un chemin relatif
		$temp['path'] = isset($temp['path']) ? $temp['path'] : '/';
		$path = array();
		$temp['path'] = explode('/', $temp['path']);

		foreach ($temp['path'] as $dir) {
			if ($dir === '..') {
				array_pop($path); // permet de réduire le nombre de dossiers si on a un retour en haut=> /foo/../bar =>> /bar
			}
			elseif ($dir !== '.') {
/*				$dir = rawurldecode($dir);
				$count_i = strlen($dir);
				// reconstruit le nom du dossier char par char (évite le genre de truc comme %20 dans les dossiers dâÃªtres parsÃ©s comme des sÃ©parateursâŠ)
					// je pense qu'il y a beaucoup plus simple, mais bon.
				for ($new_dir = '', $i = 0 ; $i < $count_i; $i++) {
					$new_dir .= strspn($dir[$i], 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-_.+!*\'(),?:@&;=') ? $dir[$i] : rawurlencode($dir[$i]);
				}
				$path[] = $new_dir;
*/

				$path[] = rawurlencode($dir);
			}
		}

		$temp['path'] = '/' . ltrim(implode('/', $path), '/'); // supprime tous les '/' à gauche et en ajoute un seul : ///fol/file => /fol/file
		$temp['file'] = substr($temp['path'], strrpos($temp['path'], '/') + 1);
		$temp['dir'] = substr($temp['path'], 0, strrpos($temp['path'], '/'));
		$temp['base'] .= $temp['dir'];
		$temp['prev_dir'] = substr_count($temp['path'], '/') > 1 ? substr($temp['base'], 0, strrpos($temp['base'], '/') + 1) : $temp['base'] . '/';
		$container = $temp;

		return true;
	}

	return false;
}

function complete_url($url, $proxify = true) {
	$url = trim($url);
	if ($url === '') {
		return '';
	}

	$hash_pos = strrpos($url, '#');
	$fragment = $hash_pos !== false ? '#' . substr($url, $hash_pos) : '';
	$sep_pos  = strpos($url, '://');

	if ($sep_pos === false || $sep_pos > 5) {
		switch ($url{0}) {
			case '/':
				$url = substr($url, 0, 2) === '//' ? $GLOBALS['_base']['scheme'] . ':' . $url : $GLOBALS['_base']['scheme'] . '://' . $GLOBALS['_base']['host'] . $GLOBALS['_base']['port_ext'] . $url;
				break;
			case '?':
				$url = $GLOBALS['_base']['base'] . '/' . $GLOBALS['_base']['file'] . $url;
				break;
			case '#':
				$proxify = false;
				break;
			case 'm':
				if (substr($url, 0, 7) == 'mailto:') {
					$proxify = false;
					break;
				}
			case 'j':
				if (substr($url, 0, 11) == 'javascript:') {
					$proxify = false;
					break;
				}
			default:
				$url = $GLOBALS['_base']['base'] . '/' . $url;
				break;
		}
	}

	//$url = str_replace('&amp;', '&', $url);
	return $proxify ? "{$GLOBALS['_script_url']}?" . $GLOBALS['q'] . "=" . encode_url($url) . $fragment : $url;
}

function proxify_inline_css($css) {
	preg_match_all('#url\s{0,}\(("|\')?([^\'")]{1,})(\'|")?\)#i', $css, $matches, PREG_SET_ORDER);
	for ($i = 0, $count = count($matches); $i < $count; ++$i) {
	if (!preg_match('#^data:#', $matches[$i][2])) {
			$css = str_replace($matches[$i][0], 'url("' . proxify_css_url($matches[$i][2]) . '")', $css);
		}
	}

	return $css;
}

function proxify_css($css) {
	$css = proxify_inline_css($css);

	preg_match_all("#@import\s*(?:\"([^\">]*)\"?|'([^'>]*)'?)([^;]*)(;|$)#i", $css, $matches, PREG_SET_ORDER);

	for ($i = 0, $count = count($matches); $i < $count; ++$i) {
		$delim = '"';
		$url = $matches[$i][2];

		if (!empty($matches[$i][3])) {
			$delim = "'";
			$url = $matches[$i][3];
		}

		$css = str_replace($matches[$i][0], '@import ' . $delim . proxify_css_url($url) . $delim . (!empty($matches[$i][4]) ? $matches[$i][4] : ''), $css);
	}

	return $css;
}

function proxify_css_url($url) {
	$url = trim($url);
	$delim = strpos($url, '"') === 0 ? '"' : (strpos($url, "'") === 0 ? "'" : '');

	return $delim . preg_replace('#([\(\),\s\'"\\\])#', '\\$1', complete_url(trim(preg_replace('#\\\(.)#', '$1', trim($url, $delim))))) . $delim;
}

//
// SET FLAGS
//

if (isset($_POST[$q]) and !isset($_GET[$q]) and isset($_POST[$hl])) {
	foreach ($_flags as $flag_name => $flag_value) {
		$_iflags .= isset($_POST[$hl][$flag_name]) ? (string)(int)(bool)$_POST[$hl][$flag_name] : 0;
	}

	$_iflags = base_convert(($_iflags != '' ? $_iflags : '0'), 2, 16);
}

elseif (isset($_GET[$hl]) and !isset($_GET['____pgfa']) and ctype_alnum($_GET[$hl])) {
	$_iflags = $_GET[$hl];
}

elseif (isset($_COOKIE['flags']) and ctype_alnum($_COOKIE['flags'])) {
	$_iflags = $_COOKIE['flags'];
}

if ($_iflags !== '') {
	$_set_cookie[] = add_cookie('flags', $_iflags, time()+2419200);
	$_iflags = str_pad(base_convert($_iflags, 16, 2), count($_flags), '0', STR_PAD_LEFT);
	$i = 0;

	foreach ($_flags as $flag_name => $flag_value) {
		$_flags[$flag_name] = (int)(bool)$_iflags{$i};
		$i++;
	}
}


function encode_url($url) {
	$encrypted_url = XOREncrypt64($url,$_SESSION['randomkey']);
	$hmac = hmacsha1( $_SESSION['randomkey'], $encrypted_url);

	return rawurlencode($hmac.$encrypted_url);
}

function decode_url($url) {
	$s = rawurldecode($url);
	$hmac = substr($s,0,40);
	$encrypted_url = substr($s,40,strlen($s)-40);

	// Make sure hmac is correct
	if ($hmac != hmacsha1($_SESSION['randomkey'], $encrypted_url)) { 
		echo "Wrong hmac.";
		exit; // Violent, but effective.
	}

	// Decrypt the URL
	$cleartext_url = XORDecrypt64($encrypted_url, $_SESSION['randomkey']);

	return str_replace(array('&amp;', '&#38;'), '&', $cleartext_url);
}


//
// STRIP SLASHES FROM GPC IF NECESSARY
//

function clean_txt($text) {
	return !get_magic_quotes_gpc() ? trim(addslashes($text)) : trim($text);;
}


function clean_txt_array($array) {
	foreach ($array as $i => $key) {
		if (is_array($array[$i])) {
			clean_txt_array($key);
		}
		else {
			$array[$i] = clean_txt($key);
		}
	}

	return $array;
}

$_GET = clean_txt_array($_GET);
$_POST = clean_txt_array($_POST);
$_COOKIE = clean_txt_array($_COOKIE);


//
// FIGURE OUT WHAT TO DO (POST URL-form submit, GET form request, regular request, basic auth, cookie manager, show URL-form)
//

if (isset($_POST[$q]) && !isset($_GET[$q]) && !isset($_POST['____pgfa'])) {
	header('Location: ' . $_script_url . '?' . $q . '=' . encode_url($_POST[$q]) . '&' . $hl . '=' . base_convert($_iflags, 2, 16));
	exit(0);
}

if (isset($_POST['____pgfa'])) {
	$_url = ($_POST['____pgfa']);
	$qstr = strpos($_url, '?') !== false ? (strpos($_url, '?') === strlen($_url) - 1 ? '' : '&') : '?';
	$arr = explode('&', $_SERVER['QUERY_STRING']);

	$getquery = "";
	foreach($_POST as $key => $val){
		if ($key != '____pgfa') {
			$getquery .= "&".$key."=".$val;
		}
	}

	$getquerylen = strlen($getquery);
	$getquery = substr($getquery, 1, $getquerylen-1);

	if (preg_match('#^\Q' . '____pgfa' . '\E#', $arr[0])) {
		array_shift($arr);
	}

	$_url .= $qstr.$getquery;
	$_gotourl = complete_url($_url);
	$_request_method = 'GET';
}

elseif (isset($_GET[$q])) {
	$_url  = decode_url($_GET[$q]);

	// If the request have already some arguments, a & must be used to add new ones. Else, we need a ?.
	// The sign to use is stored here.
	$qstr = strpos($_url, '?') !== false ? (strpos($_url, '?') === strlen($_url)-1 ? '' : '&') : '?';

	$arrs = explode('&', $_SERVER['QUERY_STRING']);

	// Length of the names of the arguments to remove ($q & $hl), plus one to take the "=" sign into account.
	// Used a few lines later to extract these.
	$lenQ = strlen($q) + 1;
	$lenHL = strlen($hl) + 1;

	foreach($arrs AS $key => $arr) {
		// $q
		if(substr($arr, 0, $lenQ) == $q + '=') {
			unset($arrs[$key]);
		}
		// $hl
		if(substr($arr, 0, $lenHL) == $hl + '=') {
			unset($arrs[$key]);
		}
	}
	
	// Is a "?" needed?
	if(strpos($_url, '?') === false && count($arrs) === 0) {
		$qstr = '';
	}

	$_url .= $qstr . implode('&', $arrs);
}

else {
	afficher_page_form(array('type' => 'empty-form', 'flag' => ''));
}


function afficher_page_form($page) {
	$url = isset($GLOBALS['_url']) ? htmlspecialchars($GLOBALS['_url']) : '';

	echo '<!DOCTYPE html>' . "\n";
	echo '<html>' . "\n";
	echo '<head>' . "\n";
	echo '	<meta charset="utf-8" />' . "\n";
	echo '	<link rel="shortcut icon" href="data:image/png;base64,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" />' . "\n";
	echo '	<title>OranjeProxy</title>' . "\n";
	echo '	<meta name="robots" content="noindex, nofollow" />' . "\n";
	echo '	<style type="text/css">' . "\n";

	echo 'body { background: #ff5508; width: 100%; margin: 0; padding: 0; }
#orpx_nav-bar { height: 72px; padding: 4px 0; margin: 0; text-align: center; border-bottom: 1px solid #755; color: #000; background-color: #ff9864; font-size: 12px; font-family: Arial; }
#orpx_nav-bar a { color: #000; }
#orpx_nav-bar a:hover { color: #007744; }
.windows-popup { background-color: #bf6464; border-top: 1px solid #44352c; border-bottom: 1px solid #44352c; clear: both; padding: 30px 0; text-align: center; margin-top: 152px; }
.windows-popup { background-color: #c27d61; }
.windows-popup p, .windows-popup form { margin: 5px; }' . "\n";
	echo '</style>' . "\n";
	if( file_exists(__DIR__ . '/user.css') ) {
		echo '<link rel="stylesheet" href="./user.css" media="screen" />';
	}
	echo '</head>' . "\n";
	echo '<body>' . "\n";

	echo '<div id="orpx_nav-bar" style="margin:0;">' . "\n";
	echo '	<form method="post" action="' . $_SERVER['PHP_SELF'] . '" style="text-align:center">' . "\n";
	echo '		<a href="' . $_SERVER['PHP_SELF'] . '">' . $GLOBALS['_labels']['home'] . '</a> — <a href="' . $url . '">' . $GLOBALS['_labels']['gotothepage'] . '</a><br />' . "\n";
	echo '		<input id="____q" type="text" size="80" name="' . $GLOBALS['q'] . '" value="' . $url . '" />' . "\n";
	echo '		<input type="submit" name="go" style="font-size: 12px;" value="' . $GLOBALS['_labels']['gotothesite'] . '"/>' . "\n";
	echo '		<br /><hr />' . "\n";
	
	foreach ($GLOBALS['_flags'] as $flag_name => $flag_value) {
		echo '		<label><input type="checkbox" name="' . $GLOBALS['hl'] . '[' . $flag_name . ']"' . ($flag_value == true ? ' checked="checked"' : '') . ' /> ' . $GLOBALS['_labels'][$flag_name][0] . '</label>' . "\n";
	}

	echo '	</form>' . "\n";
	echo '</div>' . "\n";
		
	echo '<div class="windows-popup" id="noCookies" style="display: none;">' . "\n";
		echo $GLOBALS['_labels']['error-cookie-disabled'];
	echo '</div>' . "\n";

	if ($page['type'] == 'auth') {
		echo '<div class="windows-popup" id="auth"><p><b>' . sprintf($GLOBALS['_labels']['username-password-invite'], htmlspecialchars($page['flag']), $GLOBALS['_url_parts']['host']) . '</b>' . "\n";
		echo '	<form method="post" action="#">' . "\n";
		echo '		<input type="hidden" name="____pbavn" value="' . base64_encode($page['flag']) . '" />' . "\n";
		echo '			<label>' . $GLOBALS['_labels']['username'] . ' <input type="text" name="username" value="" /></label>' . "\n";
		echo '			<label>' . $GLOBALS['_labels']['password'] . ' <input type="password" name="password" value="" /></label>' . "\n";
		echo '			<input type="submit" value="' . $GLOBALS['_labels']['login'] . '" />' . "\n";
		echo '	</form>' . "\n";
		echo '</div>' . "\n";
	}

	if ($page['type'] == 'error') {
		echo '<div class="windows-popup" id="error">' . "\n";
			echo $page['flag'];
		echo '</div>' . "\n";
	}

	echo '<script type="text/javascript">' . "\n";
	echo '	window.onload = function(e) { 
		if(navigator.cookieEnabled == false) {
			document.getElementById("noCookies").style.display = "block";
		}
	}' . "\n";
	echo '</script>' . "\n";
	echo '</body>' . "\n";
	echo '</html>' . "\n";

	exit;
}


$_basic_auth_realm = '';
$_basic_auth_header = '';
if (isset($_GET[$q], $_POST['____pbavn'], $_POST['username'], $_POST['password'])) {
	$_request_method = 'GET';
	$_basic_auth_realm = base64_decode($_POST['____pbavn']);
	$_basic_auth_header = base64_encode($_POST['username'] . ':' . $_POST['password']);
}

//
// SET URL
//

if (strpos($_url, '://') === false) {
	$_url = 'http://' . $_url;
}


$_url_parts = array();
if (url_parse($_url, $_url_parts)) {
	$_base = $_url_parts;
	if (!empty($_hosts_blacklisted)) {
		foreach ($_hosts_blacklisted as $host) {
			if (preg_match($host, $_url_parts['host'])) {
				afficher_page_form(array('type' => 'error', 'flag' => $GLOBALS['_labels']['error-url-blacklisted']));
			}
		}
	}
}

else {
	afficher_page_form(array('type' => 'error', 'flag' => $GLOBALS['_labels']['error-url-malformed']));
}


//
// OPEN SOCKET TO SERVER
//


do {
	$_retry = false;

	$_socket = @fsockopen((($_url_parts['scheme'] === 'https' and $_system['ssl']) ? 'ssl://' : 'tcp://').$_url_parts['host'], $_url_parts['port'], $err_no, $err_str, 10);

	if ($_socket === FALSE) {
		afficher_page_form(array('type' => 'error', 'flag' => sprintf($GLOBALS['_labels']['error-unreachable'], htmlspecialchars($_url), htmlspecialchars($err_no), htmlspecialchars($err_str))));
	}

	//
	// SET REQUEST HEADERS
	//
	$_request_headers = '';
	$_request_headers = $_request_method . ' ' .  urldecode( $_url_parts['path'] );

	if (isset($_url_parts['query'])) {
		$_request_headers .= '?';
		$query = preg_split('#([&;])#', $_url_parts['query'], -1, PREG_SPLIT_DELIM_CAPTURE);
		for ($i = 0, $count = count($query);
		$i < $count;
		$_request_headers .= implode('=', array_map('urlencode', array_map('urldecode', explode('=', $query[$i])))) . (isset($query[++$i]) ? $query[$i] : ''), $i++);
	}

	$_request_headers .= " HTTP/1.0\r\n";
	$_request_headers .= 'Host: ' . $_url_parts['host'] . $_url_parts['port_ext'] . "\r\n";

	if (isset($_SERVER['HTTP_USER_AGENT'])) {
		$_request_headers .= 'User-Agent: ' . $_SERVER['HTTP_USER_AGENT']."\r\n";
	}

	if (isset($_SERVER['HTTP_ACCEPT'])) {
		$_request_headers .= 'Accept: ' . $_SERVER['HTTP_ACCEPT']."\r\n";
	}
	else {
		$_request_headers .= "Accept: */*;q=0.1\r\n";
	}

	if ($_flags['show_referer'] and isset($_SERVER['HTTP_REFERER']) and preg_match('#^\Q' . $_script_url . '?' . $q . '=\E([^&]+)#', $_SERVER['HTTP_REFERER'], $matches)) {
		$_request_headers .= 'Referer: ' . decode_url($matches[1]) . "\r\n";
	}

	$_auth_creds = array();
	if (!empty($_COOKIE)) {
		$_cookie = '';
		$_auth_creds = array();
		foreach ($_COOKIE as $cookie_id => $cookie_content) {
			$cookie_id = explode(';', rawurldecode($cookie_id));
			$cookie_content = explode(';', rawurldecode($cookie_content));

			if ($cookie_id[0] === 'COOKIE') {
				$cookie_id[3] = str_replace('_', '.', $cookie_id[3]); //stupid PHP can't have dots in var names

				if (count($cookie_id) < 4 || ($cookie_content[1] == 'secure' && $_url_parts['scheme'] != 'https')) {
					continue;
				}

				if ((preg_match('#\Q' . $cookie_id[3] . '\E$#i', $_url_parts['host']) || strtolower($cookie_id[3]) == strtolower('.' . $_url_parts['host'])) && preg_match('#^\Q' . $cookie_id[2] . '\E#', $_url_parts['path'])) {
					$_cookie .= ($_cookie != '' ? '; ' : '') . (empty($cookie_id[1]) ? '' : $cookie_id[1] . '=') . $cookie_content[0];
				}
			}
			elseif ($cookie_id[0] === 'AUTH' && count($cookie_id) === 3) {
				$cookie_id[2] = str_replace('_', '.', $cookie_id[2]);

				if ($_url_parts['host'] . ':' . $_url_parts['port'] === $cookie_id[2]) {
					$_auth_creds[$cookie_id[1]] = $cookie_content[0];
				}
			}
		}

		if ($_cookie != '') {
			$_request_headers .= "Cookie: $_cookie\r\n";
		}
	}

	if (isset($_url_parts['user'], $_url_parts['pass'])) {
		$_basic_auth_header = base64_encode($_url_parts['user'] . ':' . $_url_parts['pass']);
	}

	if (!empty($_basic_auth_header)) {
		$_set_cookie[] = add_cookie("AUTH;{$_basic_auth_realm};{$_url_parts['host']}:{$_url_parts['port']}", $_basic_auth_header);
		$_request_headers .= "Authorization: Basic {$_basic_auth_header}\r\n";
	}
	elseif (!empty($_basic_auth_realm) and isset($_auth_creds[$_basic_auth_realm])) {
		$_request_headers  .= "Authorization: Basic {$_auth_creds[$_basic_auth_realm]}\r\n";
	}
	elseif (list($_basic_auth_realm, $_basic_auth_header) = each($_auth_creds)) {
		$_request_headers .= "Authorization: Basic {$_basic_auth_header}\r\n";
	}

	if ($_request_method == 'POST') {
		if (!empty($_FILES) and $_system['uploads']) {
			$_data_boundary = '----' . md5(uniqid(rand(), true));
			$array = set_post_vars($_POST);

				foreach ($array as $key => $value) {
					$_post_body .= "--{$_data_boundary}\r\n";
					$_post_body .= "Content-Disposition: form-data; name=\"$key\"\r\n\r\n";
					$_post_body .= urldecode($value) . "\r\n";
				}
				$array = set_post_files($_FILES);

				foreach ($array as $key => $file_info) {
					$_post_body .= "--{$_data_boundary}\r\n";
					$_post_body .= "Content-Disposition: form-data; name=\"$key\"; filename=\"{$file_info['name']}\"\r\n";
					$_post_body .= 'Content-Type: ' . (empty($file_info['type']) ? 'application/octet-stream' : $file_info['type']) . "\r\n\r\n";

					if (is_readable($file_info['tmp_name'])) {
						$len2read = filesize($file_info['tmp_name']);
						$handle = fopen($file_info['tmp_name'], 'rb');
						$_post_body .= fread($handle, $len2read);
						fclose($handle);
					}

					$_post_body .= "\r\n";
				}
				
				$_post_body .= "--{$_data_boundary}--\r\n";
				$_request_headers .= "Content-Type: multipart/form-data; boundary={$_data_boundary}\r\n";
				$_request_headers .= "Content-Length: " . strlen($_post_body) . "\r\n\r\n";
				$_request_headers .= $_post_body;
		}
		else {
			$array = set_post_vars($_POST);

			foreach ($array as $key => $value) {
				$_post_body .= !empty($_post_body) ? '&' : '';
				$_post_body .= $key . '=' . $value;
			}

			$_request_headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
			$_request_headers .= "Content-Length: " . strlen($_post_body) . "\r\n\r\n";
			$_request_headers .= $_post_body;
			$_request_headers .= "\r\n";
		}

		$_post_body = '';
	}

	else {
		$_request_headers .= "\r\n";
	}

	fwrite($_socket, $_request_headers);

	//
	// PROCESS RESPONSE HEADERS
	//

	$_response_headers = array();
	$_response_keys = array();

	$line = fgets($_socket, 8192);

	while (strspn($line, "\r\n") !== strlen($line)) {
		@list($name, $value) = explode(':', $line, 2);
		$name = trim($name);
		$_response_headers[strtolower($name)][] = trim($value);
		$_response_keys[strtolower($name)] = $name;
		$line = fgets($_socket, 8192);
	}

	$_http_version = '';
	$_response_code = 0;
	sscanf(current($_response_keys), '%s %s', $_http_version, $_response_code);

	$_content_type = 'text/html';
	if (isset($_response_headers['content-type'])) {
		list($_content_type, ) = explode(';', str_replace(' ', '', strtolower($_response_headers['content-type'][0])), 2);
	}

	$_content_length = false;
	if (isset($_response_headers['content-length'])) {
		$_content_length = $_response_headers['content-length'][0];
		unset($_response_headers['content-length'], $_response_keys['content-length']);
	}

	$_content_disp = '';
	if (isset($_response_headers['content-disposition'])) {
		$_content_disp = $_response_headers['content-disposition'][0];
		unset($_response_headers['content-disposition'], $_response_keys['content-disposition']);
	}

	if (isset($_response_headers['set-cookie']) and $_flags['accept_cookies']) {
		foreach ($_response_headers['set-cookie'] as $cookie) {
			$name = $value = $expires = $path = $domain = $secure = $expires_time = '';

			preg_match('#^\s*([^=;,\s]*)\s*=?\s*([^;]*)#',	$cookie, $match) and list(, $name, $value)	= $match;
			preg_match('#;\s*expires\s*=\s*([^;]*)#i',	$cookie, $match) and list(, $expires)		= $match;
			preg_match('#;\s*path\s*=\s*([^;,\s]*)#i',	$cookie, $match) and list(, $path)		= $match;
			preg_match('#;\s*domain\s*=\s*([^;,\s]*)#i',	$cookie, $match) and list(, $domain)		= $match;
			preg_match('#;\s*(secure\b)#i',			$cookie, $match) and list(, $secure)		= $match;

			$expires_time = empty($expires) ? 0 : intval(@strtotime($expires));
			$expires = ($_flags['session_cookies'] and !empty($expires) and time()-$expires_time < 0) ? '' : $expires;
			$path = empty($path) ? '/' : $path;

			if (empty($domain)) {
				$domain = $_url_parts['host'];
			}

			else {
				$domain = '.' . strtolower(str_replace('..', '.', trim($domain, '.')));
				if ((!preg_match('#\Q' . $domain . '\E$#i', $_url_parts['host']) and $domain != '.' . $_url_parts['host']) || (substr_count($domain, '.') < 2 and $domain{0} == '.')) {
					continue;
				}
			}

			if (count($_COOKIE) >= 15 and time()-$expires_time <= 0) {
				$_set_cookie[] = add_cookie(current($_COOKIE), '', 1);
			}

			$_set_cookie[] = add_cookie("COOKIE;$name;$path;$domain", "$value;$secure", $expires_time);
		}
	}

	if (isset($_response_headers['set-cookie'])) {
		unset($_response_headers['set-cookie'], $_response_keys['set-cookie']);
	}

	if (!empty($_set_cookie)) {
		$_response_keys['set-cookie'] = 'Set-Cookie';
		$_response_headers['set-cookie'] = $_set_cookie;
	}

	if (isset($_response_headers['p3p']) and preg_match('#policyref\s*=\s*[\'"]?([^\'"\s]*)[\'"]?#i', $_response_headers['p3p'][0], $matches)) {
		$_response_headers['p3p'][0] = str_replace($matches[0], 'policyref="' . complete_url($matches[1]) . '"', $_response_headers['p3p'][0]);
	}

	if (isset($_response_headers['refresh']) and preg_match('#([0-9\s]*;\s*URL\s*=)\s*(\S*)#i', $_response_headers['refresh'][0], $matches)) {
		$_response_headers['refresh'][0] = $matches[1] . complete_url($matches[2]);
	}

	if (isset($_response_headers['location'])) {
		$_response_headers['location'][0] = complete_url($_response_headers['location'][0]);
	}

	if (isset($_response_headers['uri'])) {
		$_response_headers['uri'][0] = complete_url($_response_headers['uri'][0]);
	}

	if (isset($_response_headers['content-location'])) {
		$_response_headers['content-location'][0] = complete_url($_response_headers['content-location'][0]);
	}

	if (isset($_response_headers['connection'])) {
		unset($_response_headers['connection'], $_response_keys['connection']);
	}

	if (isset($_response_headers['keep-alive'])) {
		unset($_response_headers['keep-alive'], $_response_keys['keep-alive']);
	}

	if ($_response_code == 401 and isset($_response_headers['www-authenticate']) and preg_match('#basic\s+(?:realm="(.*?)")?#i', $_response_headers['www-authenticate'][0], $matches)) {
		afficher_page_form(array('type'=> 'auth', 'flag' => $matches[1]));
	}
}

while ($_retry == TRUE);

//
// OUTPUT RESPONSE IF NO PROXIFICATION IS NEEDED
//

if (!isset($_proxify[$_content_type])) {
	@set_time_limit(0);

	$_response_keys['content-disposition'] = 'Content-Disposition';
	$_response_headers['content-disposition'][0] = empty($_content_disp) ? ($_content_type == 'application/octet_stream' ? 'attachment' : 'inline') . '; filename="' . $_url_parts['file'] . '"' : $_content_disp;

	if ($_content_length !== false) {
		$_response_keys['content-length'] = 'Content-Length';
		$_response_headers['content-length'][0] = $_content_length;
	}

	$_response_headers = array_filter($_response_headers);
	$_response_keys = array_filter($_response_keys);

	header(array_shift($_response_keys));
	array_shift($_response_headers);

	foreach ($_response_headers as $name => $array) {
		foreach ($array as $value) {
			header($_response_keys[$name] . ': ' . $value, false);
		}
	}

	do {
		$data = fread($_socket, 8192);
		echo $data;
	}

	while (isset($data{0}));

	fclose($_socket);
	exit;
}

$_response_body = '';
do {
	$data = @fread($_socket, 8192); // silenced to avoid the "normal" warning by a faulty SSL connection
	$_response_body .= $data;
}	
while (isset($data{0}));

unset($data);
fclose($_socket);


//
// MODIFY AND DUMP RESOURCE
//

if ($_content_type == 'text/css') {
	$_response_body = proxify_css($_response_body);
}

else {
	if ($_flags['remove_scripts']) {
		$_response_body = preg_replace('#<\s*script[^>]*?>.*?<\s*/\s*script\s*>#si', '', $_response_body);
		$_response_body = preg_replace("#(<\s*[\w]* )([^>]*) (on[a-z]*=\"[^\"]*\")([^>]*>)#i", '$1$2 $4', $_response_body);// "onclick", etc.
		$_response_body = preg_replace("#(href=(['\"]))(javascript:(?:(?!\g{2}).|(?:(?<=\\\)\g{2}))+)*(\g{2})#i", '$1$4', $_response_body);//href javascript
		$_response_body = preg_replace('#<noscript>(.*?)</noscript>#si', "$1", $_response_body);
	}

	//
	// PROXIFY HTML RESOURCE
	//

	$tags = array(
			'a'             => array('href'),
			'applet'        => array('codebase', 'code', 'object', 'archive'),
			'area'          => array('href'),
			'audio'         => array('src'),
			'base'          => array('href'),
			'bgsound'       => array('src'),
			'blockquote'    => array('cite'),
			'body'          => array('background'),
			'del'           => array('cite'),
			'embed'         => array('src'),
			'fig'           => array('src', 'imagemap'),
			'frame'         => array('src', 'longdesc'),
			'head'          => array('profile'),
			'html'          => array('itemtype', 'manifest'),
			'iframe'        => array('src', 'longdesc'),
			'img'           => array('src'),
			'input'         => array('src', 'usemap'),
			'ins'           => array('cite'),
			'link'          => array('href'),
			'layer'         => array('src'),
			'meta'          => array('name', 'content'),
			'form'          => array('action'),
			'object'        => array('usermap', 'codebase', 'classid', 'archive', 'data'),
			'param'         => array('value'),
			'q'             => array('cite'),
			'script'        => array('src'),
			'table'         => array('background'),
			'td'            => array('background'),
			'th'            => array('background'),
			'tr'            => array('background'),
			'video'         => array('src'),
		);

	preg_match_all('#(<\s*style[^>]*>)(.*?)(<\s*/\s*style[^>]*>)#is', $_response_body, $matches, PREG_SET_ORDER);

	$count_i = count($matches);
	for ($i = 0 ; $i < $count_i ; ++$i) {
		$_response_body = str_replace($matches[$i][0], $matches[$i][1]. proxify_css($matches[$i][2]) .$matches[$i][3], $_response_body);
	}

	preg_match_all("#<\s*/?([a-zA-Z-]+) ([^>]+)>#S", $_response_body, $matches);

	$count_i = count($matches[0]);
	for ($i = 0 ; $i < $count_i ; ++$i) {
		if (!preg_match_all("#([a-zA-Z\-\/]+)\s*(?:=\s*(?:\"([^\">]*)\"?|'([^'>]*)'?|([^'\"\s]*)))?#S", $matches[2][$i], $m, PREG_SET_ORDER)) {
			continue;
		}

		$rebuild = false;
		$extra_html = $temp = '';
		$attrs = array();

		$count_j = count($m);
		for ($j = 0 ; $j < $count_j; ++$j) {
			if (isset($m[$j][4])) 
				$attrs[strtolower($m[$j][1])] = $m[$j][4];
			elseif (isset($m[$j][3]))
				$attrs[strtolower($m[$j][1])] = $m[$j][3];
			elseif (isset($m[$j][2]))
				$attrs[strtolower($m[$j][1])] = $m[$j][2];
			elseif (isset($m[$j][5]))
				$attrs[strtolower($m[$j][1])] = $m[$j][5];
			elseif (isset($m[$j][6]))
				$attrs[strtolower($m[$j][1])] = $m[$j][6];
			else
				$attrs[strtolower($m[$j][1])] = false;
		}

		if (isset($attrs['style'])) {
			$rebuild = true;
			$attrs['style'] = proxify_inline_css(urldecode($attrs['style']));
		}

		$tag = strtolower($matches[1][$i]);

		if (isset($tags[$tag])) {
			switch ($tag) {
				case 'form':
					$rebuild = true;

					if (!isset($attrs['action']) || trim($attrs['action']) == NULL) {
						$attrs['action'] = $_url_parts['path'];
					}

					if (!isset($attrs['method']) || strtolower(trim($attrs['method'])) === 'get') {
						$extra_html = '<input type="hidden" name="' . '____pgfa' . '" value="' .complete_url($attrs['action'], false). '" />';
						$attrs['action'] = '#';
						$attrs['method'] = 'post';
						break;
					}

					$attrs['action'] = complete_url($attrs['action']);
					break;

				case 'base':
					if (isset($attrs['href'])) {
						$rebuild = true;  
						url_parse($attrs['href'], $_base);
						$attrs['href'] = complete_url($attrs['href']);
					}
					break;

				case 'head':
					if (isset($attrs['profile'])) {
						$rebuild = true;
						$attrs['profile'] = implode(' ', array_map('complete_url', explode(' ', $attrs['profile'])));
					}
					break;

				case 'applet':
					if (isset($attrs['codebase'])) {
						$rebuild = true;
						$temp = $_base;
						url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
						unset($attrs['codebase']);
					}
					if (isset($attrs['code']) && strpos($attrs['code'], '/') !== false) {
						$rebuild = true;
						$attrs['code'] = complete_url($attrs['code']);
					}
					if (isset($attrs['object'])) {
						$rebuild = true;
						$attrs['object'] = complete_url($attrs['object']);
					}
					if (isset($attrs['archive'])) {
						$rebuild = true;
						$attrs['archive'] = implode(',', array_map('complete_url', preg_split('#\s*,\s*#', $attrs['archive'])));
					}
					if (!empty($temp)) {
						$_base = $temp;
					}
				break;

				case 'object':
					if (isset($attrs['usemap'])) {
						$rebuild = true;
						$attrs['usemap'] = complete_url($attrs['usemap']);
					}
					if (isset($attrs['codebase'])) {
						$rebuild = true;
						$temp = $_base;
						url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
						unset($attrs['codebase']);
					}
					if (isset($attrs['data'])) {
						$rebuild = true;
						$attrs['data'] = complete_url($attrs['data']);
					}
					if (isset($attrs['classid']) && !preg_match('#^clsid:#i', $attrs['classid'])) {
						$rebuild = true;
						$attrs['classid'] = complete_url($attrs['classid']);
					}
					if (isset($attrs['archive'])) {
						$rebuild = true;
						$attrs['archive'] = implode(' ', array_map('complete_url', explode(' ', $attrs['archive'])));
					}
					if (!empty($temp)) {
						$_base = $temp;
					}
				break;

				case 'param':
					if (isset($attrs['valuetype'], $attrs['value']) && strtolower($attrs['valuetype']) == 'ref' && preg_match('#^[\w.+-]+://#', $attrs['value'])) {
						$rebuild = true;
						$attrs['value'] = complete_url($attrs['value']);
					}
					break;
				case 'meta':
					if (isset($attrs['content']) and isset($attr['name']) and $attr['name'] == 'viewport' ) {
						$rebuild = false;
					}
					break;
				case 'html':
					if (isset($attrs['manifest']) ) {
						$rebuild = true;
						$attrs['manifest'] = '';
						break;
					}
				case 'frame':
				case 'iframe':
					if (isset($attrs['src'])) {
						$rebuild = true;
						$attrs['src'] = complete_url($attrs['src']) . '&nf=1';
					}
					if (isset($attrs['longdesc'])) {
						$rebuild = true;
						$attrs['longdesc'] = complete_url($attrs['longdesc']);
					}
					break;
				
				case 'a':
					if (isset($attrs['href'])) { // Juste in case... :p
						$rebuild = true;
						
						if (!isset($attrs['title']) || empty($attrs['title'])) {
							$attrs['title'] = $attrs['href'];
						}
						else {
							$attrs['title'] .= ' (' . $attrs['href'] . ')';
						}
						
						$attrs['href'] = complete_url($attrs['href']);
					}
					break;
				default:
					foreach ($tags[$tag] as $attr) {
						if (isset($attrs[$attr])) {
							$rebuild = true;
							if (!preg_match('#data:#', $attrs[$attr])) {
								$attrs[$attr] = complete_url($attrs[$attr]);
							}
						}
					}
					break;
			}
		}

		if ($rebuild) {
			$new_tag = "<$tag";
			foreach ($attrs as $name => $value) {
				$delim = strpos($value, '"') && !strpos($value, "'") ? "'" : '"';
				$new_tag .= ' ' . $name . ($value !== false ? '=' . $delim.$value.$delim : '');
			}

			$_response_body = str_replace($matches[0][$i], $new_tag . '>' . $extra_html, $_response_body);
		}
	}

	if (!isset($_GET['noform']))
	{
		$_url_form = '<div style="border-radius: 0 0 30px 0; top:-110px; height: 140px; width: 500px; left: -470px; overflow: hidden; padding: 4px; text-align: center; border-bottom: 1px solid #755; color: #000; background-color: #ff9864; font-size: 12px; z-index: 2147483647; position:fixed; text-shadow: none;" onmouseover="this.style.top=\'0px\'; this.style.width=\'100%\'; this.style.left=\'0px\'" onmouseout="this.style.top=\'-110px\'; this.style.width=\'500px\'; this.style.left=\'-470px\'">' . "\n";
		$_url_form .= '<form method="post" action="' . $_script_url . '" style="text-align:center">' . "\n";
		$_url_form .= '<a style="color: #000; text-shadow: none;" href="' . $_script_base . '">' . $GLOBALS['_labels']['home'] . '</a> — <a style="color: #000;text-shadow: none;" href="' . $_url . '">' . $GLOBALS['_labels']['gotothepage'] . '</a><br />';
		$_url_form .= '<input type="text" size="80" name="' . $q . '" value="' . $_url . '" />';
		$_url_form .= '<input type="submit" name="go" style="font-size: 12px;" value="GO"/>';
		$_url_form .= '<br /><hr />';
		
		foreach ($_flags as $flag_name => $flag_value) {
			$_url_form .= '<label><input type="checkbox" name="' . $hl . '[' . $flag_name . ']"' . ($flag_value ? ' checked="checked"' : '') . ' /> ' . $GLOBALS['_labels'][$flag_name][0] . '</label>';
		}

		$_url_form .= '</form></div>';
		$_response_body = str_replace('</head>', '<meta name="robots" content="noindex, nofollow" /></head>', $_response_body);
	
		$_response_body = preg_replace('#\<\s*body(.*?)\>#si', "$0\n$_url_form" , $_response_body, 1);
	}
}

$_response_keys['content-disposition'] = 'Content-Disposition';
$_response_headers['content-disposition'][0] = empty($_content_disp) ? ($_content_type == 'application/octet_stream' ? 'attachment' : 'inline') . '; filename="' . $_url_parts['file'] . '"' : $_content_disp;

$_response_keys['content-length'] = 'Content-Length';
$_response_headers['content-length'][0] = strlen($_response_body);
$_response_headers = array_filter($_response_headers);
$_response_keys = array_filter($_response_keys);

header(array_shift($_response_keys));
array_shift($_response_headers);
$count_r_h = count($_response_headers);
$i = 0;
foreach ($_response_headers as $name => $array) {
	foreach ($array as $value) {
		header($_response_keys[$name] . ': ' . $value, false);
	}
}

$_response_body = preg_replace('#<\s*body(.*?)>#si', "$0\n" . '' , $_response_body);
$_response_body = preg_replace('#</\s*body>#si', '' . "$0" , $_response_body);

echo $_response_body;
