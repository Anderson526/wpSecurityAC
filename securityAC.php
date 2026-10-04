<?php
/*
Plugin Name: Core Security & Login Protector - toolkitAC
Plugin URI: https://anderson526.github.io/portfolio-profesional/
Description: Protege tu sitio de ataques de fuerza bruta, oculta la URL de acceso y aplica endurecimiento básico sin configuraciones técnicas. Parte de la suite AC Essential.
Version: 1.0.0
Author: Anderson Chila
Author URI: https://anderson526.github.io/portfolio-profesional/
Text Domain: anderc-security
Domain Path: /languages
Requires at least: 6.0
Requires PHP: 7.4
License: GPL-2.0-or-later
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ANDERC_ASEC_VERSION', '1.0.0' );
define( 'ANDERC_ASEC_FILE', __FILE__ );
define( 'ANDERC_ASEC_DIR', plugin_dir_path( __FILE__ ) );
define( 'ANDERC_ASEC_URL', plugin_dir_url( __FILE__ ) );

// Autoloader estilo PSR-4 (compatible con Composer si se añade vendor/).
spl_autoload_register(
	function ( $class ) {
		if ( 0 !== strpos( $class, 'ASEC_' ) ) {
			return;
		}
		$file = ANDERC_ASEC_DIR . 'includes/class-' . str_replace( '_', '-', strtolower( $class ) ) . '.php';
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
);

if ( file_exists( ANDERC_ASEC_DIR . 'vendor/autoload.php' ) ) {
	require_once ANDERC_ASEC_DIR . 'vendor/autoload.php';
}

ASEC_Plugin::instance();
