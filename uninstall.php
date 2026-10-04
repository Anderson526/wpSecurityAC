<?php
// Limpieza al desinstalar: borra ajustes y transients de bloqueo.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

delete_option( 'anderc_asec_settings' );

// Transients de intentos y bloqueos.
$wpdb->query( // phpcs:ignore WordPress.DB
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '\_transient\_anderc\_asec\_%'
	    OR option_name LIKE '\_transient\_timeout\_anderc\_asec\_%'"
);
