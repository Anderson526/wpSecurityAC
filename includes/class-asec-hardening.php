<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Endurecimiento básico: versión de WP, XML-RPC, editor de archivos y enumeración de usuarios.
 */
class ASEC_Hardening {

	public function __construct() {
		$s = ASEC_Plugin::get_settings();

		if ( ! empty( $s['hide_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		if ( ! empty( $s['disable_xmlrpc'] ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		}

		if ( ! empty( $s['disable_file_editor'] ) ) {
			add_filter( 'map_meta_cap', array( $this, 'disable_file_editor' ), 10, 2 );
		}

		if ( ! empty( $s['block_user_enum'] ) ) {
			add_action( 'init', array( $this, 'block_author_scan' ) );
			add_filter( 'rest_endpoints', array( $this, 'restrict_users_endpoint' ) );
		}
	}

	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	public function disable_file_editor( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_plugins', 'edit_themes', 'edit_files' ), true ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	/**
	 * Bloquea el escaneo de usuarios mediante ?author=N para visitantes.
	 */
	public function block_author_scan() {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( isset( $_GET['author'] ) && preg_match( '/^\d+$/', (string) wp_unslash( $_GET['author'] ) ) ) {
			wp_die(
				esc_html__( 'Petición no permitida.', 'anderc-security' ),
				esc_html__( 'Prohibido', 'anderc-security' ),
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * Oculta el listado de usuarios de la REST API a visitantes no identificados.
	 */
	public function restrict_users_endpoint( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		return $endpoints;
	}
}
