<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Núcleo del plugin: carga módulos y centraliza los ajustes.
 */
final class ASEC_Plugin {

	const OPTION = 'anderc_asec_settings';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'init', array( $this, 'load_textdomain' ) );

		new ASEC_Hide_Login();
		new ASEC_Brute_Force();
		new ASEC_Hardening();

		if ( is_admin() ) {
			new ASEC_Admin();
			new ASEC_Donations();
		}
	}

	public function load_textdomain() {
		load_plugin_textdomain( 'anderc-security', false, dirname( plugin_basename( ANDERC_ASEC_FILE ) ) . '/languages' );
	}

	public static function defaults() {
		return array(
			'login_slug'          => '',
			'limit_enabled'       => 1,
			'max_attempts'        => 3,
			'window_minutes'      => 15,
			'lockout_minutes'     => 30,
			'hide_version'        => 1,
			'disable_xmlrpc'      => 0,
			'disable_file_editor' => 1,
			'block_user_enum'     => 1,
		);
	}

	public static function get_settings() {
		$settings = get_option( self::OPTION, array() );
		return wp_parse_args( is_array( $settings ) ? $settings : array(), self::defaults() );
	}

	public static function update_settings( array $settings ) {
		update_option( self::OPTION, $settings );
	}

	/**
	 * IP del visitante. Se usa REMOTE_ADDR porque las cabeceras de proxy son falsificables.
	 */
	public static function get_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}
}
