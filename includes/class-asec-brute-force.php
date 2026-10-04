<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Limitador de intentos de acceso: bloquea la IP tras varios fallos en una ventana de tiempo.
 */
class ASEC_Brute_Force {

	const ATTEMPTS_PREFIX = 'anderc_asec_att_';
	const LOCK_PREFIX     = 'anderc_asec_lock_';

	public function __construct() {
		$settings = ASEC_Plugin::get_settings();
		if ( empty( $settings['limit_enabled'] ) ) {
			return;
		}

		add_action( 'wp_authenticate', array( $this, 'maybe_block' ), 1 );
		add_action( 'wp_login_failed', array( $this, 'record_failure' ) );
		add_action( 'wp_login', array( $this, 'clear_attempts' ) );
		add_filter( 'login_errors', array( $this, 'append_remaining' ) );
	}

	private function ip_key( $prefix ) {
		return $prefix . md5( ASEC_Plugin::get_ip() );
	}

	/**
	 * Detiene el intento con wp_die() si la IP está bloqueada.
	 */
	public function maybe_block( $username = '' ) {
		if ( '' === (string) $username ) {
			return;
		}

		$lock = get_transient( $this->ip_key( self::LOCK_PREFIX ) );
		if ( ! $lock ) {
			return;
		}

		$settings = ASEC_Plugin::get_settings();

		wp_die(
			sprintf(
				/* translators: %d: minutos de bloqueo. */
				esc_html__( 'Demasiados intentos de acceso fallidos. Tu IP ha sido bloqueada temporalmente. Inténtalo de nuevo en unos %d minutos.', 'anderc-security' ),
				(int) $settings['lockout_minutes']
			),
			esc_html__( 'Acceso bloqueado', 'anderc-security' ),
			array( 'response' => 403 )
		);
	}

	public function record_failure() {
		$settings = ASEC_Plugin::get_settings();
		$window   = max( 1, (int) $settings['window_minutes'] ) * MINUTE_IN_SECONDS;
		$max      = max( 1, (int) $settings['max_attempts'] );
		$key      = $this->ip_key( self::ATTEMPTS_PREFIX );

		$attempts   = get_transient( $key );
		$attempts   = is_array( $attempts ) ? $attempts : array();
		$attempts[] = time();

		// Conservar solo los intentos dentro de la ventana de tiempo.
		$attempts = array_values(
			array_filter(
				$attempts,
				function ( $timestamp ) use ( $window ) {
					return ( time() - (int) $timestamp ) <= $window;
				}
			)
		);

		if ( count( $attempts ) >= $max ) {
			$lockout = max( 1, (int) $settings['lockout_minutes'] ) * MINUTE_IN_SECONDS;
			set_transient( $this->ip_key( self::LOCK_PREFIX ), time(), $lockout );
			delete_transient( $key );
			return;
		}

		set_transient( $key, $attempts, $window );
	}

	public function clear_attempts() {
		delete_transient( $this->ip_key( self::ATTEMPTS_PREFIX ) );
	}

	/**
	 * Añade al mensaje de error cuántos intentos quedan antes del bloqueo.
	 */
	public function append_remaining( $errors ) {
		$attempts = get_transient( $this->ip_key( self::ATTEMPTS_PREFIX ) );
		if ( ! is_array( $attempts ) || empty( $attempts ) ) {
			return $errors;
		}

		$settings  = ASEC_Plugin::get_settings();
		$remaining = max( 0, (int) $settings['max_attempts'] - count( $attempts ) );

		if ( $remaining > 0 ) {
			$errors .= '<br />' . sprintf(
				/* translators: %d: intentos restantes. */
				esc_html( _n( 'Te queda %d intento antes del bloqueo temporal.', 'Te quedan %d intentos antes del bloqueo temporal.', $remaining, 'anderc-security' ) ),
				$remaining
			);
		}

		return $errors;
	}
}
