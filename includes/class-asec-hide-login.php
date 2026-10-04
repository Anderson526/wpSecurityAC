<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Oculta wp-login.php tras un slug personalizado (ej. /mi-acceso) y bloquea el acceso directo.
 */
class ASEC_Hide_Login {

	/**
	 * @var string Slug personalizado de acceso ('' = módulo desactivado).
	 */
	private $slug = '';

	/**
	 * @var bool Verdadero cuando servimos nosotros la pantalla de acceso.
	 */
	private $serving_login = false;

	public function __construct() {
		$settings   = ASEC_Plugin::get_settings();
		$this->slug = sanitize_title( (string) $settings['login_slug'] );

		if ( '' === $this->slug ) {
			return;
		}

		add_filter( 'site_url', array( $this, 'rewrite_login_url' ), 10, 2 );
		add_filter( 'network_site_url', array( $this, 'rewrite_login_url' ), 10, 2 );
		add_filter( 'wp_redirect', array( $this, 'rewrite_login_url' ), 10, 1 );

		add_action( 'init', array( $this, 'block_direct_access' ), 1 );
		add_action( 'wp_loaded', array( $this, 'maybe_serve_login' ), 1 );
	}

	/**
	 * Reescribe cualquier URL que apunte a wp-login.php hacia el slug personalizado.
	 */
	public function rewrite_login_url( $url, $path = '' ) {
		if ( is_string( $url ) && false !== strpos( $url, 'wp-login.php' ) ) {
			$url = str_replace( 'wp-login.php', $this->slug, $url );
		}
		return $url;
	}

	/**
	 * Bloquea wp-login.php directo y wp-admin para visitantes no identificados.
	 */
	public function block_direct_access() {
		global $pagenow;

		if ( $this->serving_login || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		// Acceso directo a wp-login.php.
		if ( 'wp-login.php' === $pagenow && ! $this->request_is_custom_slug() ) {
			$this->deny();
		}

		// wp-admin sin sesión: evita revelar el slug mediante la redirección automática.
		if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax()
			&& ! in_array( $pagenow, array( 'admin-post.php', 'async-upload.php' ), true ) ) {
			$this->deny();
		}
	}

	/**
	 * Si la URL solicitada coincide con el slug, carga internamente wp-login.php.
	 */
	public function maybe_serve_login() {
		global $pagenow;

		if ( ! $this->request_is_custom_slug() ) {
			return;
		}

		$this->serving_login = true;
		$pagenow             = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride

		status_header( 200 );
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	private function request_is_custom_slug() {
		return $this->current_path() === $this->slug;
	}

	private function current_path() {
		if ( empty( $_SERVER['REQUEST_URI'] ) ) {
			return '';
		}

		$uri  = rawurldecode( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) );
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$home = (string) wp_parse_url( home_url(), PHP_URL_PATH );

		if ( '' !== $home && 0 === strpos( $path, $home ) ) {
			$path = substr( $path, strlen( $home ) );
		}

		return trim( $path, '/' );
	}

	private function deny() {
		status_header( 404 );
		nocache_headers();
		wp_die(
			esc_html__( 'Esta página no está disponible.', 'anderc-security' ),
			esc_html__( 'Página no encontrada', 'anderc-security' ),
			array( 'response' => 404 )
		);
	}
}
