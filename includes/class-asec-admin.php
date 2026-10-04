<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Página de administración de seguridad.
 */
class ASEC_Admin {

	const SLUG = 'anderc-security';

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_anderc_asec_save', array( $this, 'save' ) );
	}

	public function register_menu() {
		add_menu_page(
			__( 'AC Security', 'anderc-security' ),
			__( 'AC Security', 'anderc-security' ),
			'manage_options',
			self::SLUG,
			array( $this, 'render' ),
			'dashicons-shield',
			65
		);
	}

	public function assets( $hook ) {
		if ( 'toplevel_page_' . self::SLUG !== $hook ) {
			return;
		}
		wp_enqueue_style( 'anderc-asec-admin', ANDERC_ASEC_URL . 'assets/css/admin.css', array(), ANDERC_ASEC_VERSION );
	}

	public function save() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'No tienes permisos suficientes.', 'anderc-security' ) );
		}
		check_admin_referer( 'anderc_asec_save' );

		$settings = ASEC_Plugin::get_settings();

		$slug = isset( $_POST['login_slug'] ) ? sanitize_title( wp_unslash( $_POST['login_slug'] ) ) : '';
		// Evita slugs que colisionen con rutas del núcleo.
		if ( in_array( $slug, array( 'wp-admin', 'wp-login', 'wp-login.php', 'admin', 'login', 'wp-content', 'wp-includes' ), true ) ) {
			$slug = '';
		}

		$settings['login_slug']          = $slug;
		$settings['limit_enabled']       = empty( $_POST['limit_enabled'] ) ? 0 : 1;
		$settings['max_attempts']        = isset( $_POST['max_attempts'] ) ? max( 1, min( 20, absint( $_POST['max_attempts'] ) ) ) : 3;
		$settings['window_minutes']      = isset( $_POST['window_minutes'] ) ? max( 1, min( 1440, absint( $_POST['window_minutes'] ) ) ) : 15;
		$settings['lockout_minutes']     = isset( $_POST['lockout_minutes'] ) ? max( 1, min( 10080, absint( $_POST['lockout_minutes'] ) ) ) : 30;
		$settings['hide_version']        = empty( $_POST['hide_version'] ) ? 0 : 1;
		$settings['disable_xmlrpc']      = empty( $_POST['disable_xmlrpc'] ) ? 0 : 1;
		$settings['disable_file_editor'] = empty( $_POST['disable_file_editor'] ) ? 0 : 1;
		$settings['block_user_enum']     = empty( $_POST['block_user_enum'] ) ? 0 : 1;

		ASEC_Plugin::update_settings( $settings );

		wp_safe_redirect( add_query_arg( array( 'page' => self::SLUG, 'updated' => '1' ), admin_url( 'admin.php' ) ) );
		exit;
	}

	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s = ASEC_Plugin::get_settings();
		?>
		<div class="wrap anderc-wrap">
			<h1><span class="anderc-badge">AC</span> <?php esc_html_e( 'Core Security & Login Protector', 'anderc-security' ); ?></h1>

			<?php if ( isset( $_GET['updated'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Ajustes guardados correctamente.', 'anderc-security' ); ?></p></div>
				<?php if ( ! empty( $s['login_slug'] ) ) : ?>
					<div class="notice notice-warning">
						<p>
							<strong><?php esc_html_e( '¡Importante! Tu nueva URL de acceso es:', 'anderc-security' ); ?></strong>
							<code><?php echo esc_html( home_url( '/' . $s['login_slug'] ) ); ?></code><br />
							<?php esc_html_e( 'Guárdala en un lugar seguro: wp-login.php y wp-admin quedarán bloqueados para visitantes.', 'anderc-security' ); ?>
						</p>
					</div>
				<?php endif; ?>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="anderc_asec_save" />
				<?php wp_nonce_field( 'anderc_asec_save' ); ?>

				<h2><?php esc_html_e( 'Ocultar URL de acceso', 'anderc-security' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="login_slug"><?php esc_html_e( 'Nueva ruta de acceso', 'anderc-security' ); ?></label></th>
						<td>
							<code><?php echo esc_html( home_url( '/' ) ); ?></code>
							<input type="text" id="login_slug" name="login_slug" value="<?php echo esc_attr( $s['login_slug'] ); ?>" placeholder="mi-acceso" />
							<p class="description"><?php esc_html_e( 'Déjalo vacío para desactivar. Con esta opción activa, wp-login.php devolverá un error 404.', 'anderc-security' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Limitador de intentos de acceso', 'anderc-security' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Activar protección', 'anderc-security' ); ?></th>
						<td><label><input type="checkbox" name="limit_enabled" value="1" <?php checked( $s['limit_enabled'] ); ?> /> <?php esc_html_e( 'Bloquear IPs con demasiados intentos fallidos', 'anderc-security' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><label for="max_attempts"><?php esc_html_e( 'Intentos permitidos', 'anderc-security' ); ?></label></th>
						<td><input type="number" id="max_attempts" name="max_attempts" value="<?php echo esc_attr( $s['max_attempts'] ); ?>" min="1" max="20" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="window_minutes"><?php esc_html_e( 'Ventana de tiempo (minutos)', 'anderc-security' ); ?></label></th>
						<td><input type="number" id="window_minutes" name="window_minutes" value="<?php echo esc_attr( $s['window_minutes'] ); ?>" min="1" max="1440" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="lockout_minutes"><?php esc_html_e( 'Duración del bloqueo (minutos)', 'anderc-security' ); ?></label></th>
						<td>
							<input type="number" id="lockout_minutes" name="lockout_minutes" value="<?php echo esc_attr( $s['lockout_minutes'] ); ?>" min="1" max="10080" />
							<p class="description"><?php esc_html_e( 'Ejemplo: 3 intentos fallidos en 15 minutos bloquean la IP durante 30 minutos.', 'anderc-security' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Endurecimiento', 'anderc-security' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Opciones', 'anderc-security' ); ?></th>
						<td>
							<label><input type="checkbox" name="hide_version" value="1" <?php checked( $s['hide_version'] ); ?> /> <?php esc_html_e( 'Ocultar la versión de WordPress', 'anderc-security' ); ?></label><br />
							<label><input type="checkbox" name="disable_xmlrpc" value="1" <?php checked( $s['disable_xmlrpc'] ); ?> /> <?php esc_html_e( 'Desactivar XML-RPC (actívalo si no usas Jetpack ni apps móviles)', 'anderc-security' ); ?></label><br />
							<label><input type="checkbox" name="disable_file_editor" value="1" <?php checked( $s['disable_file_editor'] ); ?> /> <?php esc_html_e( 'Desactivar el editor de archivos de temas y plugins', 'anderc-security' ); ?></label><br />
							<label><input type="checkbox" name="block_user_enum" value="1" <?php checked( $s['block_user_enum'] ); ?> /> <?php esc_html_e( 'Bloquear la enumeración de usuarios (?author=N y REST API)', 'anderc-security' ); ?></label>
						</td>
					</tr>
				</table>

				<?php submit_button( __( 'Guardar cambios', 'anderc-security' ) ); ?>
			</form>
		</div>
		<?php
	}
}
