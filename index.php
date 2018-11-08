<?php
/*
Plugin Name: WP JWT
Description: Plugin para fazer login via JWT e permite utilizar requisições autenticações sem cookie
*/
include('jwt.php');

function wm_api_init() {
	$namespace = 'wpjwt/v1';

	register_rest_route($namespace, '/login', array(
		'methods' => 'POST',
		'callback' => 'wm_api_ep_login'
	));

	register_rest_route($namespace, '/validate', array(
		'methods' => 'GET',
		'callback' => 'wm_api_ep_validate'
	));

	add_filter('rest_pre_dispatch', 'wm_rest_pre_dispatch', 10, 3);
}

function wm_rest_pre_dispatch($url, $server, $req) {
	$params = $req->get_params();

	if(!empty($params['jwt'])) {
		$jwt = new JWT();

		$info = $jwt->validate($params['jwt']);

		if($info && !empty($info->id)) {
			wp_set_current_user($info->id);
		}
	}
}

function wm_api_ep_validate($req) {
	$array = array('valid' => false);
	$params = $req->get_params();

	if(!empty($params['jwt'])) {
		$jwt = new JWT();

		$info = $jwt->validate($params['jwt']);

		if($info && !empty($info->id)) {
			$array['valid'] = true;
		}
	}

	return $array;
}

function wm_api_ep_login($req) {
	$array = array('logged' => false);
	$params = $req->get_params();

	$resust = wp_signon(array(
		'user_login' => $params['username'],
		'user_password' => $params['password']
	));

	if(isset($resust->data)) {
		$jwt = new JWT();

		$token = $jwt->create( array('id' => $resust->data->ID) );

		$array['logged'] = true;
		$array['token'] = $token;
	}
	
	return $array;
}

add_action('rest_api_init', 'wm_api_init');