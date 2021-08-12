<?php

define('INITIAL_STEP', 0);
define('REDIRECT_STEP', 1);
define('EXCHANGE_STEP', 2);
define('ERROR_STEP', -1);

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

/**
 * CHANGE YOUR CREDENTIALS AND URL'S
 */
$applicationId = '<SEU CLIENT ID>';
$applicationSecret = '<SEU CLIENT SECRET>';
$urlPSC = "https://apicloudid.hom.vaultid.com.br"; //PSC URL
$myBaseUri = 'http://172.17.0.1:93'; //URL to callback, @see application register service

$uri_to_redirect_user = '';
$result = '';

$error = filter_input(INPUT_GET, 'error', FILTER_SANITIZE_ENCODED);
$code = filter_input(INPUT_GET, 'code', FILTER_SANITIZE_ENCODED);

$step = INITIAL_STEP;

if (!empty($error)) {
    $step = ERROR_STEP;
} else if (empty($code)) {
    $step = INITIAL_STEP;
} else if ($code === "authenticate") {
    $username = $_POST['username'];
    $step = REDIRECT_STEP;
} else {
    $step = EXCHANGE_STEP;
}



if ($step === ERROR_STEP) {
    $errorDescription = filter_input(INPUT_GET, 'error_description', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

} else if ($step === REDIRECT_STEP) {

    //Generate random code verifier (@see RFC 7636 https://tools.ietf.org/html/rfc7636)
    $code_verifier = createRandom();
    $code_challenge = base64url_encode(hash('sha256', mb_convert_encoding($code_verifier, 'ascii'), true));

    $_SESSION['code_verifier'] = $code_verifier;
    $_SESSION['code_challenge'] = $code_challenge;

    $uri_to_redirect_user = rtrim($urlPSC, '/') . '/oauth/authorize?' . http_build_query([
        'integration'           => 'true',
        'response_type'         => 'code',
        'client_id'             => $applicationId,
        'code_challenge'        => $code_challenge,
        'code_challenge_method' => 'S256', //S256 or plain
        'redirect_uri'          => $myBaseUri,
        'state'                 => sha1(rand(0, 9999999)) . '_any_state_xpto', //Optional param
        'scope'                 => 'signature_session', //Optional param
        'login_hint'            => $username, //Optional param (CPF/CNPJ)
        'lifetime'              => 999900,
    ]);

    $_SESSION['time_before'] = microtime(true);
    header('Location: ' . $uri_to_redirect_user);

} else if ($step === EXCHANGE_STEP) {

    $body = [
        "grant_type"    => "authorization_code",
        "client_id"     => $applicationId,
        "client_secret" => $applicationSecret,
        "code"          => $code,
        'code_verifier' => $_SESSION['code_verifier'],
        "redirect_uri"  => $myBaseUri,
    ];

    $curl = curl_init();

    curl_setopt_array($curl, array(
        CURLOPT_URL            => rtrim($urlPSC, '/') . '/oauth',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING       => '',
        CURLOPT_MAXREDIRS      => 10,
        CURLOPT_TIMEOUT        => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST  => 'POST',
        CURLOPT_POSTFIELDS     => json_encode($body),
        CURLOPT_HTTPHEADER     => array(
            'Content-Type: application/json',
            'Accept: application/json',
        ),
    ));

    $response = curl_exec($curl);
    curl_close($curl);

    $result = json_decode($response, true);
}

/**
 * Helper functions
 */
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

function createRandom() {
    if (function_exists('random_bytes')) {
        $randomData = random_bytes(32);
    } elseif (function_exists('openssl_random_pseudo_bytes')) {
        $randomData = openssl_random_pseudo_bytes(32);
    } elseif (function_exists('mcrypt_create_iv')) {
        $randomData = mcrypt_create_iv(32, MCRYPT_DEV_URANDOM);
    } elseif (@file_exists('/dev/urandom')) { // Get 32 bytes of random data
        $randomData = file_get_contents('/dev/urandom', false, null, 0, 32) . uniqid(mt_rand(), true);
    } else {
        return false;
    }
    return base64url_encode($randomData);
}
?>

<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Vault Cloud Authorization Example</title>
        <meta charset="utf-8">
        <link href="https://netdna.bootstrapcdn.com/twitter-bootstrap/2.3.2/css/bootstrap-combined.no-icons.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container" id="app">
            <div class="form-horizontal" id="login">
                <fieldset>
                    <div>
                        <h2>Sample Application</h2>
                    </div>

                    <?php if ($step === ERROR_STEP): ?>
                    <div class="col-md-4 col-md-offset-4" >
                        <div class="alert alert-danger" role="alert">
                            <?php echo $errorDescription; ?>
                        </div>
                    </div>
                    <?php endif;?>

                    <?php if ($step === INITIAL_STEP): ?>
                    <div class="col-md-4 col-md-offset-4" >
                        <div class="alert alert-primary" role="alert">
                            <form action="/?code=authenticate" method="POST">
                                <input type='text' name='username' placeholder="CPF/CNPJ">
                                <input type="submit" value="Autenticar" />
                            </form>
                        </div>
                    </div>
                    <?php endif;?>

                    <?php if ($step === EXCHANGE_STEP): ?>
                    <div class="col-md-4 col-md-offset-4" >
                        <div class="alert alert-primary" role="alert">
                          <?php echo '<pre>' . print_r($result, TRUE) . '</pre>'; ?>
                        </div>
                    </div>
                    <?php endif;?>
                </fieldset>
            </div>
        </div>
    </body>
</html>
