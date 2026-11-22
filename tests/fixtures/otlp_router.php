<?php

// Fake OTLP endpoint for `php -S`: appends "path auth base64(body)" per request to $WT_OTLP_LOG.
file_put_contents((string) getenv('WT_OTLP_LOG'), sprintf(
    "%s %s %s\n",
    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),
    str_replace(' ', '_', $_SERVER['HTTP_AUTHORIZATION'] ?? '-'),
    base64_encode((string) file_get_contents('php://input')),
), FILE_APPEND | LOCK_EX);
http_response_code(200);
