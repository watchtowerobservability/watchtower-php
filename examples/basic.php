<?php
require __DIR__ . '/../vendor/autoload.php';

$tp = Watchtower\Watchtower::init(Watchtower\Config::fromEnv('example-php'));
$tp->getTracer('example')->spanBuilder('hello')->startSpan()->end();
$tp->shutdown(); // flush before exit
