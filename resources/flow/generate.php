<?php

declare(strict_types=1);

// generates the oidc flow diagrams: php resources/flow/generate.php

namespace Chubbyphp\Oidc\Resources\Flow;

require_once __DIR__.'/diagram.php';

$flows = ['frontend', 'backend', 'machine-to-machine'];

foreach ($flows as $name) {
    /** @var FlowDiagram $diagram */
    $diagram = require __DIR__.'/'.$name.'/'.$name.'.php';

    $target = __DIR__.'/'.$name.'/'.$name.'.svg';
    $svg = render($diagram);

    preg_match('/viewBox="0 0 (\d+) (\d+)"/', $svg, $matches);

    file_put_contents($target, $svg);

    echo \sprintf('%s: %sx%s', $target, $matches[1] ?? '?', $matches[2] ?? '?'), PHP_EOL;
}
