<?php

declare(strict_types=1);

// layout engine for the oidc sequence diagrams, see generate.php
//
// the types (FlowSegment, FlowLine, FlowParticipant, FlowItem, FlowDiagram, ...) are declared as type aliases within
// phpstan.neon: a line is a string or an array of segments, a segment is a string or ['t' => ..., 'mono' => ...]

namespace Chubbyphp\Oidc\Resources\Flow;

const MARGIN = 20;

const DEFAULT_LAYOUT = ['laneGap' => 300, 'participantWidth' => 280, 'noteWidth' => 270];

// the fonts are embedded (subset of Noto Sans / Noto Sans Mono, OFL, see ../fonts/README.md), so the diagrams render the
// same everywhere and the text can be measured with the real glyph advances (../fonts/metrics.json, per character in em)
const FONT_DIR = __DIR__.'/../fonts';
const FONTS = [
    'sans-400' => ['family' => 'Noto Sans', 'weight' => 400],
    'sans-700' => ['family' => 'Noto Sans', 'weight' => 700],
    'mono-400' => ['family' => 'Noto Sans Mono', 'weight' => 400],
];

const SANS = "'Noto Sans', sans-serif";
const MONO = "'Noto Sans Mono', monospace";

const C = [
    'bg' => '#ffffff',
    'text' => '#1f2328',
    'muted' => '#59636e',
    'line' => '#d1d9e0',
    'arrow' => '#59636e',
    'band' => '#f6f8fa',
    'red' => '#cf222e',
    'redBg' => '#ffebe9',
];

const PALETTE = [
    'blue' => ['stroke' => '#0969da', 'fill' => '#ddf4ff', 'text' => '#0550ae'],
    'purple' => ['stroke' => '#8250df', 'fill' => '#fbefff', 'text' => '#6639ba'],
    'green' => ['stroke' => '#1a7f37', 'fill' => '#dafbe1', 'text' => '#116329'],
    'orange' => ['stroke' => '#bc4c00', 'fill' => '#fff1e5', 'text' => '#953800'],
];

/**
 * @return array<string, array<string, float>>
 */
function metrics(): array
{
    /** @var null|array<string, array<string, float>> $metrics */
    static $metrics = null;

    if (null === $metrics) {
        /** @var array<string, array<string, float>> $metrics */
        $metrics = json_decode((string) file_get_contents(FONT_DIR.'/metrics.json'), true, flags: JSON_THROW_ON_ERROR);
    }

    return $metrics;
}

function fontFaces(): string
{
    /** @var null|string $fontFaces */
    static $fontFaces = null;

    if (null === $fontFaces) {
        $fontFaces = implode("\n", array_map(static function (string $name, array $font): string {
            $data = base64_encode((string) file_get_contents(FONT_DIR.'/'.$name.'.woff2'));

            return \sprintf(
                "@font-face{font-family:'%s';font-weight:%d;src:url(data:font/woff2;base64,%s) format('woff2');}",
                $font['family'],
                $font['weight'],
                $data
            );
        }, array_keys(FONTS), FONTS));
    }

    return $fontFaces;
}

// numbers the way javascript prints them: integral floats without a decimal point
function num(float|int $value): string
{
    return (string) $value;
}

function esc(string $value): string
{
    return str_replace(['&', '<', '>', '"'], ['&amp;', '&lt;', '&gt;', '&quot;'], $value);
}

/**
 * @param FlowSegment|string $s
 *
 * @return FlowSegment
 */
function seg(array|string $s): array
{
    return \is_string($s) ? ['t' => $s] : $s;
}

/**
 * @return array{t: string, mono: true}
 */
function m(string $t): array
{
    return ['t' => $t, 'mono' => true];
}

/**
 * @return array{t: string, bold: true}
 */
function b(string $t): array
{
    return ['t' => $t, 'bold' => true];
}

/**
 * @return array{t: string, color: string}
 */
function r(string $t): array
{
    return ['t' => $t, 'color' => C['red']];
}

/**
 * @return array{t: string, mono: true, color: string}
 */
function rm(string $t): array
{
    return ['t' => $t, 'mono' => true, 'color' => C['red']];
}

/**
 * @return array{t: string, color: string}
 */
function muted(string $t): array
{
    return ['t' => $t, 'color' => C['muted']];
}

/**
 * @param array{mono?: bool, bold?: bool, color?: string} $style
 *
 * @return FlowSegment
 */
function link(string $t, string $href, array $style = []): array
{
    return ['t' => $t, 'href' => $href] + $style;
}

/**
 * @param FlowLine $line
 *
 * @return list<FlowSegment>
 */
function toSegments(array|string $line): array
{
    return array_map(seg(...), \is_array($line) ? $line : [$line]);
}

/**
 * the whole line in muted color, unless a segment brings its own.
 *
 * @param FlowLine $line
 *
 * @return list<FlowSegment>
 */
function mutedLine(array|string $line): array
{
    return array_map(static fn (array $s): array => $s + ['color' => C['muted']], toSegments($line));
}

/**
 * @param FlowSegment $s
 */
function fontOf(array $s): string
{
    return ($s['mono'] ?? false) ? 'mono-400' : (($s['bold'] ?? false) ? 'sans-700' : 'sans-400');
}

/**
 * width of a text run in px: glyph advances without kerning (kerning only makes it narrower), plus a little slack.
 *
 * @param FlowLine $line
 */
function measure(array|string $line, float $size): float
{
    $metrics = metrics();

    $width = 0.0;

    foreach (toSegments($line) as $s) {
        $widths = $metrics[fontOf($s)];

        $sum = 0.0;

        foreach (mb_str_split($s['t']) as $ch) {
            $sum += $widths[$ch] ?? 0.6;
        }

        $width += $sum;
    }

    return $width * $size * 1.02;
}

/**
 * @param list<FlowSegment> $segments
 *
 * @return list<FlowSegment>
 */
function trimLast(array $segments): array
{
    $last = array_key_last($segments);

    if (null !== $last) {
        $segments[$last]['t'] = rtrim($segments[$last]['t']);
    }

    return $segments;
}

/**
 * a token which does not fit into a line on its own (a long identifier, ...) gets broken by character.
 *
 * @param FlowSegment $token
 *
 * @return list<FlowSegment>
 */
function chunk(array $token, float $maxWidth, float $size): array
{
    $chunks = [];

    foreach (mb_str_split($token['t']) as $ch) {
        $last = array_key_last($chunks);

        if (null !== $last) {
            $extended = ['t' => $chunks[$last]['t'].$ch] + $chunks[$last];

            if (measure([$extended], $size) <= $maxWidth) {
                $chunks[$last] = $extended;

                continue;
            }
        }

        $chunks[] = ['t' => $ch] + $token;
    }

    return $chunks;
}

/**
 * split after spaces and slashes, keeping the delimiter (like javascript's split with a lookbehind, which drops the
 * trailing empty piece).
 *
 * @return list<string>
 */
function splitWords(string $t): array
{
    /** @var list<string> $parts */
    $parts = preg_split('/(?<=[ \/])/u', $t);

    if (\count($parts) > 1 && '' === $parts[array_key_last($parts)]) {
        array_pop($parts);
    }

    return $parts;
}

/**
 * greedy word wrap (after spaces and slashes) keeping the segment styles, returns the lines as segment arrays.
 *
 * @param FlowLine $line
 *
 * @return list<list<FlowSegment>>
 */
function wrap(array|string $line, float $maxWidth, float $size): array
{
    $tokens = [];

    foreach (toSegments($line) as $s) {
        foreach (splitWords($s['t']) as $t) {
            $token = ['t' => $t] + $s;

            if (measure([$token], $size) <= $maxWidth) {
                $tokens[] = $token;
            } else {
                array_push($tokens, ...chunk($token, $maxWidth, $size));
            }
        }
    }

    $lines = [[]];

    foreach ($tokens as $token) {
        $last = array_key_last($lines);
        $current = $lines[$last];
        $fits = measure(trimLast([...$current, $token]), $size) <= $maxWidth;

        if ($fits || [] === $current) {
            $lines[$last][] = $token;
        } else {
            $lines[] = [$token];
        }
    }

    return array_map(trimLast(...), $lines);
}

/**
 * @param list<list<FlowSegment>> $lines
 *
 * @return list<list<FlowSegment>>
 */
function indent(array $lines, string $by): array
{
    return array_map(
        static fn (array $tokens, int $i): array => 0 === $i ? $tokens : [['t' => $by], ...$tokens],
        $lines,
        array_keys($lines)
    );
}

/**
 * @param FlowLine                                                                        $line
 * @param array{size?: float|int, anchor?: 'middle'|'start', color?: string, halo?: bool} $options
 */
function text(array|string $line, float|int $x, float|int $y, array $options = []): string
{
    $size = $options['size'] ?? 12;
    $anchor = $options['anchor'] ?? 'start';
    $color = $options['color'] ?? C['text'];
    $halo = $options['halo'] ?? false;

    $haloAttributes = $halo ? ' paint-order="stroke" stroke="'.C['bg'].'" stroke-width="5" stroke-linejoin="round"' : '';

    $spans = '';

    foreach (toSegments($line) as $s) {
        $attributes = ['font-family="'.(($s['mono'] ?? false) ? MONO : SANS).'"'];

        if ($s['bold'] ?? false) {
            $attributes[] = 'font-weight="bold"';
        }

        if (isset($s['color'])) {
            $attributes[] = 'fill="'.$s['color'].'"';
        }

        $tspan = \sprintf(
            '<tspan %s%s>%s</tspan>',
            implode(' ', $attributes),
            isset($s['href']) ? ' text-decoration="underline"' : '',
            esc($s['t'])
        );

        // links work when the svg is opened directly, not within an <img> (e.g. the readme on github)
        $spans .= isset($s['href']) ? '<a href="'.esc($s['href']).'" target="_blank">'.$tspan.'</a>' : $tspan;
    }

    return \sprintf(
        '<text x="%s" y="%s" font-family="%s" font-size="%s" fill="%s" text-anchor="%s"%s>%s</text>',
        num($x),
        num($y),
        SANS,
        num($size),
        $color,
        $anchor,
        $haloAttributes,
        $spans
    );
}

/**
 * @param array<string, FlowLaneStyle> $lanes
 *
 * @return FlowLaneStyle
 */
function lane(array $lanes, string $id): array
{
    if (!isset($lanes[$id])) {
        throw new \RuntimeException(
            \sprintf('Unknown lane "%s", known lanes are %s', $id, implode(', ', array_keys($lanes)))
        );
    }

    return $lanes[$id];
}

/**
 * a paragraph of muted text wrapped to the page width.
 *
 * @param FlowLine $line
 *
 * @return FlowFragment
 */
function paragraph(int $W, array|string $line, float|int $y, float $size): array
{
    $lines = wrap($line, $W - 80, $size);

    return [
        'height' => \count($lines) * ($size + 4),
        'elements' => array_map(
            static fn (array $tokens, int $i): string => text(mutedLine($tokens), 40, $y + $i * ($size + 4), ['size' => $size]),
            $lines,
            array_keys($lines)
        ),
    ];
}

/**
 * the box is at least as high as its content, all boxes of a row share the height of the tallest one.
 *
 * @param array<string, FlowLaneStyle> $lanes
 * @param FlowParticipant              $participant
 *
 * @return FlowFragment
 */
function participant(array $lanes, int $participantWidth, float|int $y, array $participant, float|int $minHeight = 0): array
{
    ['id' => $id, 'title' => $title, 'subtitle' => $subtitle, 'bullets' => $bullets] = $participant;
    ['x' => $x, 'stroke' => $stroke, 'fill' => $fill, 'text' => $color] = lane($lanes, $id);
    $subtitles = wrap($subtitle, $participantWidth - 20, 11.5);
    $bulletsY = $y + 42 + \count($subtitles) * 15 + 9;

    $lines = [];

    foreach ($bullets as $line) {
        foreach (wrap($line, $participantWidth - 28 - 12, 12) as $i => $tokens) {
            $lines[] = [['t' => 0 === $i ? '• ' : '   '], ...$tokens];
        }
    }

    $height = max($minHeight, $bulletsY - $y + \count($lines) * 17 + 5);

    return [
        'height' => $height,
        'elements' => [
            \sprintf(
                '<rect x="%s" y="%s" width="%s" height="%s" rx="8" fill="%s" stroke="%s" stroke-width="1.5"/>',
                num($x - $participantWidth / 2),
                num($y),
                num($participantWidth),
                num($height),
                $fill,
                $stroke
            ),
            text([b($title)], $x, $y + 24, ['size' => 16, 'anchor' => 'middle', 'color' => $color]),
            ...array_map(
                static fn (array $line, int $i): string => text($line, $x, $y + 42 + $i * 15, ['size' => 11.5, 'anchor' => 'middle', 'color' => C['muted']]),
                $subtitles,
                array_keys($subtitles)
            ),
            ...array_map(
                static fn (array $line, int $i): string => text($line, $x - $participantWidth / 2 + 14, $bulletsY + $i * 17),
                $lines,
                array_keys($lines)
            ),
        ],
    ];
}

/**
 * @param FlowState $state
 * @param FlowLine  $subtitle
 *
 * @return FlowState
 */
function band(int $W, array $state, string $title, array|string $subtitle): array
{
    $y = $state['y'] + 12;
    $lines = wrap([b($title), muted('   '), ...mutedLine($subtitle)], $W - 112, 13.5);
    $height = 14 + \count($lines) * 18;

    $state['y'] = $y + $height + 18;
    $state['elements'][] = \sprintf(
        '<rect x="40" y="%s" width="%s" height="%s" rx="6" fill="%s" stroke="%s"/>',
        num($y),
        num($W - 80),
        num($height),
        C['band'],
        C['line']
    );

    foreach ($lines as $i => $line) {
        $state['elements'][] = text($line, 56, $y + 23 + $i * 18, ['size' => 13.5]);
    }

    return $state;
}

/**
 * @param array<string, FlowLaneStyle> $lanes
 * @param FlowState                    $state
 * @param list<FlowLine>               $lines
 *
 * @return FlowState
 */
function note(array $lanes, int $noteWidth, array $state, string $id, array $lines, bool $error): array
{
    ['x' => $x, 'stroke' => $stroke, 'fill' => $fill] = lane($lanes, $id);

    $wrapped = [];

    foreach ($lines as $line) {
        array_push($wrapped, ...indent(wrap($line, $noteWidth - 24 - 10, 12), '  '));
    }

    $height = \count($wrapped) * 16 + 16;
    $y = $state['y'] + 6;

    $state['y'] = $y + $height + 10;
    $state['elements'][] = \sprintf(
        '<rect x="%s" y="%s" width="%s" height="%s" rx="5" fill="%s" stroke="%s" stroke-width="1"/>',
        num($x - $noteWidth / 2),
        num($y),
        num($noteWidth),
        num($height),
        $error ? C['redBg'] : $fill,
        $error ? C['red'] : $stroke
    );

    foreach ($wrapped as $i => $line) {
        $state['elements'][] = text($line, $x - $noteWidth / 2 + 12, $y + 20 + $i * 16);
    }

    return $state;
}

/**
 * @param array<string, FlowLaneStyle> $lanes
 * @param FlowState                    $state
 * @param list<FlowLine>               $lines
 *
 * @return FlowState
 */
function arrow(array $lanes, array $state, string $from, string $to, array $lines, bool $response): array
{
    $x1 = lane($lanes, $from)['x'];
    $x2 = lane($lanes, $to)['x'];
    $mid = ($x1 + $x2) / 2;

    // labels may reach a little beyond the two lanes, the halo keeps them readable across a lifeline
    $wrapped = [];

    foreach ($lines as $line) {
        array_push($wrapped, ...wrap($line, abs($x2 - $x1) + 100, 12));
    }

    $y = $state['y'] + \count($wrapped) * 15 + 14;
    $direction = $x2 > $x1 ? 1 : -1;
    $step = $state['step'] + 1;

    $state['y'] = $y + 16;
    $state['step'] = $step;

    foreach ($wrapped as $i => $line) {
        $state['elements'][] = text(
            $line,
            $mid,
            $y - 16 - (\count($wrapped) - 1 - $i) * 15,
            ['anchor' => 'middle', 'halo' => true]
        );
    }

    $state['elements'][] = \sprintf(
        '<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="1.5"%s marker-end="url(#arrow)"/>',
        num($x1 + $direction * 12),
        num($y),
        num($x2 - $direction * 8),
        num($y),
        C['arrow'],
        $response ? ' stroke-dasharray="6 4"' : ''
    );
    $state['elements'][] = \sprintf(
        '<circle cx="%s" cy="%s" r="11" fill="%s" stroke="%s" stroke-width="1.5"/>',
        num($x1),
        num($y),
        C['bg'],
        C['arrow']
    );
    $state['elements'][] = text([b((string) $step)], $x1, $y + 4, ['size' => 11, 'anchor' => 'middle', 'color' => C['arrow']]);

    return $state;
}

/**
 * @param array<string, FlowLaneStyle> $lanes
 * @param FlowState                    $state
 * @param FlowItem                     $current
 *
 * @return FlowState
 */
function item(array $lanes, int $W, int $noteWidth, array $state, array $current): array
{
    return match ($current['kind']) {
        'band' => band($W, $state, $current['title'], $current['subtitle']),
        'note' => note($lanes, $noteWidth, $state, $current['lane'], $current['lines'], $current['error'] ?? false),
        'arrow' => arrow($lanes, $state, $current['from'], $current['to'], $current['lines'], $current['response'] ?? false),
    };
}

/**
 * @param FlowDiagram $diagram
 */
function render(array $diagram): string
{
    ['laneGap' => $laneGap, 'participantWidth' => $participantWidth, 'noteWidth' => $noteWidth]
        = ($diagram['layout'] ?? []) + DEFAULT_LAYOUT;

    $W = 2 * MARGIN + (\count($diagram['participants']) - 1) * $laneGap + $participantWidth;

    /** @var array<string, FlowLaneStyle> $lanes */
    $lanes = [];

    foreach ($diagram['participants'] as $i => ['id' => $id, 'color' => $color]) {
        $lanes[$id] = ['x' => MARGIN + $participantWidth / 2 + $i * $laneGap] + PALETTE[$color];
    }

    $TITLE_Y = 44;
    $intro = paragraph($W, $diagram['intro'], $TITLE_Y + 24, 13);
    $participantsY = $TITLE_Y + 24 + $intro['height'] + 16;

    $participantsHeight = 0;

    foreach ($diagram['participants'] as $current) {
        $participantsHeight = max($participantsHeight, participant($lanes, $participantWidth, $participantsY, $current)['height']);
    }

    $participants = array_map(
        static fn (array $current): array => participant($lanes, $participantWidth, $participantsY, $current, $participantsHeight),
        $diagram['participants']
    );
    $lifelineStart = $participantsY + $participantsHeight + 24;

    $sequence = ['y' => $lifelineStart, 'step' => 0, 'elements' => []];

    foreach ($diagram['items'] as $current) {
        $sequence = item($lanes, $W, $noteWidth, $sequence, $current);
    }

    $legendY = $sequence['y'] + 12 + 24;
    $specs = paragraph($W, $diagram['specs'], $legendY + 22, 11.5);
    $H = $legendY + 22 + $specs['height'] + 8;

    $lifelines = array_map(
        static fn (array $lane): string => \sprintf(
            '<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="1.5" stroke-dasharray="4 6" opacity="0.6"/>',
            num($lane['x']),
            num($lifelineStart),
            num($lane['x']),
            num($legendY - 24),
            $lane['stroke']
        ),
        array_values($lanes)
    );

    $legend = [
        \sprintf('<line x1="40" y1="%s" x2="%s" y2="%s" stroke="%s"/>', num($sequence['y'] + 12), num($W - 40), num($sequence['y'] + 12), C['line']),
        \sprintf('<line x1="40" y1="%s" x2="80" y2="%s" stroke="%s" stroke-width="1.5" marker-end="url(#arrow)"/>', num($legendY - 4), num($legendY - 4), C['arrow']),
        text('request', 88, $legendY),
        \sprintf('<line x1="150" y1="%s" x2="190" y2="%s" stroke="%s" stroke-width="1.5" stroke-dasharray="6 4" marker-end="url(#arrow)"/>', num($legendY - 4), num($legendY - 4), C['arrow']),
        text('response', 198, $legendY),
        \sprintf('<rect x="270" y="%s" width="18" height="12" rx="2" fill="%s" stroke="%s"/>', num($legendY - 13), C['redBg'], C['red']),
        text('rejected request / error', 296, $legendY),
        text([m('mono'), ' spec parameter, claim, header or code of this library'], 460, $legendY),
        ...$specs['elements'],
    ];

    $elements = [
        ...$lifelines,
        text([b($diagram['title'])], 40, $TITLE_Y, ['size' => 22]),
        ...$intro['elements'],
        ...array_merge(...array_column($participants, 'elements')),
        ...$sequence['elements'],
        ...$legend,
    ];

    return \sprintf(
        <<<'SVG'
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %1$s %2$s" width="%1$s" height="%2$s" role="img" aria-label="%3$s">
            <title>%4$s</title>
            <defs>
            <style>
            %5$s
            </style>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="%6$s"/></marker>
            </defs>
            <rect width="%1$s" height="%2$s" fill="%7$s"/>
            %8$s
            </svg>

            SVG,
        num($W),
        num($H),
        esc($diagram['label']),
        esc($diagram['title']),
        fontFaces(),
        C['arrow'],
        C['bg'],
        implode("\n", $elements)
    );
}
