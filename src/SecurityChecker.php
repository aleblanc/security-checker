<?php

namespace SensioLabs\Security;

use SensioLabs\Security\Exception\RuntimeException;

class SecurityChecker
{
    const VERSION = '6.0';

    private $crawler;

    public function __construct(Crawler $crawler = null)
    {
        $this->crawler = null === $crawler ? new Crawler() : $crawler;
    }

    public function check(string $lock, string $format = 'json'): array
    {
        if (0 !== strpos($lock, 'data://text/plain;base64,')) {
            if (is_dir($lock) && file_exists($lock.'/composer.lock')) {
                $lock = $lock.'/composer.lock';
            } elseif (preg_match('/composer\.json$/', $lock)) {
                $lock = str_replace('composer.json', 'composer.lock', $lock);
            }

            if (!is_file($lock)) {
                throw new RuntimeException('Lock file does not exist.');
            }
        }

        return $this->crawler->check($lock, $format);
    }

    /**
     * @internal
     *
     * @return Crawler
     */
    public function getCrawler()
    {
        return $this->crawler;
    }
}
