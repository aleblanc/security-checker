<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security\Crawler;

use Composer\CaBundle\CaBundle;
use SensioLabs\Security\Exception\HttpException;
use SensioLabs\Security\Exception\RuntimeException;
use SensioLabs\Security\SecurityChecker;

/**
 * @internal
 */
class FileGetContentsCrawler extends BaseCrawler
{
    /**
     * {@inheritdoc}
     */
    protected function doCheck($lock)
    {
        $boundary = '------------------------'.md5(microtime(true));
        $headers = "Content-Type: multipart/form-data; boundary=$boundary\r\nAccept: application/json";
        if ($this->token) {
            $headers .= "\r\nAuthorization: Token {$this->token}";
        }
        $context = stream_context_create(array(
            'http' => array(
                'method' => 'POST',
                'header' => $headers,
                'content' => "--$boundary\r\nContent-Disposition: form-data; name=\"lock\"; filename=\"composer.lock\"\r\nContent-Type: application/octet-stream\r\n\r\n".$this->getLockContents($lock)."\r\n--$boundary--\r\n",
                'ignore_errors' => true,
                'follow_location' => true,
                'max_redirects' => 3,
                'timeout' => $this->timeout,
                'user_agent' => sprintf('SecurityChecker-CLI/%s FGC PHP', SecurityChecker::VERSION),
            ),
            'ssl' => array(
                'cafile' => CaBundle::getSystemCaRootBundlePath(),
                'verify_peer' => 1,
                'verify_host' => 2,
            ),
        ));

        $level = error_reporting(0);
        $body = file_get_contents($this->endPoint, 0, $context);
        error_reporting($level);
        if (false === $body) {
            $error = error_get_last();

            throw new RuntimeException(sprintf('An error occurred: %s.', $error['message']));
        }

        // status code
        if (!preg_match('{HTTP/\d\.\d (\d+) }i', $http_response_header[0], $match)) {
            throw new RuntimeException('An unknown error occurred.');
        }

        $statusCode = $match[1];
        if (400 == $statusCode) {
            $data = json_decode($body, true);

            throw new RuntimeException($data['error']);
        }

        if (200 != $statusCode) {
            throw new HttpException(sprintf('The web service failed for an unknown reason (HTTP %s).', $statusCode), $statusCode);
        }

        $headers = '';
        foreach ($http_response_header as $header) {
            if (false !== strpos($header, 'X-Alerts: ')) {
                $headers = $header;
            }
        }

        return array($headers, $body);
    }
}
