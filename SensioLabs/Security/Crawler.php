<?php

namespace SensioLabs\Security;

use SensioLabs\Security\Exception\HttpException;
use SensioLabs\Security\Exception\RuntimeException;
use Symfony\Component\Finder\Finder;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\Multipart\FormDataPart;
use Symfony\Component\Yaml\Parser;
use Symfony\Contracts\HttpClient\ResponseInterface;

class Crawler
{
    private $endPoint = 'https://codeload.github.com/github/advisory-database/zip/main';
    private $timeout = 20;
    private $headers = [];
    
    
    /**
     * Adds a global header that will be sent with all requests to the server.
     */
    public function addHeader($key, $value)
    {
        $this->headers[] = $key . ': ' . $value;
    }
    
    /**
     * Checks a Composer lock file.
     *
     * @param string $lock The path to the composer.lock file or a string able to be opened via file_get_contents
     * @param string $format The format of the result
     * @param array $headers An array of headers to add for this specific HTTP request
     *
     * @return Result
     */
    public function check($lock, $format = 'json', array $headers = [])
    {
        return $this->doCheck($lock, $format, $headers);
    }
    
    /**
     * @return array An array where the first element is a headers string and second one the response body
     */
    private function doCheck($lock, $format = 'json', array $contextualHeaders = []): array
    {
        $client = HttpClient::create();
        $body = new FormDataPart([
            'lock' => new DataPart($this->getLockContents($lock), 'composer.lock'),
        ]);
        $headers = array_merge($this->headers, [
            'Accept' => $this->getContentType($format),
            'User-Agent' => sprintf('SecurityChecker-CLI/%s FGC PHP', SecurityChecker::VERSION),
        ], $body->getPreparedHeaders()->toArray());
        
        $lockContent = ($this->getLockContents($lock));
        //@todo serializer
        $decodeJson = \GuzzleHttp\json_decode($lockContent);
        
        $path = dirname(__FILE__) . '/../../../../../var/cache/security-cheker/';
        $this->extractTo($this->endPoint,$path);
        
        
        //parse json files
        
        $path = dirname(__FILE__) . '/../../../../../var/cache/security-cheker/advisory-database-main/advisories/github-reviewed/';
        $yaml = new Parser();
        $finder = new Finder();
        $parsedData = array();
        $tmp = $finder->files()->in($path)->name('*.json')->depth('> 1');
        
        $i = 0;
        foreach ($tmp as $t) {
            $decodeOneJson = \GuzzleHttp\json_decode(file_get_contents($t));
            foreach ($decodeOneJson->affected as $affected) {
                if ($affected->package->ecosystem == "Packagist") {
                    foreach ($affected->ranges as $range) {
                        if (isset($range->events[1]->fixed)) {
                            $packages[$affected->package->name][] = [
                                "introduced" => $range->events[0]->introduced,
                                "fixed" => $range->events[1]->fixed,
                                "data" => $decodeOneJson,
                            ];
                        } else {
                            $packages[$affected->package->name][] = [
                                "introduced" => $range->events[0]->introduced,
                                "last_known_affected_version_range" => $affected->database_specific->last_known_affected_version_range
                            ];
                        }
                    }
                }
            }
        }
        $vulnerabilities = [];
        foreach($decodeJson->packages as $lockPackage){
            $version =  trim($lockPackage->version,'v');
            if(isset($packages[$lockPackage->name])){
                foreach($packages[$lockPackage->name] as $vulnerability){
    
                    if (version_compare($version,$vulnerability["introduced"], '>=') && version_compare($version,$vulnerability["fixed"], '<')) {
                        $vulnerabilities[$lockPackage->name. ' ('.$version.')'][]=($vulnerability);
                    }
                
                }
                
            }
        }
        return $vulnerabilities;
    }
    
    private function extractTo($fileUrl, $target_dir)
    {
        // @todo add check date for refresh
        @mkdir($target_dir);
        $fileZip = $target_dir . 'file.zip';
        if(time() > ( filemtime($fileZip) + (60*60*2) ) ){
            file_put_contents($fileZip, file_get_contents($fileUrl));
            $zip = new \ZipArchive();
            if (file_exists($fileZip)) {
                if ($zip->open($fileZip)) {
                    $zip->extractTo($target_dir);
                    $zip->close();
                } else {
                    throw new \Exception("Failed to open '$fileZip'");
                }
            } else {
                throw new \Exception("File doesn't exist. '$fileZip'");
            }
        }
        
        return $this;
    }
    
    private function getContentType($format)
    {
        static $formats = [
            'text' => 'text/plain',
            'simple' => 'text/plain',
            'markdown' => 'text/markdown',
            'yaml' => 'text/yaml',
            'json' => 'application/json',
            'ansi' => 'text/plain+ansi',
        ];
        
        return isset($formats[$format]) ? $formats[$format] : 'text';
    }
    
    private function getLockContents($lock)
    {
        $contents = json_decode(file_get_contents($lock), true);
        $hash = isset($contents['content-hash']) ? $contents['content-hash'] : (isset($contents['hash']) ? $contents['hash'] : '');
        $packages = ['content-hash' => $hash, 'packages' => [], 'packages-dev' => []];
        foreach (['packages', 'packages-dev'] as $key) {
            if (!\is_array($contents[$key])) {
                continue;
            }
            foreach ($contents[$key] as $package) {
                $data = [
                    'name' => $package['name'],
                    'version' => $package['version'],
                ];
                if (isset($package['time']) && false !== strpos($package['version'], 'dev')) {
                    $data['time'] = $package['time'];
                }
                $packages[$key][] = $data;
            }
        }
        
        return json_encode($packages);
    }
}
