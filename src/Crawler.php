<?php

namespace SensioLabs\Security;

use Symfony\Component\Finder\Finder;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\Multipart\FormDataPart;
use Symfony\Component\Yaml\Parser;
use Symfony\Contracts\HttpClient\ResponseInterface;

class Crawler
{
    private $endPoint = 'https://codeload.github.com/github/advisory-database/zip/main';
    
    public function check($lock, $format = 'json'): array
    {
        return $this->doCheck($lock, $format);
    }
    
    private function doCheck($lock, $format = 'json'): array
    {
        $lockContent = ($this->getLockContents($lock));
        //@todo serializer
        $decodeJson = json_decode($lockContent);
        
        $path = dirname(__FILE__) . '/../../../../var/cache/security-cheker/';
        $this->extractTo($this->endPoint, $path);
        
        $path = dirname(__FILE__) . '/../../../../var/cache/security-cheker/advisory-database-main/advisories/github-reviewed/';
        $finder = new Finder();
        $tmp = $finder->files()->in($path)->name('*.json')->depth('> 1');
        
        foreach ($tmp as $t) {
            $decodeOneJson = json_decode(file_get_contents($t));
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
        foreach ($decodeJson->packages as $lockPackage) {
            $version = trim($lockPackage->version, 'v');
            if (isset($packages[$lockPackage->name])) {
                foreach ($packages[$lockPackage->name] as $vulnerability) {
                    
                    if (version_compare($version, $vulnerability["introduced"], '>=') && version_compare($version, $vulnerability["fixed"], '<')) {
                        $vulnerabilities[$lockPackage->name . ' (' . $version . ')'][] = ($vulnerability);
                    }
                    
                }
                
            }
        }
        return $vulnerabilities;
    }
    
    private function extractTo(string $fileUrl, string $target_dir): void
    {
        @mkdir($target_dir);
        $fileZip = $target_dir . 'file.zip';
        if (time() > (filemtime($fileZip) + (60 * 60 * 2))) {
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
    }
    
    private function getLockContents(string $lock): string
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
