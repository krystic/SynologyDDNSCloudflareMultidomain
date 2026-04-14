#!/usr/bin/php -d open_basedir=/usr/syno/bin/ddns
<?php
/**
 * Cloudflare DDNS agent for Synology DSM
 * @link https://github.com/mrikirill/SynologyDDNSCloudflareMultidomain
 * @version 2.0
 * @license MIT
 * @author https://github.com/mrikirill
 */

/**
 * Synology passes 5 arguments in order:
 * 0 - not in use
 * 1 - username - uses for domains: domain1.com|vpn.domain2.com
 * 2 - password - Cloudflare API token
 * 3 - hostname - the script doesn't use it die to input limits
 * 4 - IPv4     - Synology provided IPv4
 */
if (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME'])) {
    if ($argc !== 5) {
        echo SynologyOutput::BAD_PARAMS;
        exit();
    }

    $cf = new SynologyCloudflareDDNSAgent($argv[2], $argv[1], $argv[4]);
    $cf->setDnsRecords();
    $cf->updateDnsRecords();
}

class SynologyOutput
{
    const SUCCESS = 'good';               // Update successfully
    const NO_HOSTNAME = 'nohost';         // The hostname specified does not exist in this user account
    const HOSTNAME_INCORRECT = 'notfqdn'; // The hostname specified is not a fully-qualified domain name
    const AUTH_FAILED = 'badauth';        // Authenticate failed
    const DDNS_FAILED = '911';            // There is a problem or scheduled maintenance on provider side
    const BAD_HTTP_REQUEST = 'badagent';  // HTTP method/parameters is not permitted
    const BAD_PARAMS = 'badparam';        // Bad params
}

/**
 * Cloudflare api client
 * @link https://developers.cloudflare.com/api/
 */
class CloudflareAPI
{
    const API_URL = 'https://api.cloudflare.com';
    const ZONES_PER_PAGE = 50;
    private $apiKey;

    public function __construct($apiKey)
    {
        $this->apiKey = $apiKey;
    }

    /**
     * Makes an API call to the specified Cloudflare endpoint.
     *
     * @param string $method The HTTP method to use (GET, POST, PUT, PATCH).
     * @param string $path The API endpoint path to call.
     * @param array $data Optional data to send with the request.
     * @return array The JSON-decoded response from the API call.
     * @throws Exception If an error occurs during the API call.
     */
    private function call($method, $path, $data = [])
    {
        $options = [
            CURLOPT_URL => self::API_URL . '/' . $path,
            CURLOPT_HTTPHEADER => ["Authorization: Bearer $this->apiKey", "Content-Type: application/json"],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_VERBOSE => false,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
        ];

        switch ($method) {
            case "GET":
                $options[CURLOPT_HTTPGET] = true;
                break;
            case "POST":
                $options[CURLOPT_POST] = true;
                $options[CURLOPT_POSTFIELDS] = json_encode($data);
                break;
            case "PUT":
                $options[CURLOPT_CUSTOMREQUEST] = "PUT";
                $options[CURLOPT_POSTFIELDS] = json_encode($data);
                break;
            case "PATCH":
                $options[CURLOPT_CUSTOMREQUEST] = "PATCH";
                $options[CURLOPT_POSTFIELDS] = json_encode($data);
                break;
            default:
                throw new Exception("Invalid HTTP method: $method");
        }

        $req = curl_init();
        curl_setopt_array($req, $options);
        $res = curl_exec($req);

        if (curl_errno($req)) {
            throw new Exception('Curl error: ' . curl_error($req));
        }

        curl_close($req);
        $json = json_decode($res, true);

        if (!$json['success']) {
            throw new Exception('API call failed');
        }

        return $json;
    }

    /**
     * @link https://developers.cloudflare.com/api/operations/user-api-tokens-verify-token
     * @throws Exception
     */
    public function verifyToken()
    {
        return $this->call("GET", "client/v4/user/tokens/verify");
    }

    /**
     * Note: getting max 50 zones see the documentation
     * @link https://developers.cloudflare.com/api/operations/zones-get
     * @throws Exception
     */
    public function getZones()
    {
        return $this->call("GET", "client/v4/zones?per_page=" . self::ZONES_PER_PAGE . "&status=active");
    }

    public function getZoneByName($zoneName)
{
    return $this->call(
        "GET",
        "client/v4/zones?name=" . rawurlencode($zoneName) . "&status=active"
    );
}

    /**
     * @link https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records
     * @throws Exception
     */
    public function getDnsRecords($zoneId, $type, $name)
    {
        return $this->call("GET", "client/v4/zones/$zoneId/dns_records?type=$type&name=$name");
    }

    /**
     * @link https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-patch-dns-record
     * @throws Exception
     */
    public function updateDnsRecord($zoneId, $recordId, $body)
    {
        return $this->call("PATCH", "client/v4/zones/$zoneId/dns_records/$recordId", $body);
    }
}

class IPv6Resolver
{
    const API_URL = 'https://api6.ipify.org/?format=json';
    const API_URL_CN = 'https://v6.ip.zxinc.org/info.php?type=json';
    const FIELD_DEFAULT = 'ip';
    const FIELD_CN = 'myip';

    /**
     * Get external IPv6 address from specified or default API
     * @param string|null $customUrl Custom API URL (null = use default ipify)
     * @param string|null $fieldName JSON field name for IP (null = auto-detect)
     * @throws Exception
     */
    public function tryGetIpv6($customUrl = null, $fieldName = null)
    {
        $url = $customUrl ?: self::API_URL;
        
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => [
                "Content-Type: application/json",
                "User-Agent: curl/7.79.1"
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_VERBOSE => false,
            CURLOPT_HTTPGET => true,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
        ];

        $req = curl_init();
        curl_setopt_array($req, $options);
        $res = curl_exec($req);

        if (curl_errno($req)) {
            $error = curl_error($req);
            curl_close($req);
            throw new Exception("IPv6 API connection failed ($url): $error");
        }

        curl_close($req);
        $json = json_decode($res, true);

        if ($json === null) {
            throw new Exception("IPv6 API returned invalid JSON ($url): $res");
        }

        // Determine field name
        if ($fieldName) {
            $ip = $json[$fieldName] ?? null;
        } else {
            // Auto-detect: try 'ip' first, then 'myip'
            $ip = $json['ip'] ?? $json['myip'] ?? null;
        }

        if (!$ip) {
            throw new Exception("IPv6 API response missing IP field ($url): " . json_encode($json));
        }

        return $ip;
    }
}

class DnsRecordEntity
{
    public $id;
    public $type;
    public $hostname;
    public $ip;
    public $zoneId;
    public $ttl;
    public $proxied;
    public $currentIp;

    public function __construct($id, $type, $hostname, $ip, $zoneId, $ttl, $proxied)
    {
        $this->id = $id;
        $this->type = $type;
        $this->hostname = $hostname;
        $this->ip = $ip;
        $this->zoneId = $zoneId;
        $this->ttl = $ttl;
        $this->proxied = $proxied;
    }

    public function toArray()
    {
        return [
            'id' => $this->id,
            'type' => $this->type,
            'name' => $this->hostname,
            'content' => $this->ip,
            'zoneId' => $this->zoneId,
            'ttl' => $this->ttl,
            'proxied' => $this->proxied
        ];
    }
}

/**
 * DDNS auto update agent for Synology DSM
 * Supports multidomains and subdomains
 * 
 * Hostname format: domain1.com|domain2.com,v4|domain3.com,v6|cn
 * Options:
 *   (none) - Update both A (IPv4) and AAAA (IPv6)
 *   ,v4    - Update A record only (IPv4)
 *   ,v6    - Update AAAA record only (IPv6)
 *   |cn    - (at end) Use China API for IPv6 detection
 *   |https://custom.api/path,fieldname - (at end) Use custom API, fieldname is the JSON key for IPv6
 */
class SynologyCloudflareDDNSAgent
{
    private $ipv4, $ipv6, $ipv6Error, $dnsRecordList = [];
    private $cloudflareAPI;
    private $ipv6Resolver;

    function __construct($apiKey, $hostname, $ipv4, $cloudflareAPI = null, $ipv6Resolver = null)
    {
        $this->cloudflareAPI = $cloudflareAPI ?: new CloudflareAPI($apiKey);
        $this->ipv6Resolver = $ipv6Resolver ?: new IPv6Resolver();
        $this->ipv4 = $ipv4;

        // Parse IPv6 configuration from hostname
        $ipv6Config = $this->parseIPv6Config($hostname);

        // Get IPv6 address based on configuration
        try {
            $this->ipv6 = $this->ipv6Resolver->tryGetIpv6($ipv6Config['url'], $ipv6Config['field']);
        } catch (Exception $e) {
            $this->ipv6Error = $e->getMessage();
            // IPv6 not available, will be handled later if needed
        }

        try {
            if (!$this->isCFTokenValid()) {
                $this->exitWithSynologyMsg(SynologyOutput::AUTH_FAILED);
            }
        } catch (Exception $e) {
            $this->exitWithSynologyMsg();
        }

        $hostnameList = $this->extractHostnames($hostname);
        if (empty($hostnameList)) {
            $this->exitWithSynologyMsg(SynologyOutput::HOSTNAME_INCORRECT);
        }

        $this->matchHostnameWithZone($hostnameList);
    }

    /**
     * Parse IPv6 API configuration from hostname string
     * 
     * Formats:
     *   domain.com           -> use default API (ipify)
     *   domain.com|cn        -> use China API
     *   domain.com|https://api.example.com/ip,fieldname -> use custom API
     * 
     * @param string $hostname
     * @return array ['url' => string|null, 'field' => string|null]
     */
    private function parseIPv6Config($hostname)
    {
        $parts = preg_split('/\|/', $hostname, -1, PREG_SPLIT_NO_EMPTY);
        
        if (empty($parts)) {
            return ['url' => null, 'field' => null]; // Default API
        }
        
        $lastPart = trim(end($parts));
        $lastPartLower = strtolower($lastPart);
        
        // Check for 'cn' keyword
        if ($lastPartLower === 'cn') {
            return [
                'url' => IPv6Resolver::API_URL_CN,
                'field' => IPv6Resolver::FIELD_CN
            ];
        }
        
        // Check for custom URL format: https://...,fieldname
        if (preg_match('/^(https?:\/\/.+),([a-zA-Z_][a-zA-Z0-9_]*)$/', $lastPart, $matches)) {
            return [
                'url' => $matches[1],
                'field' => $matches[2]
            ];
        }
        
        // Default API
        return ['url' => null, 'field' => null];
    }

    /**
     * Sets DNS A Records for each host in the DNS record list.
     *
     * Iterates over the dnsRecordList, retrieves existing DNS records
     * from the Cloudflare API, and updates the records' IDs, TTL, and proxied status.
     *
     * If the dnsRecordList is empty, it exits with a NO_HOSTNAME message.
     * If an API call fails, it exits with a DDNS_FAILED message.
     */
    public function setDnsRecords()
    {
        if (empty($this->dnsRecordList)) {
            $this->exitWithSynologyMsg(SynologyOutput::NO_HOSTNAME);
        }

        try {
            foreach ($this->dnsRecordList as $key => $dnsRecord) {
                $json = $this->cloudflareAPI->getDnsRecords($dnsRecord->zoneId, $dnsRecord->type, $dnsRecord->hostname);
                if (isset($json['result']['0'])) {
                    // If the DNS record exists, update its ID, TTL, proxied status, and current IP
                    $this->dnsRecordList[$key]->id = $json['result']['0']['id'];
                    $this->dnsRecordList[$key]->ttl = $json['result']['0']['ttl'];
                    $this->dnsRecordList[$key]->proxied = $json['result']['0']['proxied'];
                    $this->dnsRecordList[$key]->currentIp = $json['result']['0']['content'];
                } else {
                    // If the DNS record does not exist, remove it from the list
                    unset($this->dnsRecordList[$key]);
                }
            }
        } catch (Exception $e) {
            $this->exitWithSynologyMsg(SynologyOutput::DDNS_FAILED);
        }
    }

    /**
     * Updates Cloudflare DNS records
     *
     * Verifies each DNS record in the list, attempts to update it via the Cloudflare API,
     * and outputs 'SUCCESS' if all updates are completed without errors.
     * If the DNS record list is empty, it exits with a 'NO_HOSTNAME' message.
     * If an API call fails, it exits with a 'BAD_HTTP_REQUEST' message.
     */
    function updateDnsRecords()
    {
        if (empty($this->dnsRecordList)) {
            $this->exitWithSynologyMsg(SynologyOutput::NO_HOSTNAME);
        }
        foreach ($this->dnsRecordList as $dnsRecord) {
            // Skip update if the IP address hasn't changed
            if ($dnsRecord->ip === $dnsRecord->currentIp) {
                continue;
            }
            
            try {
               $this->cloudflareAPI->updateDnsRecord($dnsRecord->zoneId, $dnsRecord->id, $dnsRecord->toArray());
            } catch (Exception $e) {
                $this->exitWithSynologyMsg(SynologyOutput::BAD_HTTP_REQUEST);
            }
        }

        echo SynologyOutput::SUCCESS;
    }

    /**
     * Matches hostnames with their corresponding Cloudflare zone.
     *
     * This method fetches the list of zones from the Cloudflare API,
     * iterates over each hostname provided, and stores corresponding DNS records
     * in the dnsRecordList property if a match is found.
     *
     * @param array $hostnameList List of hostname entries with options.
     * @throws Exception If an error occurs during the API call,
     * it outputs an appropriate Synology message and exits the script.
     */
    private function matchHostnameWithZone($hostnameList = [])
    {
        try {
            foreach ($hostnameList as $entry) {
                $hostname = $entry['hostname'];
                $updateV4 = $entry['updateV4'];
                $updateV6 = $entry['updateV6'];

                $zoneId = $this->findZoneIdByHostname($hostname);

                if (!$zoneId) {
                    continue;
                }

                // Add A record (IPv4)
                if ($updateV4 && isset($this->ipv4)) {
                    $this->dnsRecordList[] = new DnsRecordEntity(
                        '',
                        'A',
                        $hostname,
                        $this->ipv4,
                        $zoneId,
                        '',
                        ''
                    );
                }

                // Add AAAA record (IPv6)
                if ($updateV6) {
                    if (isset($this->ipv6)) {
                        $this->dnsRecordList[] = new DnsRecordEntity(
                            '',
                            'AAAA',
                            $hostname,
                            $this->ipv6,
                            $zoneId,
                            '',
                            ''
                        );
                    } elseif ($this->ipv6Error) {
                        // IPv6 was requested but failed to obtain
                        $this->exitWithSynologyMsg(SynologyOutput::DDNS_FAILED . " - IPv6 Error: " . $this->ipv6Error);
                    }
                }
            }

            if (empty($this->dnsRecordList)) {
                $this->exitWithSynologyMsg(SynologyOutput::NO_HOSTNAME);
            }
        } catch (Exception $e) {
            $this->exitWithSynologyMsg(SynologyOutput::NO_HOSTNAME);
        }
    }

    /**
     * Summary of findZoneIdByHostname
     * @param mixed $hostname
     */
    private function findZoneIdByHostname($hostname)
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $labels = explode('.', $hostname);
        $count = count($labels);

        for ($i = 0; $i <= $count - 2; $i++) {
            $candidateZone = implode('.', array_slice($labels, $i));
            $zone = $this->cloudflareAPI->getZoneByName($candidateZone);

            if (!empty($zone['result']) && !empty($zone['result'][0]['id'])) {
                return $zone['result'][0]['id'];
            }
        }

        return null;
    }

    /**
     * Extracts valid hostnames and their options from a given string.
     *
     * Format: domain1.com|domain2.com,v4|domain3.com,v6|cn
     * Options:
     *   (none) - Update both A (IPv4) and AAAA (IPv6)
     *   ,v4    - Update A record only (IPv4)
     *   ,v6    - Update AAAA record only (IPv6)
     *   |cn    - (at end) Use China API for IPv6 (not included in hostList)
     *   |https://...,field - (at end) Custom IPv6 API (not included in hostList)
     *
     * @param string $hostnames A string of hostnames separated by pipes (|).
     * @return array An array of hostname entries with options.
     */
    private function extractHostnames($hostnames)
    {
        $arHost = preg_split('/\|/', $hostnames, -1, PREG_SPLIT_NO_EMPTY);
        $hostList = [];
        
        foreach ($arHost as $value) {
            $trimmedValue = trim($value);
            
            // Skip 'cn' flag or custom URL at the end
            if (strtolower($trimmedValue) === 'cn') {
                continue;
            }
            if (preg_match('/^https?:\/\/.+,.+$/', $trimmedValue)) {
                continue;
            }

            $parts = explode(',', $value, 2);
            $hostname = trim($parts[0]);
            $option = isset($parts[1]) ? strtolower(trim($parts[1])) : '';

            if (!$this->isValidHostname($hostname)) {
                continue;
            }

            // Parse options
            $updateV4 = true;
            $updateV6 = true;

            switch ($option) {
                case '':
                    // Default: v4 + v6
                    $updateV4 = true;
                    $updateV6 = true;
                    break;
                case 'v4':
                    // v4 only
                    $updateV4 = true;
                    $updateV6 = false;
                    break;
                case 'v6':
                    // v6 only
                    $updateV4 = false;
                    $updateV6 = true;
                    break;
                default:
                    // Unknown option, use default behavior
                    break;
            }

            $hostList[] = [
                'hostname' => $hostname,
                'updateV4' => $updateV4,
                'updateV6' => $updateV6
            ];
        }
        
        return $hostList;
    }

    /**
     * Validates whether a given value is a fully-qualified domain name (FQDN).
     *
     * Uses a regular expression pattern to check for valid FQDN structure.
     * An FQDN must consist of at least one label, each label must be alphanumeric or hyphenated,
     * but cannot begin or end with a hyphen, followed by a top-level domain (TLD) that is 2-6 characters long.
     *
     * @param string $value The input string to be validated as an FQDN.
     * @return bool Returns true if the input string is a valid FQDN, false otherwise.
     */
    private function isValidHostname($value)
    {
        $domainPattern = "/^(?!-)(?:\*\.)?(?:(?:[a-zA-Z\d][a-zA-Z\d\-]{0,61})?[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$/";
        return preg_match($domainPattern, $value) === 1;
    }

    /**
     * Checks CF API Token is valid
     *
     * This function verifies if the Cloudflare API token is valid by calling the verifyToken
     * method of the CloudflareAPI class. If the token is valid, it returns true.
     * If an exception occurs during the verification process, the function catches the exception
     * and returns false, indicating that the token is not valid or an error has occurred.
     *
     * @return bool Returns true if the Cloudflare API token is valid, otherwise false.
     */
    private function isCFTokenValid()
    {
        try {
            $res = $this->cloudflareAPI->verifyToken();
            return $res['success'];
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Outputs a message and exits the script.
     *
     * This function is used to print a specified message and then terminate
     * the execution of the script. It is primarily used for handling
     * and responding to various error conditions during the DNS update process.
     *
     * @param string $msg The message to be output before exiting.
     * If no message is specified, an empty string is printed.
     */
    protected function exitWithSynologyMsg($msg = '')
    {
        echo $msg;
        exit();
    }
}
?>
