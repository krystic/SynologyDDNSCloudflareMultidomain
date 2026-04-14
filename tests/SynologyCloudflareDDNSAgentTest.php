<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../cloudflare.php';

class ExitException extends Error {}

class TestableSynologyCloudflareDDNSAgent extends SynologyCloudflareDDNSAgent
{
    public $exitMsg = null;

    protected function exitWithSynologyMsg($msg = '')
    {
        $this->exitMsg = $msg;
        throw new ExitException("Exit called with message: $msg");
    }

    public function callPrivateMethod($methodName, $args = [])
    {
        $reflection = new ReflectionClass($this);
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);
        return $method->invokeArgs($this, $args);
    }
}

class SynologyCloudflareDDNSAgentTest extends TestCase
{
    public function testIsValidHostname()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => true]);

        $mockApi->method('getZoneByName')
            ->willReturnCallback(function ($zoneName) {
                if ($zoneName === 'example.com') {
                    return [
                        'result' => [
                            [
                                'id' => 'test-zone-id',
                                'name' => 'example.com',
                            ]
                        ]
                    ];
                }

                return ['result' => []];
            });

        $agent = new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com', '1.2.3.4', $mockApi, $mockIPv6Resolver);

        $this->assertTrue($agent->callPrivateMethod('isValidHostname', ['example.com']));
        $this->assertTrue($agent->callPrivateMethod('isValidHostname', ['sub.example.com']));
        $this->assertFalse($agent->callPrivateMethod('isValidHostname', ['-example.com']));
        $this->assertFalse($agent->callPrivateMethod('isValidHostname', ['example.com-']));
    }

    public function testExtractHostnames()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => true]);

        $mockApi->method('getZoneByName')
            ->willReturnCallback(function ($zoneName) {
                if ($zoneName === 'example.com') {
                    return [
                        'result' => [
                            [
                                'id' => 'test-zone-id',
                                'name' => 'example.com',
                            ]
                        ]
                    ];
                }

                return ['result' => []];
            });

        $agent = new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com', '1.2.3.4', $mockApi, $mockIPv6Resolver);

        // Test basic hostname extraction
        $input = "example.com|sub.example.com|invalid-";
        $result = $agent->callPrivateMethod('extractHostnames', [$input]);
        
        $this->assertCount(2, $result);
        $this->assertEquals('example.com', $result[0]['hostname']);
        $this->assertTrue($result[0]['updateV4']);
        $this->assertTrue($result[0]['updateV6']);
        $this->assertEquals('sub.example.com', $result[1]['hostname']);

        // Test with v4 option
        $input2 = "example.com,v4|sub.example.com,v6";
        $result2 = $agent->callPrivateMethod('extractHostnames', [$input2]);
        
        $this->assertTrue($result2[0]['updateV4']);
        $this->assertFalse($result2[0]['updateV6']);
        $this->assertFalse($result2[1]['updateV4']);
        $this->assertTrue($result2[1]['updateV6']);

        // Test with cn flag (should be excluded)
        $input3 = "example.com|cn";
        $result3 = $agent->callPrivateMethod('extractHostnames', [$input3]);
        
        $this->assertCount(1, $result3);
        $this->assertEquals('example.com', $result3[0]['hostname']);
    }

    public function testParseIPv6Config()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => true]);
        $mockApi->method('getZoneByName')
            ->willReturnCallback(function ($zoneName) {
                if ($zoneName === 'example.com') {
                    return ['result' => [['id' => 'test-zone-id', 'name' => 'example.com']]];
                }
                return ['result' => []];
            });

        $agent = new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com', '1.2.3.4', $mockApi, $mockIPv6Resolver);

        // Test default (no flag)
        $result1 = $agent->callPrivateMethod('parseIPv6Config', ['example.com']);
        $this->assertNull($result1['url']);
        $this->assertNull($result1['field']);

        // Test cn flag
        $result2 = $agent->callPrivateMethod('parseIPv6Config', ['example.com|cn']);
        $this->assertEquals(IPv6Resolver::API_URL_CN, $result2['url']);
        $this->assertEquals(IPv6Resolver::FIELD_CN, $result2['field']);

        // Test custom URL
        $result3 = $agent->callPrivateMethod('parseIPv6Config', ['example.com|https://api.test.com/ip,myfield']);
        $this->assertEquals('https://api.test.com/ip', $result3['url']);
        $this->assertEquals('myfield', $result3['field']);
    }

    public function testConstructorAuthFailure()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => false]);

        $this->expectException(ExitException::class);
        $this->expectExceptionMessage("Exit called with message: " . SynologyOutput::AUTH_FAILED);

        new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com', '1.2.3.4', $mockApi, $mockIPv6Resolver);
    }

    public function testParseIPv6ConfigWithHttpUrl()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => true]);
        $mockApi->method('getZoneByName')
            ->willReturnCallback(function ($zoneName) {
                if ($zoneName === 'example.com') {
                    return ['result' => [['id' => 'test-zone-id', 'name' => 'example.com']]];
                }
                return ['result' => []];
            });

        $agent = new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com', '1.2.3.4', $mockApi, $mockIPv6Resolver);

        // Test HTTP (not HTTPS) custom URL
        $result = $agent->callPrivateMethod('parseIPv6Config', ['example.com|http://api.test.com/ip,ipv6addr']);
        $this->assertEquals('http://api.test.com/ip', $result['url']);
        $this->assertEquals('ipv6addr', $result['field']);
    }

    public function testExtractHostnamesWithCustomUrl()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => true]);
        $mockApi->method('getZoneByName')
            ->willReturnCallback(function ($zoneName) {
                if ($zoneName === 'example.com') {
                    return ['result' => [['id' => 'test-zone-id', 'name' => 'example.com']]];
                }
                return ['result' => []];
            });

        $agent = new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com', '1.2.3.4', $mockApi, $mockIPv6Resolver);

        // Test custom URL is excluded from hostname list
        $input = "example.com,v4|https://api.test.com/ip,myfield";
        $result = $agent->callPrivateMethod('extractHostnames', [$input]);
        
        $this->assertCount(1, $result);
        $this->assertEquals('example.com', $result[0]['hostname']);
        $this->assertTrue($result[0]['updateV4']);
        $this->assertFalse($result[0]['updateV6']);

        // Test HTTP URL is also excluded
        $input2 = "example.com|http://api.test.com/ip,field";
        $result2 = $agent->callPrivateMethod('extractHostnames', [$input2]);
        
        $this->assertCount(1, $result2);
        $this->assertEquals('example.com', $result2[0]['hostname']);
    }

    public function testIPv6ResolverWithMockedResponse()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => true]);
        $mockApi->method('getZoneByName')
            ->willReturnCallback(function ($zoneName) {
                if ($zoneName === 'example.com') {
                    return ['result' => [['id' => 'test-zone-id', 'name' => 'example.com']]];
                }
                return ['result' => []];
            });

        // Mock IPv6 resolver to return a specific IPv6 address
        $mockIPv6Resolver->method('tryGetIpv6')
            ->willReturn('2001:db8::1');

        $agent = new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com', '1.2.3.4', $mockApi, $mockIPv6Resolver);

        // Verify the agent was created successfully with mocked IPv6
        $this->assertNull($agent->exitMsg);
    }

    public function testIPv6ErrorPropagationWithV6Only()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => true]);
        $mockApi->method('getZoneByName')
            ->willReturnCallback(function ($zoneName) {
                if ($zoneName === 'example.com') {
                    return ['result' => [['id' => 'test-zone-id', 'name' => 'example.com']]];
                }
                return ['result' => []];
            });

        // Mock IPv6 resolver to throw an exception
        $mockIPv6Resolver->method('tryGetIpv6')
            ->willThrowException(new Exception('IPv6 API connection failed'));

        $this->expectException(ExitException::class);
        $this->expectExceptionMessage("IPv6 Error: IPv6 API connection failed");

        // Request v6 only - should fail because IPv6 is not available
        new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com,v6', '1.2.3.4', $mockApi, $mockIPv6Resolver);
    }

    public function testIPv6ErrorNotPropagatedWithV4Only()
    {
        $mockApi = $this->createMock(CloudflareAPI::class);
        $mockIPv6Resolver = $this->createMock(IPv6Resolver::class);

        $mockApi->method('verifyToken')->willReturn(['success' => true]);
        $mockApi->method('getZoneByName')
            ->willReturnCallback(function ($zoneName) {
                if ($zoneName === 'example.com') {
                    return ['result' => [['id' => 'test-zone-id', 'name' => 'example.com']]];
                }
                return ['result' => []];
            });

        // Mock IPv6 resolver to throw an exception
        $mockIPv6Resolver->method('tryGetIpv6')
            ->willThrowException(new Exception('IPv6 API connection failed'));

        // Request v4 only - should NOT fail even though IPv6 is not available
        $agent = new TestableSynologyCloudflareDDNSAgent('apikey', 'example.com,v4', '1.2.3.4', $mockApi, $mockIPv6Resolver);
        
        // Should succeed without error
        $this->assertNull($agent->exitMsg);
    }

    public function testIPv6ResolverConstants()
    {
        // Test that IPv6Resolver constants are defined correctly
        $this->assertEquals('https://api6.ipify.org/?format=json', IPv6Resolver::API_URL);
        $this->assertEquals('https://v6.ip.zxinc.org/info.php?type=json', IPv6Resolver::API_URL_CN);
        $this->assertEquals('ip', IPv6Resolver::FIELD_DEFAULT);
        $this->assertEquals('data.myip', IPv6Resolver::FIELD_CN);
    }
}