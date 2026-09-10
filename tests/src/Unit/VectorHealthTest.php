<?php

namespace Drupal\Tests\s360_vector_health\Unit;

use Drupal\Tests\UnitTestCase;
use Drupal\s360_vector_health\VectorHealth;

/**
 * Tests the vector store diagnostics helpers.
 *
 * @coversDefaultClass \Drupal\s360_vector_health\VectorHealth
 *
 * @group s360_vector_health
 */
class VectorHealthTest extends UnitTestCase {

  /**
   * Tests that the firewall command is filled from the default template.
   *
   * @covers ::buildFirewallCommand
   */
  public function testBuildAzCommand(): void {
    $this->assertSame(
      'az postgres flexible-server firewall-rule create -g <resource-group> -s <server-name> -n pantheon-34-44-63-255 --start-ip-address 34.44.63.255 --end-ip-address 34.44.63.255',
      VectorHealth::buildFirewallCommand('34.44.63.255', VectorHealth::DEFAULT_FIREWALL_TEMPLATE),
    );
  }

  /**
   * Tests that the rule name uses -n and not -r.
   *
   * Regression guard: -r was rejected outright by az 2.89.0 as an
   * unrecognized argument, so the command the page offered could not be
   * pasted and run — the one job it has.
   *
   * @covers ::buildFirewallCommand
   */
  public function testAzCommandUsesCorrectRuleNameFlag(): void {
    $command = VectorHealth::buildFirewallCommand('34.44.63.255', VectorHealth::DEFAULT_FIREWALL_TEMPLATE);

    $this->assertStringContainsString('-n pantheon-34-44-63-255', $command);
    $this->assertStringNotContainsString('-r ', $command);
    $this->assertStringContainsString('-s <server-name>', $command);
  }

  /**
   * Tests that the default template keeps its visible placeholders.
   *
   * @covers ::buildFirewallCommand
   */
  public function testBuildAzCommandWithoutConfiguration(): void {
    $command = VectorHealth::buildFirewallCommand('34.44.63.255', VectorHealth::DEFAULT_FIREWALL_TEMPLATE);

    $this->assertStringContainsString('-g <resource-group>', $command);
    $this->assertStringContainsString('-s <server-name>', $command);
  }

  /**
   * Tests that a prefix produces a rule spanning the whole prefix.
   *
   * @covers ::buildFirewallCommand
   */
  public function testBuildAzCommandWithPrefix(): void {
    $this->assertSame(
      'az postgres flexible-server firewall-rule create -g <resource-group> -s <server-name> -n pantheon-35-253-0-0-16 --start-ip-address 35.253.0.0 --end-ip-address 35.253.255.255',
      VectorHealth::buildFirewallCommand('35.253.12.190', VectorHealth::DEFAULT_FIREWALL_TEMPLATE, '35.253.0.0/16'),
    );
  }

  /**
   * Tests CIDR expansion, including the /15 that was once entered as a /16.
   *
   * Regression guard: 34.44.0.0/15 ends at 34.45.255.255, not 34.44.255.255.
   * The hand-entered rule stopped one address short of half the prefix and
   * would have surfaced as intermittent, unreproducible timeouts.
   *
   * @covers ::cidrRange
   * @dataProvider cidrRangeProvider
   */
  public function testCidrRange(string $cidr, string $first, string $last): void {
    $this->assertSame([$first, $last], VectorHealth::cidrRange($cidr));
  }

  /**
   * Data provider for testCidrRange().
   */
  public static function cidrRangeProvider(): array {
    return [
      'slash 15' => ['34.44.0.0/15', '34.44.0.0', '34.45.255.255'],
      'slash 16' => ['35.253.0.0/16', '35.253.0.0', '35.253.255.255'],
      'slash 17' => ['104.154.128.0/17', '104.154.128.0', '104.154.255.255'],
      'slash 24' => ['34.71.177.0/24', '34.71.177.0', '34.71.177.255'],
      'slash 32' => ['34.44.63.255/32', '34.44.63.255', '34.44.63.255'],
      'unaligned network is normalised' => ['34.44.63.255/15', '34.44.0.0', '34.45.255.255'],
    ];
  }

  /**
   * Tests that malformed prefixes are rejected rather than guessed at.
   *
   * @covers ::cidrRange
   * @dataProvider badCidrProvider
   */
  public function testCidrRangeRejectsBadInput(string $cidr): void {
    $this->expectException(\InvalidArgumentException::class);
    VectorHealth::cidrRange($cidr);
  }

  /**
   * Data provider for testCidrRangeRejectsBadInput().
   */
  public static function badCidrProvider(): array {
    return [
      'no slash' => ['34.44.0.0'],
      'too long' => ['34.44.0.0/33'],
      'not an address' => ['pantheon/16'],
      'ipv6' => ['2600:1900::/28'],
    ];
  }

  /**
   * Tests the prefix lookup against a list shaped like cloud.json.
   *
   * @covers ::findPrefix
   */
  public function testFindPrefix(): void {
    $prefixes = [
      ['ipv6Prefix' => '2600:1900:4000::/44', 'scope' => 'us-central1'],
      ['ipv4Prefix' => '34.44.0.0/15', 'scope' => 'us-central1'],
      ['ipv4Prefix' => '35.253.0.0/16', 'scope' => 'us-central1'],
      ['ipv4Prefix' => '104.154.128.0/17', 'scope' => 'us-central1'],
      ['ipv4Prefix' => '35.184.0.0/13', 'scope' => 'us-central1'],
    ];

    $this->assertSame('35.253.0.0/16', VectorHealth::findPrefix('35.253.12.190', $prefixes)['ipv4Prefix']);
    $this->assertSame('34.44.0.0/15', VectorHealth::findPrefix('34.45.0.1', $prefixes)['ipv4Prefix']);
    $this->assertSame('104.154.128.0/17', VectorHealth::findPrefix('104.154.219.186', $prefixes)['ipv4Prefix']);
    $this->assertSame('us-central1', VectorHealth::findPrefix('104.154.219.186', $prefixes)['scope']);
    $this->assertNull(VectorHealth::findPrefix('104.154.1.1', $prefixes), 'An address below the /17 boundary is outside the prefix.');
    $this->assertNull(VectorHealth::findPrefix('8.8.8.8', $prefixes));
    $this->assertNull(VectorHealth::findPrefix('not-an-ip', $prefixes));
  }

  /**
   * Tests that overlapping prefixes resolve to the most specific one.
   *
   * @covers ::findPrefix
   */
  public function testFindPrefixPrefersLongestMatch(): void {
    $prefixes = [
      ['ipv4Prefix' => '34.0.0.0/8', 'scope' => 'global'],
      ['ipv4Prefix' => '34.44.0.0/15', 'scope' => 'us-central1'],
      ['ipv4Prefix' => '34.44.63.0/24', 'scope' => 'us-central1-zone'],
    ];

    $this->assertSame('34.44.63.0/24', VectorHealth::findPrefix('34.44.63.255', $prefixes)['ipv4Prefix']);
    $this->assertSame('34.44.0.0/15', VectorHealth::findPrefix('34.45.1.1', $prefixes)['ipv4Prefix']);
    $this->assertSame('34.0.0.0/8', VectorHealth::findPrefix('34.100.1.1', $prefixes)['ipv4Prefix']);
  }

}
