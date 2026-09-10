<?php

namespace Drupal\s360_vector_health;

use Drupal\ai\AiVdbProviderPluginManager;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Collects diagnostics about this environment's vector store connection.
 *
 * Provider-agnostic: talks to whichever Drupal AI vector DB provider is
 * configured, and reads the Search API indexes that use it.
 *
 * Answers three questions that are otherwise guesswork from inside a Pantheon
 * container: which index this environment is actually pointed at, whether the
 * Postgres connection is reachable and verified, and what egress address the
 * container presents to the store's firewall.
 */
final class VectorHealth {

  /**
   * Cache ID for the container's egress address.
   */
  protected const EGRESS_CACHE_ID = 's360_vector_health:egress_ip';

  /**
   * Cache ID for Google's published IPv4 prefix list.
   */
  protected const GCP_RANGES_CACHE_ID = 's360_vector_health:gcp_ranges';

  /**
   * Google's published list of Cloud IP ranges.
   */
  protected const GCP_RANGES_URL = 'https://www.gstatic.com/ipranges/cloud.json';

  /**
   * Name of the settings config object.
   */
  protected const CONFIG_NAME = 's360_vector_health.settings';

  /**
   * Default firewall command template.
   *
   * Shaped for Azure Database for PostgreSQL; sites on other stores replace
   * it in settings.
   */
  public const DEFAULT_FIREWALL_TEMPLATE = 'az postgres flexible-server firewall-rule create -g <resource-group> -s <server-name> -n {rule_name} --start-ip-address {start} --end-ip-address {end}';

  /**
   * Constructs the diagnostics service.
   *
   * @param \Drupal\ai\AiVdbProviderPluginManager $vdbProviderPluginManager
   *   The vector DB provider plugin manager.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   The HTTP client.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   *   The default cache bin.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $loggerFactory
   *   The logger channel factory.
   */
  public function __construct(
    protected AiVdbProviderPluginManager $vdbProviderPluginManager,
    protected EntityTypeManagerInterface $entityTypeManager,
    protected ConfigFactoryInterface $configFactory,
    protected ClientInterface $httpClient,
    protected CacheBackendInterface $cache,
    protected LoggerChannelFactoryInterface $loggerFactory,
  ) {}

  /**
   * Report on the Postgres connection this environment would make.
   *
   * Every failure mode is returned rather than thrown: a diagnostics page that
   * dies on the first problem cannot report the problem.
   *
   * @return array
   *   An associative array with keys:
   *   - settings: connection parameters, credentials excluded.
   *   - reachable: TRUE when a connection was established.
   *   - tls_version: negotiated TLS version, or NULL.
   *   - tls_cipher: negotiated cipher, or NULL.
   *   - verified: TRUE when the sslmode in force validates the server
   *     certificate and the connection succeeded anyway.
   *   - error: failure message, or NULL.
   */
  public function getConnectionDiagnostics(): array {
    $result = [
      'settings' => [],
      'reachable' => FALSE,
      'tls_version' => NULL,
      'tls_cipher' => NULL,
      'verified' => FALSE,
      'error' => NULL,
    ];

    try {
      $provider = $this->vdbProviderPluginManager->createInstance($this->providerId());
      $data = $provider->getConnectionData();
    }
    catch (\Throwable $e) {
      $result['error'] = $e->getMessage();
      return $result;
    }

    $cert = $data['sslrootcert'] ?? NULL;
    $result['settings'] = [
      'host' => $data['host'] ?? NULL,
      'port' => $data['port'] ?? NULL,
      'username' => $data['username'] ?? NULL,
      'default_database' => $data['default_database'] ?? NULL,
      'sslmode' => $data['sslmode'] ?? NULL,
      'sslrootcert' => $cert,
      'sslrootcert_readable' => $cert ? is_readable($cert) : FALSE,
    ];

    try {
      $connection = $provider->getConnection();
      if (!$connection) {
        $result['error'] = 'The provider returned no connection.';
        return $result;
      }
      $result['reachable'] = TRUE;

      // pg_stat_ssl reports what this backend actually negotiated, rather than
      // what the server is willing to accept.
      $row = $connection
        ->query('SELECT version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()')
        ->fetch();
      if ($row) {
        $result['tls_version'] = $row['version'] ?: NULL;
        $result['tls_cipher'] = $row['cipher'] ?: NULL;
      }

      // A verifying sslmode that connected at all is its own proof, because
      // libpq refuses the connection outright when verification fails.
      $result['verified'] = in_array(
        $data['sslmode'] ?? '',
        ['verify-ca', 'verify-full'],
        TRUE,
      );
    }
    catch (\Throwable $e) {
      $result['error'] = $e->getMessage();
    }

    return $result;
  }

  /**
   * Report which collection each vector store index is pointed at.
   *
   * @return array
   *   A list of arrays with keys: server, server_label, database, collection,
   *   and indexes (a list of arrays with keys id, label, read_only).
   */
  public function getIndexTargets(): array {
    $targets = [];

    try {
      $servers = $this->entityTypeManager
        ->getStorage('search_api_server')
        ->loadMultiple();
      $indexes = $this->entityTypeManager
        ->getStorage('search_api_index')
        ->loadMultiple();
    }
    catch (\Throwable $e) {
      $this->loggerFactory->get('s360_vector_health')->error(
        'Could not load Search API entities: @message',
        ['@message' => $e->getMessage()],
      );
      return $targets;
    }

    foreach ($servers as $server) {
      $backend_config = $server->getBackendConfig();
      if (($backend_config['database'] ?? NULL) !== $this->providerId()) {
        continue;
      }
      $settings = $backend_config['database_settings'] ?? [];

      $server_indexes = [];
      foreach ($indexes as $index) {
        if ($index->getServerId() !== $server->id()) {
          continue;
        }
        $server_indexes[] = [
          'id' => $index->id(),
          'label' => $index->label(),
          'read_only' => $index->isReadOnly(),
        ];
      }

      $targets[] = [
        'server' => $server->id(),
        'server_label' => $server->label(),
        'database' => $settings['database_name'] ?? NULL,
        'collection' => $settings['collection'] ?? NULL,
        'indexes' => $server_indexes,
      ];
    }

    return $targets;
  }

  /**
   * Report this container's egress address and the GCP prefix it belongs to.
   *
   * No allowlist verdict is computed: the site cannot query the store's
   * firewall, so any verdict would come from a hand-maintained config mirror
   * that drifts from the real rule list. Whether the address is allowlisted
   * is answered by the connection diagnostics — reachable means allowlisted.
   *
   * The prefilled az command covers the whole published GCP prefix, not the
   * single observed address. Pantheon containers move, and a rule pinned to
   * one address breaks silently the first time they do; a rule covering the
   * prefix survives the move. When the prefix cannot be determined the
   * command falls back to the single address, and says so.
   *
   * Applies only while the store is reached over a public endpoint; see the
   * "egress" section marker in the controller.
   *
   * @param bool $refresh
   *   TRUE to bypass the cached address and prefix list.
   *
   * @return array
   *   An associative array with keys:
   *   - ip: the observed egress address, or NULL on failure.
   *   - cached: TRUE when the address came from cache.
   *   - prefix: the published GCP prefix containing the address, or NULL.
   *   - scope: the GCP region of that prefix, or NULL.
   *   - prefix_error: why no prefix was found, or NULL.
   *   - firewall_command: a prefilled firewall command from the template, or
   *   NULL.
   *   - error: failure message, or NULL.
   */
  public function getEgressDiagnostics(bool $refresh = FALSE): array {
    $config = $this->configFactory->get(static::CONFIG_NAME);

    $result = [
      'ip' => NULL,
      'cached' => FALSE,
      'prefix' => NULL,
      'scope' => NULL,
      'prefix_error' => NULL,
      'firewall_command' => NULL,
      'error' => NULL,
    ];

    $cached = $refresh ? FALSE : $this->cache->get(static::EGRESS_CACHE_ID);
    if ($cached && !empty($cached->data)) {
      $result['ip'] = $cached->data;
      $result['cached'] = TRUE;
    }
    else {
      try {
        $response = $this->httpClient->request(
          'GET',
          $config->get('egress_echo_url') ?: 'https://api.ipify.org',
          ['timeout' => 5],
        );
        $ip = trim((string) $response->getBody());
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
          throw new \RuntimeException('The echo service returned "' . $ip . '", which is not an IP address.');
        }
        $result['ip'] = $ip;
        $this->cache->set(
          static::EGRESS_CACHE_ID,
          $ip,
          time() + (int) ($config->get('egress_cache_ttl') ?: 300),
        );
      }
      catch (GuzzleException | \RuntimeException $e) {
        // Outbound HTTP may itself be blocked. Report it and carry on: the
        // connection section above is still worth rendering.
        $result['error'] = $e->getMessage();
        return $result;
      }
    }

    $lookup = $this->lookupGcpPrefix($result['ip'], $refresh);
    $result['prefix'] = $lookup['prefix'];
    $result['scope'] = $lookup['scope'];
    $result['prefix_error'] = $lookup['error'];

    $result['firewall_command'] = static::buildFirewallCommand(
      $result['ip'],
      (string) ($config->get('firewall_command_template') ?: static::DEFAULT_FIREWALL_TEMPLATE),
      $result['prefix'],
    );

    return $result;
  }

  /**
   * Find the published GCP prefix containing an address.
   *
   * Google's list is fetched once and cached for a day: it changes rarely,
   * and a lookup that re-downloaded 100 KB on every page view would be the
   * slowest thing on the report.
   *
   * @param string $ip
   *   The address to look up.
   * @param bool $refresh
   *   TRUE to bypass the cached prefix list.
   *
   * @return array
   *   An associative array with keys prefix, scope, and error. Exactly one of
   *   prefix and error is non-NULL.
   */
  protected function lookupGcpPrefix(string $ip, bool $refresh = FALSE): array {
    $config = $this->configFactory->get(static::CONFIG_NAME);
    $result = ['prefix' => NULL, 'scope' => NULL, 'error' => NULL];

    $prefixes = NULL;
    $cached = $refresh ? FALSE : $this->cache->get(static::GCP_RANGES_CACHE_ID);
    if ($cached && is_array($cached->data)) {
      $prefixes = $cached->data;
    }
    else {
      try {
        $response = $this->httpClient->request(
          'GET',
          $config->get('gcp_ranges_url') ?: static::GCP_RANGES_URL,
          ['timeout' => 5],
        );
        $data = json_decode((string) $response->getBody(), TRUE);
        if (!is_array($data['prefixes'] ?? NULL)) {
          throw new \RuntimeException('The range list did not contain a "prefixes" array.');
        }
        // Keep only what the lookup needs; the full document carries IPv6
        // prefixes and service labels that would only bloat the cache.
        $prefixes = [];
        foreach ($data['prefixes'] as $entry) {
          if (!empty($entry['ipv4Prefix'])) {
            $prefixes[] = [
              'ipv4Prefix' => $entry['ipv4Prefix'],
              'scope' => $entry['scope'] ?? '',
            ];
          }
        }
        $this->cache->set(
          static::GCP_RANGES_CACHE_ID,
          $prefixes,
          time() + (int) ($config->get('gcp_ranges_cache_ttl') ?: 86400),
        );
      }
      catch (GuzzleException | \RuntimeException $e) {
        $result['error'] = $e->getMessage();
        return $result;
      }
    }

    $match = static::findPrefix($ip, $prefixes);
    if (!$match) {
      $result['error'] = 'The address is not inside any prefix on Google\'s published list.';
      return $result;
    }

    $result['prefix'] = $match['ipv4Prefix'];
    $result['scope'] = $match['scope'];
    return $result;
  }

  /**
   * Find the most specific IPv4 prefix containing an address.
   *
   * @param string $ip
   *   The IPv4 address to look up.
   * @param array $prefixes
   *   A list of arrays with keys ipv4Prefix (CIDR) and scope. Entries
   *   without an ipv4Prefix key are ignored.
   *
   * @return array|null
   *   The matching entry, or NULL when no prefix contains the address. When
   *   prefixes overlap, the longest (most specific) one wins.
   */
  public static function findPrefix(string $ip, array $prefixes): ?array {
    $needle = ip2long($ip);
    if ($needle === FALSE) {
      return NULL;
    }

    $best = NULL;
    $best_length = -1;
    foreach ($prefixes as $entry) {
      $cidr = $entry['ipv4Prefix'] ?? NULL;
      if (!$cidr || !str_contains($cidr, '/')) {
        continue;
      }
      [$network, $length] = explode('/', $cidr, 2);
      $length = (int) $length;
      $base = ip2long($network);
      if ($base === FALSE || $length < 0 || $length > 32) {
        continue;
      }
      $mask = $length === 0 ? 0 : (~0 << (32 - $length)) & 0xFFFFFFFF;
      if (($needle & $mask) === ($base & $mask) && $length > $best_length) {
        $best = $entry;
        $best_length = $length;
      }
    }

    return $best;
  }

  /**
   * Expand an IPv4 CIDR prefix into its first and last address.
   *
   * @param string $cidr
   *   The prefix, e.g. "34.44.0.0/15".
   *
   * @return string[]
   *   A two-element list: first address, last address.
   *
   * @throws \InvalidArgumentException
   *   When the prefix is not valid IPv4 CIDR.
   */
  public static function cidrRange(string $cidr): array {
    if (!str_contains($cidr, '/')) {
      throw new \InvalidArgumentException('"' . $cidr . '" is not CIDR notation.');
    }
    [$network, $length] = explode('/', $cidr, 2);
    $base = ip2long($network);
    $length = (int) $length;
    if ($base === FALSE || !ctype_digit(explode('/', $cidr, 2)[1]) || $length > 32) {
      throw new \InvalidArgumentException('"' . $cidr . '" is not a valid IPv4 prefix.');
    }
    $mask = $length === 0 ? 0 : (~0 << (32 - $length)) & 0xFFFFFFFF;
    $first = $base & $mask;
    $last = $first | (~$mask & 0xFFFFFFFF);

    return [long2ip($first), long2ip($last)];
  }

  /**
   * Fills the firewall command template for an address or prefix.
   *
   * Tokens: {rule_name}, {start}, {end}, {ip}, {prefix}. Unknown tokens are
   * left in place so a half-edited template is visible rather than silently
   * wrong.
   *
   * @param string $ip
   *   The observed address. Used on its own when no prefix is given.
   * @param string $template
   *   The command template from settings.
   * @param string|null $cidr
   *   The published prefix containing the address, or NULL to allow only the
   *   single address.
   *
   * @return string
   *   The command.
   */
  public static function buildFirewallCommand(string $ip, string $template, ?string $cidr = NULL): string {
    if ($cidr !== NULL) {
      [$start, $end] = static::cidrRange($cidr);
      $name = 'pantheon-' . str_replace(['.', '/'], '-', $cidr);
    }
    else {
      $start = $end = $ip;
      $name = 'pantheon-' . str_replace('.', '-', $ip);
    }

    return strtr($template, [
      '{rule_name}' => $name,
      '{start}' => $start,
      '{end}' => $end,
      '{ip}' => $ip,
      '{prefix}' => $cidr ?? $ip,
    ]);
  }

  /**
   * The configured vector DB provider plugin id.
   */
  public function providerId(): string {
    return (string) ($this->configFactory->get(static::CONFIG_NAME)->get('vdb_provider') ?: 'postgres');
  }

  /**
   * Whether the egress section applies to this environment.
   *
   * Setting egress_mode: "auto" (default) shows it only where
   * PANTHEON_ENVIRONMENT
   * is set, "on" always, "off" never.
   */
  public function egressEnabled(): bool {
    $mode = (string) ($this->configFactory->get(static::CONFIG_NAME)->get('egress_mode') ?: 'auto');
    return match ($mode) {
      'on' => TRUE,
      'off' => FALSE,
      default => getenv('PANTHEON_ENVIRONMENT') !== FALSE,
    };
  }

  /**
   * Whether the report should be denied on the live environment.
   */
  public function denyOnLive(): bool {
    $value = $this->configFactory->get(static::CONFIG_NAME)->get('deny_on_live');
    return $value === NULL ? TRUE : (bool) $value;
  }

}
