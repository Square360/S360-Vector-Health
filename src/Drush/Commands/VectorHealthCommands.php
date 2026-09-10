<?php

declare(strict_types=1);

namespace Drupal\s360_vector_health\Drush\Commands;

use Consolidation\OutputFormatters\StructuredData\RowsOfFields;
use Drupal\s360_vector_health\VectorHealth;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Drush commands for the vector store health report.
 *
 * Drush 12.4+/13 registration: discovered from src/Drush/Commands/ and
 * instantiated via AutowireTrait::create(). No permission check: drush runs
 * as root, and the command only reads.
 */
class VectorHealthCommands extends DrushCommands {

  use AutowireTrait;

  public function __construct(
    #[Autowire(service: 's360_vector_health.health')]
    protected VectorHealth $health,
  ) {
    parent::__construct();
  }

  /**
   * Shows the vector store connection, TLS state, index targets, and egress.
   */
  #[CLI\Command(name: 's360:vector:health', aliases: ['s360-vector-health'])]
  #[CLI\Usage(name: 'drush s360:vector:health', description: 'Connection, TLS, index targets, and (on Pantheon) egress as a table.')]
  #[CLI\Usage(name: 'drush s360:vector:health --format=json', description: 'Same as JSON, for scripts.')]
  #[CLI\FieldLabels(labels: ['item' => 'Item', 'value' => 'Value'])]
  public function health(): RowsOfFields {
    $rows = [];
    $add = function (string $key, string $item, mixed $value) use (&$rows): void {
      $rows[$key] = ['item' => $item, 'value' => is_bool($value) ? ($value ? 'yes' : 'no') : (string) ($value ?? '')];
    };

    $c = $this->health->getConnectionDiagnostics();
    $s = $c['settings'];
    $add('provider', 'Provider', $this->health->providerId());
    $add('host', 'Host', ($s['host'] ?? '') . (isset($s['port']) ? ':' . $s['port'] : ''));
    $add('database', 'Database', $s['default_database'] ?? NULL);
    $add('sslmode', 'SSL mode', $s['sslmode'] ?? NULL);
    $add('reachable', 'Reachable', $c['reachable']);
    $add('tls', 'Negotiated TLS', $c['tls_version'] ? $c['tls_version'] . ' (' . ($c['tls_cipher'] ?? '?') . ')' : NULL);
    $add('verified', 'Certificate verified', $c['verified']);
    if ($c['error']) {
      $add('error', 'Error', $c['error']);
    }

    foreach ($this->health->getIndexTargets() as $t) {
      $indexes = implode(', ', array_map(fn(array $i) => $i['id'] . ($i['read_only'] ? ' (ro)' : ''), $t['indexes']));
      $add('target_' . $t['server'], 'Index target: ' . $t['server'], ($t['database'] ?? '?') . ' / ' . ($t['collection'] ?? '?') . ($indexes ? ' <- ' . $indexes : ' (no index)'));
    }

    if ($this->health->egressEnabled()) {
      $e = $this->health->getEgressDiagnostics();
      $add('egress_ip', 'Egress address', $e['ip'] ?? $e['error']);
      $add('egress_prefix', 'Published GCP prefix', $e['prefix'] ? $e['prefix'] . ' (' . $e['scope'] . ')' : ($e['prefix_error'] ?? ''));
      $add('firewall', 'Firewall command', $e['firewall_command']);
    }

    if (!$c['reachable'] || !$c['verified']) {
      $this->logger()->warning(dt('Vector store is unreachable or its certificate is not verified.'));
    }
    return new RowsOfFields($rows);
  }

}
