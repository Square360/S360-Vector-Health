<?php

namespace Drupal\s360_vector_health\Controller;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\s360_vector_health\VectorHealth;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Renders the vector store diagnostics report.
 */
final class VectorHealthController extends ControllerBase {

  /**
   * Constructs the controller.
   *
   * @param \Drupal\s360_vector_health\VectorHealth $diagnostics
   *   The diagnostics service.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack.
   */
  public function __construct(
    protected VectorHealth $diagnostics,
    protected RequestStack $requestStack,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('s360_vector_health.health'),
      $container->get('request_stack'),
    );
  }

  /**
   * Deny the report on production.
   *
   * The report names the vector store host and the container's egress address.
   * Neither is a credential, but neither belongs on a public production site
   * unless the site says so (deny_on_live setting).
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function access(): AccessResultInterface {
    $environment = getenv('PANTHEON_ENVIRONMENT') ?: '';
    $denied = $this->diagnostics->denyOnLive() && $environment === 'live';

    return AccessResult::allowedIf(!$denied)
      ->addCacheTags(['config:s360_vector_health.settings']);
  }

  /**
   * Build the report.
   *
   * @return array
   *   A render array.
   */
  public function report(): array {
    $build = [];
    $refresh = (bool) $this->requestStack->getCurrentRequest()->query->get('refresh');

    $build['connection'] = $this->buildConnectionSection();
    $build['targets'] = $this->buildTargetsSection();
    if ($this->diagnostics->egressEnabled()) {
      $build['egress'] = $this->buildEgressSection($refresh);
    }

    $build['#attached']['library'][] = 's360_vector_health/report';
    $build['#cache'] = ['max-age' => 0];

    return $build;
  }

  /**
   * Build the connection section.
   *
   * @return array
   *   A render array.
   */
  protected function buildConnectionSection(): array {
    $data = $this->diagnostics->getConnectionDiagnostics();
    $settings = $data['settings'];

    $rows = [
      [$this->t('Host'), $settings['host'] ?? $this->t('Not configured')],
      [$this->t('Port'), $settings['port'] ?? $this->t('Not configured')],
      [$this->t('Username'), $settings['username'] ?? $this->t('Not configured')],
      [$this->t('Default database'), $settings['default_database'] ?? $this->t('Not configured')],
      [$this->t('SSL mode'), $settings['sslmode'] ?? $this->t('Not configured')],
    ];

    if (!empty($settings['sslrootcert'])) {
      $rows[] = [
        $this->t('Root certificate'),
        $settings['sslrootcert_readable']
          ? $this->t('@path (readable)', ['@path' => $settings['sslrootcert']])
          : $this->t('@path — MISSING or unreadable', ['@path' => $settings['sslrootcert']]),
      ];
    }

    $rows[] = [
      $this->t('Reachable'),
      $data['reachable'] ? $this->t('Yes') : $this->t('No'),
    ];

    if ($data['reachable']) {
      $rows[] = [
        $this->t('Negotiated TLS'),
        $data['tls_version']
          ? $this->t('@version (@cipher)', [
            '@version' => $data['tls_version'],
            '@cipher' => $data['tls_cipher'] ?? $this->t('cipher unknown'),
          ])
          : $this->t('Not an encrypted connection'),
      ];
      $rows[] = [
        $this->t('Certificate verified'),
        $data['verified']
          ? $this->t('Yes — the server certificate validated against the pinned roots')
          : $this->t('No — the SSL mode in force does not validate the certificate'),
      ];
    }

    $build = [
      '#type' => 'details',
      '#title' => $this->t('Vector store connection'),
      '#open' => TRUE,
      '#attributes' => [
        'class' => [
          $data['reachable'] ? 's360-vector-health--ok' : 's360-vector-health--fail',
        ],
      ],
    ];

    if (!empty($data['error'])) {
      $build['error'] = [
        '#theme' => 'status_messages',
        '#message_list' => ['error' => [$data['error']]],
      ];
    }

    $build['table'] = [
      '#type' => 'table',
      '#header' => [$this->t('Setting'), $this->t('Value')],
      '#rows' => $rows,
    ];

    return $build;
  }

  /**
   * Build the index targets section.
   *
   * @return array
   *   A render array.
   */
  protected function buildTargetsSection(): array {
    $targets = $this->diagnostics->getIndexTargets();

    $build = [
      '#type' => 'details',
      '#title' => $this->t('Index targets'),
      '#open' => TRUE,
      '#description' => $this->t('Which collection this environment reads and writes. Collections are tables inside one database, so two environments sharing a database are still separated only by these names.'),
    ];

    if (!$targets) {
      $build['empty'] = [
        '#markup' => '<p>' . $this->t('No Search API server is using the Postgres vector store.') . '</p>',
      ];
      return $build;
    }

    $rows = [];
    foreach ($targets as $target) {
      foreach ($target['indexes'] as $index) {
        $rows[] = [
          $target['server_label'] ?? $target['server'],
          $target['database'] ?? $this->t('Not set'),
          $target['collection'] ?? $this->t('Not set'),
          $index['label'] ?? $index['id'],
          $index['read_only'] ? $this->t('Read only') : $this->t('Writable'),
        ];
      }
      if (!$target['indexes']) {
        $rows[] = [
          $target['server_label'] ?? $target['server'],
          $target['database'] ?? $this->t('Not set'),
          $target['collection'] ?? $this->t('Not set'),
          $this->t('No index attached'),
          '',
        ];
      }
    }

    $build['table'] = [
      '#type' => 'table',
      '#header' => [
        $this->t('Server'),
        $this->t('Database'),
        $this->t('Collection'),
        $this->t('Index'),
        $this->t('Write status'),
      ],
      '#rows' => $rows,
    ];

    return $build;
  }

  /**
   * Build the egress section.
   *
   * Applies only while the store is reached over a public endpoint: the
   * broad firewall allowlist goes away and the container's egress address
   * stops being something anyone needs to look up. Delete this method, the
   * egress half of VectorHealth, and the egress settings together.
   *
   * @param bool $refresh
   *   TRUE to bypass the cached address.
   *
   * @return array
   *   A render array.
   */
  protected function buildEgressSection(bool $refresh): array {
    $data = $this->diagnostics->getEgressDiagnostics($refresh);

    $build = [
      '#type' => 'details',
      '#title' => $this->t('Container egress address'),
      '#open' => TRUE,
      '#description' => $this->t('Pantheon publishes no egress range, so a store behind an IP allowlist has to allow the published GCP prefixes containers have been seen in. A container that moves outside them fails as a connection timeout, not as an error that names the cause. This section applies only while the store is reached over a public endpoint; it goes away once a private path (for example Pantheon Secure Integration) exists.'),
    ];

    if (!empty($data['error'])) {
      $build['error'] = [
        '#theme' => 'status_messages',
        '#message_list' => [
          'warning' => [
            $this->t('Could not determine the egress address: @message', ['@message' => $data['error']]),
          ],
        ],
      ];
      return $build;
    }

    $rows = [
      [
        $this->t('Egress address'),
        $data['cached']
          ? $this->t('@ip (cached)', ['@ip' => $data['ip']])
          : $data['ip'],
      ],
    ];
    if ($data['prefix']) {
      $rows[] = [
        $this->t('Published GCP prefix'),
        $this->t('@prefix (@scope)', [
          '@prefix' => $data['prefix'],
          '@scope' => $data['scope'] ?: $this->t('scope unknown'),
        ]),
      ];
    }
    $build['table'] = [
      '#type' => 'table',
      '#header' => [$this->t('Item'), $this->t('Value')],
      '#rows' => $rows,
    ];

    // The site cannot query the store's firewall, so no allowlisted-or-not
    // verdict is rendered; a verdict computed from a config mirror drifts
    // from reality. The connection section above is the ground truth.
    if ($data['prefix']) {
      $build['command_label'] = [
        '#markup' => '<p>' . $this->t('The vector store connection above is the ground truth: reachable means this address is allowlisted. If connections time out, allow the whole published prefix; a rule pinned to the single address breaks silently the next time the container moves:') . '</p>',
      ];
    }
    else {
      $build['prefix_warning'] = [
        '#theme' => 'status_messages',
        '#message_list' => [
          'warning' => [
            $this->t('Could not map the address to a published GCP prefix (@message). The command below allows only this single address, which will break when the container moves; look the prefix up by hand before running it.', ['@message' => $data['prefix_error']]),
          ],
        ],
      ];
      $build['command_label'] = [
        '#markup' => '<p>' . $this->t('If connections time out, add the address to the store firewall with:') . '</p>',
      ];
    }
    $build['command'] = [
      '#type' => 'html_tag',
      '#tag' => 'pre',
      '#value' => $data['firewall_command'],
    ];

    $build['refresh'] = [
      '#type' => 'link',
      '#title' => $this->t('Re-check egress address and prefix list'),
      '#url' => Url::fromRoute('s360_vector_health.report', [], [
        'query' => ['refresh' => 1],
      ]),
      '#attributes' => ['class' => ['button']],
    ];

    return $build;
  }

}
