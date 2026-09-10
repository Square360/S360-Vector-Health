<?php

declare(strict_types=1);

namespace Drupal\s360_vector_health\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\s360_vector_health\VectorHealth;

/**
 * Settings for the vector store health report.
 */
final class SettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 's360_vector_health_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['s360_vector_health.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('s360_vector_health.settings');

    $form['vdb_provider'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Vector DB provider plugin id'),
      '#default_value' => $config->get('vdb_provider') ?: 'postgres',
      '#required' => TRUE,
      '#description' => $this->t('The Drupal AI vector DB provider this site uses, e.g. postgres. The connection section asks this provider for its connection; the index targets section lists Search API servers whose backend uses it.'),
    ];
    $form['deny_on_live'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Deny the report on the live environment'),
      '#default_value' => $config->get('deny_on_live') ?? TRUE,
      '#description' => $this->t('The report names the store host and the container egress address. Neither is a credential, but neither needs to be on a public production site.'),
    ];

    $form['egress'] = [
      '#type' => 'details',
      '#title' => $this->t('Container egress (Pantheon)'),
      '#open' => TRUE,
    ];
    $form['egress']['egress_mode'] = [
      '#type' => 'radios',
      '#title' => $this->t('Show the egress section'),
      '#options' => [
        'auto' => $this->t('Automatically, when PANTHEON_ENVIRONMENT is set'),
        'on' => $this->t('Always'),
        'off' => $this->t('Never'),
      ],
      '#default_value' => $config->get('egress_mode') ?: 'auto',
    ];
    $form['egress']['egress_echo_url'] = [
      '#type' => 'url',
      '#title' => $this->t('Egress echo service'),
      '#default_value' => $config->get('egress_echo_url') ?: 'https://api.ipify.org',
      '#description' => $this->t('A service that returns the caller IP as plain text.'),
    ];
    $form['egress']['egress_cache_ttl'] = [
      '#type' => 'number',
      '#title' => $this->t('Egress cache lifetime (seconds)'),
      '#default_value' => $config->get('egress_cache_ttl') ?: 300,
      '#min' => 0,
    ];
    $form['egress']['gcp_ranges_url'] = [
      '#type' => 'url',
      '#title' => $this->t('Google Cloud range list'),
      '#default_value' => $config->get('gcp_ranges_url') ?: 'https://www.gstatic.com/ipranges/cloud.json',
    ];
    $form['egress']['gcp_ranges_cache_ttl'] = [
      '#type' => 'number',
      '#title' => $this->t('Range list cache lifetime (seconds)'),
      '#default_value' => $config->get('gcp_ranges_cache_ttl') ?: 86400,
      '#min' => 0,
    ];
    $form['egress']['firewall_command_template'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Firewall command template'),
      '#default_value' => $config->get('firewall_command_template') ?: VectorHealth::DEFAULT_FIREWALL_TEMPLATE,
      '#rows' => 3,
      '#description' => $this->t('Tokens: {rule_name}, {start}, {end}, {ip}, {prefix}. The default is an Azure Database for PostgreSQL rule; replace it for other stores.'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config('s360_vector_health.settings')
      ->set('vdb_provider', trim((string) $form_state->getValue('vdb_provider')))
      ->set('deny_on_live', (bool) $form_state->getValue('deny_on_live'))
      ->set('egress_mode', (string) $form_state->getValue('egress_mode'))
      ->set('egress_echo_url', (string) $form_state->getValue('egress_echo_url'))
      ->set('egress_cache_ttl', (int) $form_state->getValue('egress_cache_ttl'))
      ->set('gcp_ranges_url', (string) $form_state->getValue('gcp_ranges_url'))
      ->set('gcp_ranges_cache_ttl', (int) $form_state->getValue('gcp_ranges_cache_ttl'))
      ->set('firewall_command_template', trim((string) $form_state->getValue('firewall_command_template')))
      ->save();
    parent::submitForm($form, $form_state);
  }

}
