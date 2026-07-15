export const DEADLINES = Object.freeze({
    nginx_config_test: 10000,
    nginx_readiness: 15000,
    chromium_launch: 30000,
    browser_context: 10000,
    cdp_operation: 10000,
    document_navigation: 30000,
    e2e_terminal_outcome: 30000,
    controlled_probe: 10000,
    fail_closed_quiet_window: 1000,
    benchmark_controller_quiet_window: 1000,
    diagnostic_capture: 10000,
    page_context_close: 10000,
    chromium_close: 15000,
    nginx_quit: 10000,
    nginx_term: 5000,
    nginx_kill: 2000,
});

export const FEASIBILITY_TARGET_TIMEOUT_MS = 180000;
export const E2E_TARGET_TIMEOUT_MS = 600000;
export const BENCHMARK_TARGET_TIMEOUT_MS = 360000;
export const BROWSER_AGGREGATE_TIMEOUT_MS = 1300000;
export const OUTER_WATCHDOG_CLEANUP_GRACE_MS = 20000;

export const CAPTURE_LIMITS = Object.freeze({
    bench_min_attempts: 1,
    bench_max_attempts: 262144,
    bench_target_block_ms: 10,
    bench_js_block_ceiling_ms: 25,
    max_observation_events_per_page: 4096,
    max_observation_metadata_bytes_per_page: 1024 * 1024,
    max_raw_samples_per_run_series: 8192,
    max_generated_evidence_bytes: 16 * 1024 * 1024,
    max_retained_diagnostic_bytes: 2 * 1024 * 1024,
    max_failed_benchmark_sample_excerpt: 32,
    heartbeat_allowed_timer_tail: 2,
});

class ReadonlySet {
    #values;

    constructor(values) {
        this.#values = new Set(values);
        Object.freeze(this);
    }

    has(value) {
        return this.#values.has(value);
    }

    get size() {
        return this.#values.size;
    }

    [Symbol.iterator]() {
        return this.#values[Symbol.iterator]();
    }
}


export const FAILURE_CATEGORIES = new ReadonlySet([
    'host_policy',
    'environment_identity',
    'fixture_configuration',
    'fixture_startup',
    'sandbox_policy',
    'browser_pairing',
    'browser_runtime',
    'protocol_assertion',
    'cookie_assertion',
    'controller_assertion',
    'benchmark_correctness',
    'benchmark_responsiveness',
    'evidence_validation',
    'internal_invariant',
    'cleanup',
]);
