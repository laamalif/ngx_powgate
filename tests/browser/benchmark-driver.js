(() => {
    'use strict';

    const MAX_COUNTER = Number.MAX_SAFE_INTEGER;
    const RESULT_KEYS = Object.freeze([
        'attempts', 'counter', 'exhausted', 'found', 'nextCounter',
    ]);

    function assertResult(result, start, limit) {
        if (result === null || typeof result !== 'object'
            || !Object.isFrozen(result)
            || Object.keys(result).sort().join(',') !== RESULT_KEYS.join(',')
            || !Number.isSafeInteger(result.attempts)
            || result.attempts < 1 || result.attempts > limit) {
            throw new Error();
        }
        if (result.found) {
            if (result.exhausted || !Number.isSafeInteger(result.counter)
                || result.counter < start
                || result.counter !== start + result.attempts - 1
                || result.nextCounter !== null) {
                throw new Error();
            }
        } else if (result.counter !== null) {
            throw new Error();
        } else if (result.exhausted) {
            if (result.nextCounter !== null
                || start + result.attempts - 1 !== MAX_COUNTER) {
                throw new Error();
            }
        } else if (result.nextCounter !== start + result.attempts) {
            throw new Error();
        }
    }

    function counterBytes(nonce, counter) {
        const decimal = new TextEncoder().encode(`${counter}`);
        const message = new Uint8Array(nonce.length + decimal.length);
        message.set(nonce);
        message.set(decimal, nonce.length);
        return message;
    }


    function hexBytes(text) {
        const output = new Uint8Array(text.length / 2);
        for (let index = 0; index < output.length; index += 1) {
            output[index] = Number.parseInt(
                text.slice(index * 2, (index * 2) + 2), 16,
            );
        }
        return output;
    }

    function meets(digest, difficulty) {
        const full = Math.floor(difficulty / 8);
        for (let index = 0; index < full; index += 1) {
            if (digest[index] !== 0) {
                return false;
            }
        }
        const remainder = difficulty % 8;
        return remainder === 0
            || (digest[full] >>> (8 - remainder)) === 0;
    }

    function verifySuccess(nonce, difficulty, counter) {
        const digest = globalThis.PowGateSolver.sha256(
            counterBytes(nonce, counter),
        );
        return meets(digest, difficulty);
    }

    function nextCounter(result, nonce, difficulty) {
        if (!result.found) {
            return Object.freeze({
                next: result.nextCounter,
                safeDomainTerminal: result.exhausted,
                verified: true,
            });
        }
        const verified = verifySuccess(nonce, difficulty, result.counter);
        if (!verified) {
            throw new Error();
        }
        return Object.freeze({
            next: result.counter === MAX_COUNTER ? null : result.counter + 1,
            safeDomainTerminal: result.counter === MAX_COUNTER,
            verified,
        });
    }

    function boundedAttempts(current, duration, start, options) {
        const measured = Math.max(duration, options.timerResolutionFloorMs);
        if (!(measured > 0)) {
            throw new Error();
        }
        let selected = Math.round(current * options.targetBlockMs / measured);
        selected = Math.max(options.minAttempts,
            Math.min(options.maxAttempts, selected));
        if (start > MAX_COUNTER - (selected - 1)) {
            selected = MAX_COUNTER - start + 1;
        }
        if (!Number.isSafeInteger(selected) || selected < 1) {
            throw new Error();
        }
        return selected;
    }

    function yieldTurn() {
        return new Promise((resolve) => setTimeout(resolve, 0));
    }

    async function invoke(nonce, difficulty, start, limit, backend) {
        const before = performance.now();
        const promise = globalThis.PowGateSolver.solve(
            nonce, difficulty, start, limit, backend,
        );
        const synchronousEntryMs = performance.now() - before;
        const result = await promise;
        const awaitedMs = performance.now() - before;
        assertResult(result, start, limit);
        const continuation = nextCounter(result, nonce, difficulty);
        return Object.freeze({
            awaitedMs,
            continuation,
            result,
            synchronousEntryMs,
        });
    }

    async function warmup(options) {
        const nonce = new Uint8Array(options.nonce);
        let attempts = options.minAttempts;
        let counter = 0;
        const start = performance.now();
        while (performance.now() - start < options.warmupMs) {
            const measured = await invoke(
                nonce, options.difficulty, counter, attempts, options.backend,
            );
            if (measured.continuation.safeDomainTerminal) {
                throw new Error();
            }
            counter = measured.continuation.next;
            const duration = options.backend === 'js'
                ? measured.synchronousEntryMs : measured.awaitedMs;
            attempts = boundedAttempts(attempts, duration, counter, options);
            await yieldTurn();
        }
        return attempts;
    }

    async function run(options) {
        if (document.hidden || !Object.isFrozen(globalThis.PowGateSolver)
            || Object.keys(globalThis.PowGateSolver).sort().join(',')
                !== 'sha256,solve') {
            throw new Error();
        }
        const nonce = new Uint8Array(options.nonce);
        let limit = await warmup(options);
        let counter = 0;
        let completed = 0;
        let hits = 0;
        let firstHitOffset = null;
        let nextDeadline;
        let heartbeatTimer;
        let heartbeatActive = true;
        const heartbeatSamples = [];
        const jsDurations = [];
        const subtleEntryDurations = [];
        const subtleAwaitedDurations = [];
        const subtleAsyncDurations = [];

        const recordedStart = performance.now();
        const stoppingDeadline = recordedStart + options.recordMs;
        nextDeadline = recordedStart + options.heartbeatMs;
        function heartbeat() {
            if (!heartbeatActive) {
                return;
            }
            const actual = performance.now();
            while (nextDeadline <= actual) {
                heartbeatSamples.push({
                    deadline_performance_ms: nextDeadline,
                    delay_ms: Math.max(0, actual - nextDeadline),
                });
                nextDeadline += options.heartbeatMs;
            }
            heartbeatTimer = setTimeout(
                heartbeat, Math.max(0, nextDeadline - performance.now()),
            );
        }
        heartbeatTimer = setTimeout(
            heartbeat, Math.max(0, nextDeadline - performance.now()),
        );

        try {
            do {
                if (document.hidden) {
                    throw new Error();
                }
                const invocationStart = counter;
                const measured = await invoke(
                    nonce, options.difficulty, counter, limit, options.backend,
                );
                if (options.backend === 'js') {
                    jsDurations.push(measured.synchronousEntryMs);
                } else {
                    subtleEntryDurations.push(measured.synchronousEntryMs);
                    subtleAwaitedDurations.push(measured.awaitedMs);
                    subtleAsyncDurations.push(Math.max(
                        0, measured.awaitedMs - measured.synchronousEntryMs,
                    ));
                }
                if (measured.result.found) {
                    hits += 1;
                    if (firstHitOffset === null) {
                        firstHitOffset = completed
                            + (measured.result.counter - invocationStart);
                    }
                }
                completed += measured.result.attempts;
                if (measured.continuation.safeDomainTerminal) {
                    throw new Error();
                }
                counter = measured.continuation.next;
                await yieldTurn();
            } while (performance.now() < stoppingDeadline);
        } finally {
            heartbeatActive = false;
            clearTimeout(heartbeatTimer);
        }

        const recordedEnd = performance.now();
        while (nextDeadline <= recordedEnd) {
            heartbeatSamples.push({
                deadline_performance_ms: nextDeadline,
                delay_ms: Math.max(0, recordedEnd - nextDeadline),
            });
            nextDeadline += options.heartbeatMs;
        }
        return Object.freeze({
            calibrated_attempt_limit: limit,
            completed_candidates: completed,
            first_valid_hit_offset: firstHitOffset,
            heartbeat_samples: heartbeatSamples,
            js_block_durations_ms: jsDurations,
            recorded_end_performance_ms: recordedEnd,
            recorded_start_performance_ms: recordedStart,
            subtle_async_remainder_durations_ms: subtleAsyncDurations,
            subtle_awaited_invocation_durations_ms: subtleAwaitedDurations,
            subtle_sync_entry_durations_ms: subtleEntryDurations,
            valid_hit_count: hits,
        });
    }


    async function kat(backend) {
        const nonce = hexBytes(
            'c382cd45c32e81f6f5bdcc5fb29497876a3d4364b688245668ab1b578ff7184f',
        );
        const expected = hexBytes(
            '0028df459a18ed1973ccbfb54439b98bef2e3988fb5072e2fd3b8a1368d275f5',
        );
        const digest = globalThis.PowGateSolver.sha256(
            counterBytes(nonce, 34),
        );
        if (digest.length !== expected.length
            || digest.some((byte, index) => byte !== expected[index])) {
            throw new Error();
        }
        const measured = await invoke(nonce, 10, 34, 1, backend);
        if (!measured.result.found || measured.result.counter !== 34
            || measured.result.attempts !== 1
            || measured.continuation.next !== 35) {
            throw new Error();
        }
        return true;
    }

    globalThis.PowGateBenchmarkDriver = Object.freeze({ kat, run });
})();
