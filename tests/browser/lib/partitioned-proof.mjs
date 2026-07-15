const expectedPartitionKey = Object.freeze({
    hasCrossSiteAncestor: false,
    sourceOrigin: 'https://powgate.test',
});
const expectedCookie = Object.freeze({
    domain: 'gate.powgate.test',
    expires: -1,
    httpOnly: false,
    partitionKey: expectedPartitionKey,
    path: '/',
    sameSite: 'Lax',
    secure: true,
    session: true,
});

export const PARTITIONED_PROOF_FIXTURE = Object.freeze({
    challengePath: '/partitioned-feasibility',
    expectedCookie,
    name: '__pow_p',
    seedPath: '/__powgate_partitioned_seed',
    setCookie: '__pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned',
    value: '1.0.0',
});


export function countExactProofCookies(text) {
    if (typeof text !== 'string') {
        throw new TypeError('invalid cookie text');
    }

    const proofName = '__pow_p';
    let count = 0;
    let cursor = 0;

    while (cursor <= text.length) {
        let end = text.indexOf(';', cursor);
        if (end === -1) {
            end = text.length;
        }
        while (cursor < end && (text.charCodeAt(cursor) === 0x20
            || text.charCodeAt(cursor) === 0x09)) {
            cursor++;
        }
        if (text.slice(cursor, cursor + proofName.length + 1)
            === `${proofName}=`) {
            count++;
        }
        if (end === text.length) {
            break;
        }
        cursor = end + 1;
    }
    return count;
}


export function partitionedCookieMatchesFixture(cookie) {
    const partitionKey = cookie?.partitionKey;

    return cookie !== null && typeof cookie === 'object'
        && cookie.name === PARTITIONED_PROOF_FIXTURE.name
        && cookie.value === PARTITIONED_PROOF_FIXTURE.value
        && cookie.domain === expectedCookie.domain
        && cookie.path === expectedCookie.path
        && cookie.secure === expectedCookie.secure
        && cookie.httpOnly === expectedCookie.httpOnly
        && cookie.sameSite === expectedCookie.sameSite
        && cookie.session === expectedCookie.session
        && cookie.expires === expectedCookie.expires
        && partitionKey !== null && typeof partitionKey === 'object'
        && !Array.isArray(partitionKey)
        && Object.keys(partitionKey).sort().join(',')
            === 'hasCrossSiteAncestor,sourceOrigin'
        && partitionKey.sourceOrigin === expectedPartitionKey.sourceOrigin
        && partitionKey.hasCrossSiteAncestor
            === expectedPartitionKey.hasCrossSiteAncestor;
}


export function classifyPartitionedCookies(
    cookies, parentCookies, authCookieName,
) {
    if (!Array.isArray(cookies) || !Array.isArray(parentCookies)
        || typeof authCookieName !== 'string' || authCookieName === '') {
        throw new TypeError('invalid partitioned cookie classification');
    }
    if (parentCookies.some((cookie) =>
        cookie?.name === PARTITIONED_PROOF_FIXTURE.name)) {
        throw new Error('partitioned proof cookie is not host-only');
    }

    let authCookieCount = 0;
    let newPartitionedProofCount = 0;
    let originalPartitionedProofCount = 0;
    let unpartitionedProofCount = 0;

    for (const cookie of cookies) {
        if (cookie?.name === authCookieName) {
            authCookieCount++;
        }
        if (cookie?.name !== PARTITIONED_PROOF_FIXTURE.name) {
            continue;
        }
        if (cookie.partitionKey === undefined) {
            unpartitionedProofCount++;
        } else if (partitionedCookieMatchesFixture(cookie)) {
            originalPartitionedProofCount++;
        } else {
            newPartitionedProofCount++;
        }
    }

    return Object.freeze({
        authCookieCount,
        newPartitionedProofCount,
        originalPartitionedProofCount,
        unpartitionedProofCount,
    });
}


export function partitionedObserverBootstrap() {
    const productionDescriptor = Object.freeze({
        configurable: true,
        enumerable: true,
        writable: true,
    });
    const state = {
        descriptorValid: false,
        exportsValid: false,
        namespaceAssignments: 0,
        namespaceFrozen: false,
        phase: 'waiting',
        solverCalls: 0,
    };
    let wrapped;

    Object.defineProperty(globalThis, '__powgatePartitionedObserver', {
        configurable: false,
        enumerable: false,
        value: Object.freeze({
            snapshot() {
                return Object.freeze({ ...state });
            },
        }),
        writable: false,
    });
    Object.defineProperty(globalThis, 'PowGateSolver', {
        configurable: true,
        enumerable: true,
        get() {
            return wrapped;
        },
        set(namespace) {
            state.namespaceAssignments++;
            if (state.namespaceAssignments !== 1) {
                throw new TypeError('PowGateSolver assigned more than once');
            }
            const keys = namespace === null || typeof namespace !== 'object'
                ? [] : Object.keys(namespace);
            if (keys.join(',') !== 'sha256,solve'
                || typeof namespace.sha256 !== 'function'
                || typeof namespace.solve !== 'function'
                || !Object.isFrozen(namespace)) {
                throw new TypeError('invalid PowGateSolver namespace');
            }
            wrapped = Object.freeze({
                sha256: namespace.sha256,
                solve(...args) {
                    state.solverCalls++;
                    return Reflect.apply(namespace.solve, namespace, args);
                },
            });
            state.exportsValid = Object.keys(wrapped).join(',')
                === 'sha256,solve';
            state.namespaceFrozen = Object.isFrozen(wrapped);
            state.phase = 'assigned';
        },
    });
    document.addEventListener('DOMContentLoaded', () => {
        if (state.namespaceAssignments !== 1 || wrapped === undefined) {
            throw new TypeError('PowGateSolver assignment missing');
        }
        Object.defineProperty(globalThis, 'PowGateSolver', {
            ...productionDescriptor,
            value: wrapped,
        });
        const descriptor = Object.getOwnPropertyDescriptor(
            globalThis, 'PowGateSolver',
        );
        state.descriptorValid = descriptor !== undefined
            && descriptor.value === wrapped
            && descriptor.configurable === productionDescriptor.configurable
            && descriptor.enumerable === productionDescriptor.enumerable
            && descriptor.writable === productionDescriptor.writable;
        state.phase = 'installed';
    }, { capture: true, once: true });
}


export async function partitionedObserverSnapshot(page) {
    const snapshot = await page.evaluate(() =>
        globalThis.__powgatePartitionedObserver.snapshot());
    return Object.freeze({ ...snapshot });
}
