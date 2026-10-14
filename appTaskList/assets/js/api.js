const ONLINE_STORAGE_API = "https://onlinestorage.you.tec.br/api";
const ONLINE_STORAGE_BUCKET = "app-task-list";
const PASSWORD_HASH_ITERATIONS = 120000;

async function requestStorage(path, options = {}) {
    let response;

    try {
        response = await fetch(`${ONLINE_STORAGE_API}${path}`, options);
    } catch (error) {
        throw new Error("Não foi possível conectar à API. Verifique sua conexão e tente novamente.");
    }

    if (!response.ok) {
        const responseText = await response.text();
        let responseBody = null;

        try {
            responseBody = responseText ? JSON.parse(responseText) : null;
        } catch {
            responseBody = null;
        }

        const message = responseBody && typeof responseBody === "object"
            ? responseBody.message || responseBody.error
            : null;
        const error = new Error(message || `A API retornou o erro ${response.status}.`);
        error.status = response.status;
        throw error;
    }

    const responseText = await response.text();
    let responseBody = null;

    if (responseText) {
        try {
            responseBody = JSON.parse(responseText);
        } catch {
            throw new Error("A API retornou uma resposta inválida.");
        }
    }

    return responseBody;
}

async function getStorageValue(key, defaultValue) {
    let response;

    try {
        response = await requestStorage(
            `/getkey/${encodeURIComponent(ONLINE_STORAGE_BUCKET)}/${encodeURIComponent(key)}`
        );
    } catch (error) {
        if (error.status === 404) {
            return defaultValue;
        }

        throw error;
    }

    if (response && typeof response === "object" && Object.hasOwn(response, "value")) {
        return response.value;
    }

    return response;
}

async function setStorageValue(key, value) {
    await requestStorage("/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            bucket: ONLINE_STORAGE_BUCKET,
            key,
            value
        })
    });
}

function accountStorageKey(email) {
    return `user_${email.trim().toLowerCase()}`;
}

function tasksStorageKey(userId) {
    return `tasks_${userId}`;
}

function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
}

async function hashPassword(password, salt) {
    if (!globalThis.crypto || !crypto.subtle || !crypto.getRandomValues) {
        throw new Error("O login seguro exige abrir o app por HTTPS ou por um servidor local.");
    }

    const passwordKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: hexToBytes(salt),
            iterations: PASSWORD_HASH_ITERATIONS,
            hash: "SHA-256"
        },
        passwordKey,
        256
    );

    return bytesToHex(new Uint8Array(derivedBits));
}

function createSalt() {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    return bytesToHex(salt);
}

function createId() {
    const id = new Uint8Array(16);
    crypto.getRandomValues(id);
    return bytesToHex(id);
}

function passwordsMatch(firstHash, secondHash) {
    if (firstHash.length !== secondHash.length) {
        return false;
    }

    let difference = 0;
    for (let index = 0; index < firstHash.length; index += 1) {
        difference |= firstHash.charCodeAt(index) ^ secondHash.charCodeAt(index);
    }

    return difference === 0;
}

window.OnlineStorage = Object.freeze({
    accountStorageKey,
    createId,
    createSalt,
    get: getStorageValue,
    hashPassword,
    passwordsMatch,
    set: setStorageValue,
    tasksStorageKey
});
