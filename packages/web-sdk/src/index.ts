import {
  type LocalPlaintextMessage,
  type WsClientEvent,
  type WsServerEvent,
  localPlaintextMessageSchema,
  wsServerEventSchema,
} from '@zuri-secure-chat/protocol';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const dbName = 'zuri-secure-chat';
const dbVersion = 1;

type WebCryptoBytes = Uint8Array<ArrayBuffer>;

export type DeviceKeyPair = {
  publicKey: JsonWebKey;
  privateKey: CryptoKey;
};

export type VaultBackup = {
  version: 1;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  salt: string;
  nonce: string;
  encryptedPrivateKey: string;
  encryptedHistoryKey: string;
  publicKey: JsonWebKey;
  createdAt: string;
};

export type LocalEncryptedMessage = {
  id: string;
  conversationRef: string;
  localCiphertext: string;
  nonce: string;
  createdAt: string;
};

export type RelayClientOptions = {
  relayUrl: string;
};

export class ZuriSecureRelayClient {
  private readonly relayUrl: string;

  constructor(options: RelayClientOptions) {
    this.relayUrl = options.relayUrl.replace(/\/$/, '');
  }

  async createQueue() {
    return this.request('/queues', { method: 'POST' });
  }

  async enqueue(input: {
    queueId: string;
    sendToken: string;
    ciphertext: string;
    nonce?: string;
    clientMessageId?: string;
  }) {
    return this.request('/messages/enqueue', {
      method: 'POST',
      body: JSON.stringify(input),
      headers: { 'content-type': 'application/json' },
    });
  }

  async pull(input: { queueId: string; receiveToken: string; limit?: number }) {
    const params = new URLSearchParams({
      queueId: input.queueId,
      receiveToken: input.receiveToken,
      limit: String(input.limit ?? 50),
    });
    return this.request(`/messages/pull?${params.toString()}`);
  }

  async delivered(input: { messageId: string; queueId: string; receiveToken: string }) {
    return this.request(`/messages/${encodeURIComponent(input.messageId)}/delivered`, {
      method: 'POST',
      body: JSON.stringify({
        queueId: input.queueId,
        receiveToken: input.receiveToken,
      }),
      headers: { 'content-type': 'application/json' },
    });
  }

  private async request(path: string, init?: RequestInit) {
    const response = await fetch(`${this.relayUrl}${path}`, init);
    if (!response.ok) {
      throw new Error(`Relay request failed: ${response.status}`);
    }
    return response.json() as Promise<unknown>;
  }
}

export type RealtimeClientOptions = {
  relayUrl: string;
  queueId: string;
  receiveToken: string;
  onEvent: (event: WsServerEvent) => void;
  onStatus?: (status: 'connecting' | 'open' | 'closed') => void;
  onError?: (error: Error) => void;
};

export class ZuriSecureRealtimeClient {
  private readonly options: RealtimeClientOptions;
  private socket?: WebSocket;

  constructor(options: RealtimeClientOptions) {
    this.options = options;
  }

  connect() {
    this.close();
    this.options.onStatus?.('connecting');
    const url = websocketUrl(this.options.relayUrl, this.options.queueId, this.options.receiveToken);
    const socket = new WebSocket(url);
    this.socket = socket;

    socket.addEventListener('open', () => this.options.onStatus?.('open'));
    socket.addEventListener('close', () => this.options.onStatus?.('closed'));
    socket.addEventListener('error', () => this.options.onError?.(new Error('WebSocket connection failed.')));
    socket.addEventListener('message', (event) => {
      try {
        const payload = JSON.parse(String(event.data));
        this.options.onEvent(wsServerEventSchema.parse(payload));
      } catch (error) {
        this.options.onError?.(error instanceof Error ? error : new Error('Invalid WebSocket event.'));
      }
    });
  }

  send(event: WsClientEvent) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not connected.');
    }
    this.socket.send(JSON.stringify(event));
  }

  close() {
    this.socket?.close();
    this.socket = undefined;
  }
}

export async function generateDeviceKeyPair(): Promise<DeviceKeyPair> {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey'],
  );

  return {
    publicKey: await crypto.subtle.exportKey('jwk', pair.publicKey),
    privateKey: pair.privateKey,
  };
}

export async function importPeerPublicKey(publicKey: JsonWebKey) {
  return crypto.subtle.importKey(
    'jwk',
    publicKey,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    [],
  );
}

export async function deriveConversationKey(privateKey: CryptoKey, peerPublicKey: JsonWebKey) {
  const publicKey = await importPeerPublicKey(peerPublicKey);
  return crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: publicKey,
    },
    privateKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function generateHistoryKey() {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptEnvelope(message: LocalPlaintextMessage, conversationKey: CryptoKey) {
  const parsed = localPlaintextMessageSchema.parse(message);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    conversationKey,
    encoder.encode(JSON.stringify(parsed)),
  );

  return {
    ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
    nonce: encodeBase64Url(nonce),
  };
}

export async function decryptEnvelope(ciphertext: string, nonce: string, conversationKey: CryptoKey) {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: decodeBase64Url(nonce),
    },
    conversationKey,
    decodeBase64Url(ciphertext),
  );

  return localPlaintextMessageSchema.parse(JSON.parse(decoder.decode(plaintext)));
}

export async function exportZuriKeyBackup(password: string, device: DeviceKeyPair, historyKey: CryptoKey) {
  const iterations = 310000;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrappingKey = await derivePasswordKey(password, salt, iterations);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', device.privateKey);
  const historyKeyJwk = await crypto.subtle.exportKey('jwk', historyKey);

  const encryptedPrivateKey = await encryptJson(privateKeyJwk, wrappingKey, nonce);
  const historyNonce = crypto.getRandomValues(new Uint8Array(12));
  const encryptedHistoryKey = await encryptJson(historyKeyJwk, wrappingKey, historyNonce);

  return {
    version: 1,
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: encodeBase64Url(salt),
    nonce: `${encodeBase64Url(nonce)}.${encodeBase64Url(historyNonce)}`,
    encryptedPrivateKey,
    encryptedHistoryKey,
    publicKey: device.publicKey,
    createdAt: new Date().toISOString(),
  } satisfies VaultBackup;
}

export async function importZuriKeyBackup(password: string, backup: VaultBackup) {
  const [privateNonce, historyNonce] = backup.nonce.split('.');
  if (!privateNonce || !historyNonce) {
    throw new Error('Invalid backup nonce.');
  }
  const wrappingKey = await derivePasswordKey(password, decodeBase64Url(backup.salt), backup.iterations);
  const privateKeyJwk = await decryptJson<JsonWebKey>(backup.encryptedPrivateKey, wrappingKey, privateNonce);
  const historyKeyJwk = await decryptJson<JsonWebKey>(backup.encryptedHistoryKey, wrappingKey, historyNonce);

  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateKeyJwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey'],
  );
  const historyKey = await crypto.subtle.importKey('jwk', historyKeyJwk, { name: 'AES-GCM' }, true, [
    'encrypt',
    'decrypt',
  ]);

  return {
    device: {
      publicKey: backup.publicKey,
      privateKey,
    },
    historyKey,
  };
}

export async function openLocalHistoryDb() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(dbName, dbVersion);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('messages')) {
        const store = db.createObjectStore('messages', { keyPath: 'id' });
        store.createIndex('conversationRef', 'conversationRef');
        store.createIndex('createdAt', 'createdAt');
      }
    };
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

export async function saveLocalMessage(input: {
  db: IDBDatabase;
  historyKey: CryptoKey;
  conversationRef: string;
  message: LocalPlaintextMessage;
}) {
  const id = `local_${crypto.randomUUID()}`;
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    input.historyKey,
    encoder.encode(JSON.stringify(localPlaintextMessageSchema.parse(input.message))),
  );
  const record: LocalEncryptedMessage = {
    id,
    conversationRef: input.conversationRef,
    localCiphertext: encodeBase64Url(new Uint8Array(ciphertext)),
    nonce: encodeBase64Url(nonce),
    createdAt: new Date().toISOString(),
  };

  await putRecord(input.db, record);
  return record;
}

export async function listLocalMessages(input: {
  db: IDBDatabase;
  historyKey: CryptoKey;
  conversationRef: string;
}) {
  const records = await getRecords(input.db, input.conversationRef);
  return Promise.all(
    records.map(async (record) => ({
      record,
      message: await decryptLocalRecord(record, input.historyKey),
    })),
  );
}

export async function requestPersistentStorage() {
  if (!navigator.storage?.persist) return false;
  return navigator.storage.persist();
}

export async function createPasskeyCredential(userId: string, userName: string) {
  if (!navigator.credentials?.create) {
    throw new Error('Passkeys are not supported by this browser.');
  }

  return navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'Zuri Secure Chat' },
      user: {
        id: encoder.encode(userId),
        name: userName,
        displayName: userName,
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'preferred',
      },
      timeout: 60000,
    },
  });
}

export async function authenticatePasskey() {
  if (!navigator.credentials?.get) {
    throw new Error('Passkeys are not supported by this browser.');
  }

  return navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: 'required',
      timeout: 60000,
    },
  });
}

async function derivePasswordKey(password: string, salt: WebCryptoBytes, iterations: number) {
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptJson(value: unknown, key: CryptoKey, nonce: WebCryptoBytes) {
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    encoder.encode(JSON.stringify(value)),
  );
  return encodeBase64Url(new Uint8Array(ciphertext));
}

async function decryptJson<T>(ciphertext: string, key: CryptoKey, nonce: string) {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: decodeBase64Url(nonce),
    },
    key,
    decodeBase64Url(ciphertext),
  );
  return JSON.parse(decoder.decode(plaintext)) as T;
}

async function decryptLocalRecord(record: LocalEncryptedMessage, historyKey: CryptoKey) {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: decodeBase64Url(record.nonce),
    },
    historyKey,
    decodeBase64Url(record.localCiphertext),
  );

  return localPlaintextMessageSchema.parse(JSON.parse(decoder.decode(plaintext)));
}

function putRecord(db: IDBDatabase, record: LocalEncryptedMessage) {
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction('messages', 'readwrite');
    tx.objectStore('messages').put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function getRecords(db: IDBDatabase, conversationRef: string) {
  return new Promise<LocalEncryptedMessage[]>((resolve, reject) => {
    const tx = db.transaction('messages', 'readonly');
    const index = tx.objectStore('messages').index('conversationRef');
    const request = index.getAll(conversationRef);
    request.onsuccess = () => resolve(request.result as LocalEncryptedMessage[]);
    request.onerror = () => reject(request.error);
  });
}

function websocketUrl(relayUrl: string, queueId: string, receiveToken: string) {
  const url = new URL(relayUrl.replace(/\/$/, ''));
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = `${url.pathname.replace(/\/$/, '')}/ws`;
  url.searchParams.set('queueId', queueId);
  url.searchParams.set('receiveToken', receiveToken);
  return url.toString();
}

function encodeBase64Url(bytes: Uint8Array) {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(value: string) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
