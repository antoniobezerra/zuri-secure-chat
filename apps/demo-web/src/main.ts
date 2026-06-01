import {
  encryptEnvelope,
  exportZuriKeyBackup,
  generateDeviceKeyPair,
  generateHistoryKey,
  listLocalMessages,
  openLocalHistoryDb,
  requestPersistentStorage,
  saveLocalMessage,
  ZuriSecureRelayClient,
  type VaultBackup,
} from '@zuri-secure-chat/web-sdk';
import './style.css';

type AppState = {
  relayUrl: string;
  queueId: string;
  sendToken: string;
  receiveToken: string;
  password: string;
  plaintext: string;
  log: string[];
  backup?: VaultBackup;
  historyKey?: CryptoKey;
  db?: IDBDatabase;
};

function defaultRelayUrl() {
  const configured = import.meta.env.VITE_RELAY_URL as string | undefined;
  if (configured) return configured;
  return `${window.location.protocol}//${window.location.hostname}:4088`;
}

const state: AppState = {
  relayUrl: defaultRelayUrl(),
  queueId: '',
  sendToken: '',
  receiveToken: '',
  password: 'demo-local-password',
  plaintext: 'Oi. Esta mensagem sera criptografada antes de ir para o relay.',
  log: [],
};

render();

function render() {
  document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
    <section class="hero">
      <p>Chat Zuri Seguro</p>
      <h1>A seguranca e nossa. A conversa e sua.</h1>
      <p>Demo PWA: o relay guarda ciphertext somente ate a entrega; o historico local fica criptografado em IndexedDB.</p>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>1. Cofre local</h2>
        <label>Senha local do backup .zuri-key
          <input id="password" value="${escapeHtml(state.password)}" />
        </label>
        <div class="actions">
          <button id="setup">Gerar chaves locais</button>
          <button class="secondary" id="persist">Pedir storage persistente</button>
        </div>
      </div>

      <div class="panel">
        <h2>2. Fila anonima</h2>
        <label>Relay URL
          <input id="relayUrl" value="${escapeHtml(state.relayUrl)}" />
        </label>
        <div class="actions">
          <button id="createQueue">Criar fila</button>
        </div>
      </div>

      <div class="panel full">
        <h2>3. Enviar envelope criptografado</h2>
        <label>Mensagem local
          <textarea id="plaintext">${escapeHtml(state.plaintext)}</textarea>
        </label>
        <div class="actions">
          <button id="send">Criptografar e enviar</button>
          <button class="secondary" id="pull">Puxar, descriptografar localmente e apagar do relay</button>
        </div>
      </div>

      <div class="panel">
        <h2>Estado</h2>
        <pre>${escapeHtml(JSON.stringify({
          queueId: state.queueId || null,
          hasSendToken: Boolean(state.sendToken),
          hasReceiveToken: Boolean(state.receiveToken),
          hasLocalVault: Boolean(state.historyKey),
          hasBackup: Boolean(state.backup),
        }, null, 2))}</pre>
      </div>

      <div class="panel">
        <h2>Log</h2>
        <pre>${escapeHtml(state.log.join('\\n'))}</pre>
      </div>

      <div class="panel full">
        <h2>Historico local criptografado</h2>
        <div id="messages" class="messages"></div>
      </div>
    </section>
  `;

  bind();
  refreshLocalMessages();
}

function bind() {
  document.querySelector<HTMLInputElement>('#password')!.addEventListener('input', (event) => {
    state.password = (event.target as HTMLInputElement).value;
  });
  document.querySelector<HTMLInputElement>('#relayUrl')!.addEventListener('input', (event) => {
    state.relayUrl = (event.target as HTMLInputElement).value;
  });
  document.querySelector<HTMLTextAreaElement>('#plaintext')!.addEventListener('input', (event) => {
    state.plaintext = (event.target as HTMLTextAreaElement).value;
  });
  document.querySelector<HTMLButtonElement>('#setup')!.addEventListener('click', () => run(setupVault));
  document.querySelector<HTMLButtonElement>('#persist')!.addEventListener('click', () => run(persistStorage));
  document.querySelector<HTMLButtonElement>('#createQueue')!.addEventListener('click', () => run(createQueue));
  document.querySelector<HTMLButtonElement>('#send')!.addEventListener('click', () => run(sendMessage));
  document.querySelector<HTMLButtonElement>('#pull')!.addEventListener('click', () => run(pullMessages));
}

async function setupVault() {
  const device = await generateDeviceKeyPair();
  const historyKey = await generateHistoryKey();
  const db = await openLocalHistoryDb();
  state.backup = await exportZuriKeyBackup(state.password, device, historyKey);
  state.historyKey = historyKey;
  state.db = db;
  state.log.unshift('Cofre local criado. Backup .zuri-key gerado em memoria para demo.');
}

async function persistStorage() {
  const persisted = await requestPersistentStorage();
  state.log.unshift(`Storage persistente: ${persisted ? 'aceito' : 'nao garantido pelo navegador'}.`);
}

async function createQueue() {
  const client = new ZuriSecureRelayClient({ relayUrl: state.relayUrl });
  const response = (await client.createQueue()) as {
    data: { queueId: string; sendToken: string; receiveToken: string };
  };
  state.queueId = response.data.queueId;
  state.sendToken = response.data.sendToken;
  state.receiveToken = response.data.receiveToken;
  state.log.unshift('Fila anonima criada. Tokens existem somente no cliente demo.');
}

async function sendMessage() {
  ensureReady();
  const client = new ZuriSecureRelayClient({ relayUrl: state.relayUrl });
  const envelope = await encryptEnvelope(
    {
      kind: 'text',
      body: state.plaintext,
      markdown: true,
      createdAt: new Date().toISOString(),
    },
    state.historyKey!,
  );
  await client.enqueue({
    queueId: state.queueId,
    sendToken: state.sendToken,
    ciphertext: envelope.ciphertext,
    nonce: envelope.nonce,
    clientMessageId: crypto.randomUUID(),
  });
  await saveLocalMessage({
    db: state.db!,
    historyKey: state.historyKey!,
    conversationRef: state.queueId,
    message: {
      kind: 'text',
      body: state.plaintext,
      markdown: true,
      createdAt: new Date().toISOString(),
    },
  });
  state.log.unshift('Mensagem criptografada enviada. Relay recebeu apenas ciphertext.');
}

async function pullMessages() {
  ensureReady();
  const client = new ZuriSecureRelayClient({ relayUrl: state.relayUrl });
  const response = (await client.pull({
    queueId: state.queueId,
    receiveToken: state.receiveToken,
  })) as {
    data: Array<{ id: string; ciphertext: string; nonce: string }>;
  };

  for (const item of response.data) {
    await saveLocalMessage({
      db: state.db!,
      historyKey: state.historyKey!,
      conversationRef: state.queueId,
      message: {
        kind: 'event',
        markdown: false,
        event: {
          name: 'relay.received_ciphertext',
          payload: { messageId: item.id, ciphertextBytes: item.ciphertext.length },
        },
        createdAt: new Date().toISOString(),
      },
    });
    await client.delivered({
      messageId: item.id,
      queueId: state.queueId,
      receiveToken: state.receiveToken,
    });
  }

  state.log.unshift(`${response.data.length} envelope(s) puxado(s) e apagado(s) do relay.`);
}

async function refreshLocalMessages() {
  const element = document.querySelector<HTMLDivElement>('#messages');
  if (!element || !state.db || !state.historyKey || !state.queueId) return;

  const messages = await listLocalMessages({
    db: state.db,
    historyKey: state.historyKey,
    conversationRef: state.queueId,
  });
  element.innerHTML = messages
    .map(
      ({ message, record }) => `
        <div class="message">
          <strong>${escapeHtml(message.kind)}</strong>
          <p>${escapeHtml(message.body ?? message.event?.name ?? 'evento local')}</p>
          <small>${escapeHtml(record.createdAt)} · salvo criptografado em IndexedDB</small>
        </div>
      `,
    )
    .join('');
}

function ensureReady() {
  if (!state.historyKey || !state.db) throw new Error('Gere o cofre local primeiro.');
  if (!state.queueId || !state.sendToken || !state.receiveToken) throw new Error('Crie uma fila anonima primeiro.');
}

async function run(action: () => Promise<void>) {
  try {
    await action();
  } catch (error) {
    state.log.unshift(error instanceof Error ? error.message : 'Erro desconhecido.');
  }
  render();
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
