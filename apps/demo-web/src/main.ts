import {
  decryptEnvelope,
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

type Direction = {
  queueId: string;
  sendToken: string;
  receiveToken: string;
};

type Invite = {
  version: 1;
  relayUrl: string;
  chatKey: JsonWebKey;
  aToB: Direction;
  bToA: Direction;
  createdAt: string;
};

type Role = 'a' | 'b';

type ChatMessage = {
  from: Role;
  text: string;
  createdAt: string;
};

type RelayOverview = {
  generatedAt: string;
  relayStoresPlaintext: boolean;
  totals: {
    queues: number;
    activeQueues: number;
    pendingMessages: number;
    pendingBytes: number;
  };
  queues: Array<{
    queueId: string;
    status: string;
    createdAt: string;
    pendingCount: number;
    pendingBytes: number;
    oldestPendingAt: string | null;
    newestPendingAt: string | null;
    expiresNextAt: string | null;
  }>;
  pendingMessages: Array<{
    id: string;
    queueId: string;
    clientMessageId?: string;
    envelopeVersion: number;
    ciphertextHash: string;
    byteSize: number;
    createdAt: string;
    expiresAt: string;
  }>;
  hourlyMetrics: Array<{
    bucketAt: string;
    metricHash: string;
    enqueuedCount: number;
    deliveredCount: number;
    expiredCount: number;
  }>;
};

type AppState = {
  relayUrl: string;
  adminToken: string;
  role: Role | null;
  inviteText: string;
  messageText: string;
  log: string[];
  ops?: RelayOverview;
  backup?: VaultBackup;
  historyKey?: CryptoKey;
  chatKey?: CryptoKey;
  db?: IDBDatabase;
  invite?: Invite;
};

function defaultRelayUrl() {
  const configured = import.meta.env.VITE_RELAY_URL as string | undefined;
  if (configured) return configured;
  if (window.location.protocol === 'https:') return `${window.location.origin}/relay`;
  return `${window.location.protocol}//${window.location.hostname}:4088`;
}

const state: AppState = {
  relayUrl: defaultRelayUrl(),
  adminToken: 'zuri-demo-admin',
  role: null,
  inviteText: '',
  messageText: 'Oi, testando o Chat Zuri Seguro.',
  log: [],
};

render();

function render() {
  const canChat = Boolean(state.invite && state.role && state.chatKey && state.historyKey && state.db);
  const myName = state.role === 'a' ? 'Pessoa A' : state.role === 'b' ? 'Pessoa B' : 'Ninguem conectado';
  const peerName = state.role === 'a' ? 'Pessoa B' : 'Pessoa A';

  document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
    <section class="hero">
      <span class="eyebrow">Chat Zuri Seguro</span>
      <h1>A conversa precisa parecer simples, mesmo quando a seguranca trabalha pesado.</h1>
      <p>Abra esta pagina em dois navegadores. No primeiro, crie o convite. No segundo, cole o convite. Depois envie e receba mensagens sem o relay ver texto puro.</p>
      <div class="heroLinks">
        <a href="#start">Comecar</a>
        <a href="#observability">Ver fila</a>
        <a href="${escapeHtml(state.relayUrl)}/health" target="_blank" rel="noreferrer">Ver relay</a>
      </div>
    </section>

    <section class="statusBar" aria-label="Estado da conversa">
      <div class="${state.db ? 'ok' : ''}">
        <strong>1</strong>
        <span>Cofre local</span>
      </div>
      <div class="${state.invite ? 'ok' : ''}">
        <strong>2</strong>
        <span>Convite</span>
      </div>
      <div class="${canChat ? 'ok' : ''}">
        <strong>3</strong>
        <span>Conversa</span>
      </div>
    </section>

    <section class="workspace" id="start">
      <aside class="sidePanel">
        <h2>Como testar com duas pessoas</h2>
        <ol>
          <li>Abra esta mesma URL em duas janelas ou dois navegadores.</li>
          <li>Na janela A, clique em <strong>Criar convite</strong>.</li>
          <li>Copie o convite e cole na janela B.</li>
          <li>Na janela B, clique em <strong>Entrar na conversa</strong>.</li>
          <li>Uma janela envia, a outra clica em <strong>Receber agora</strong>.</li>
        </ol>
        <div class="note">
          <strong>O relay so ve:</strong>
          <span>queue_id, tokens e ciphertext. O texto aparece apenas no navegador.</span>
        </div>
      </aside>

      <main class="chatCard">
        <header class="chatHeader">
          <div>
            <span>Voce esta como</span>
            <strong>${escapeHtml(myName)}</strong>
          </div>
          <button class="ghost" id="persist">Guardar melhor neste navegador</button>
        </header>

        <section class="setupGrid">
          <div class="setupBox">
            <h3>Janela A</h3>
            <p>Cria uma conversa nova e gera um convite para a outra pessoa.</p>
            <label>Relay
              <input id="relayUrl" value="${escapeHtml(state.relayUrl)}" />
            </label>
            <button id="createInvite">Criar convite</button>
          </div>

          <div class="setupBox">
            <h3>Janela B</h3>
            <p>Cola o convite recebido para entrar na mesma conversa.</p>
            <label>Convite recebido
              <textarea id="inviteInput" placeholder="Cole aqui o convite da Pessoa A">${escapeHtml(state.inviteText)}</textarea>
            </label>
            <button id="joinInvite">Entrar na conversa</button>
          </div>
        </section>

        ${state.invite ? `
          <section class="inviteBox">
            <div>
              <h3>Convite desta conversa</h3>
              <p>Use este bloco para abrir a segunda janela. Em produto real isso vira link/QR Code com expiracao.</p>
            </div>
            <textarea readonly id="inviteOutput">${escapeHtml(encodeInvite(state.invite))}</textarea>
            <button id="copyInvite">Copiar convite</button>
          </section>
        ` : ''}

        <section class="conversation ${canChat ? '' : 'disabled'}">
          <div class="conversationTop">
            <div>
              <span>Conversa com</span>
              <strong>${escapeHtml(canChat ? peerName : 'aguardando convite')}</strong>
            </div>
            <button class="secondary" id="receive" ${canChat ? '' : 'disabled'}>Receber agora</button>
          </div>

          <div id="messages" class="messages">
            <div class="empty">As mensagens descriptografadas vao aparecer aqui.</div>
          </div>

          <div class="composer">
            <textarea id="messageText" ${canChat ? '' : 'disabled'}>${escapeHtml(state.messageText)}</textarea>
            <button id="send" ${canChat ? '' : 'disabled'}>Enviar criptografado</button>
          </div>
        </section>

        <section class="logPanel">
          <h3>O que aconteceu</h3>
          <pre>${escapeHtml(state.log.join('\n') || 'Nada ainda.')}</pre>
        </section>

        <section class="opsPanel" id="observability">
          <div class="opsHeader">
            <div>
              <h3>Fila do servidor</h3>
              <p>Mostra envelopes pendentes, filas e metricas. Nao mostra ciphertext completo nem texto da conversa.</p>
            </div>
            <button id="refreshOps">Atualizar fila</button>
          </div>
          <label>Token admin da demo
            <input id="adminToken" value="${escapeHtml(state.adminToken)}" />
          </label>
          ${renderOps()}
        </section>
      </main>
    </section>
  `;

  bind();
  refreshLocalMessages();
}

function bind() {
  document.querySelector<HTMLInputElement>('#relayUrl')?.addEventListener('input', (event) => {
    state.relayUrl = (event.target as HTMLInputElement).value;
  });
  document.querySelector<HTMLInputElement>('#adminToken')?.addEventListener('input', (event) => {
    state.adminToken = (event.target as HTMLInputElement).value;
  });
  document.querySelector<HTMLTextAreaElement>('#inviteInput')?.addEventListener('input', (event) => {
    state.inviteText = (event.target as HTMLTextAreaElement).value;
  });
  document.querySelector<HTMLTextAreaElement>('#messageText')?.addEventListener('input', (event) => {
    state.messageText = (event.target as HTMLTextAreaElement).value;
  });
  document.querySelector<HTMLButtonElement>('#createInvite')?.addEventListener('click', () => run(createInvite));
  document.querySelector<HTMLButtonElement>('#joinInvite')?.addEventListener('click', () => run(joinInvite));
  document.querySelector<HTMLButtonElement>('#copyInvite')?.addEventListener('click', () => run(copyInvite));
  document.querySelector<HTMLButtonElement>('#persist')?.addEventListener('click', () => run(persistStorage));
  document.querySelector<HTMLButtonElement>('#send')?.addEventListener('click', () => run(sendMessage));
  document.querySelector<HTMLButtonElement>('#receive')?.addEventListener('click', () => run(receiveMessages));
  document.querySelector<HTMLButtonElement>('#refreshOps')?.addEventListener('click', () => run(refreshOps));
}

async function createInvite() {
  await setupLocalVault();
  const client = new ZuriSecureRelayClient({ relayUrl: state.relayUrl });
  const queues = await Promise.all([client.createQueue(), client.createQueue()]) as [
    { data: Direction },
    { data: Direction },
  ];
  const [aToB, bToA] = queues;
  const chatKey = await generateHistoryKey();
  const invite: Invite = {
    version: 1,
    relayUrl: state.relayUrl,
    chatKey: await crypto.subtle.exportKey('jwk', chatKey),
    aToB: aToB.data,
    bToA: bToA.data,
    createdAt: new Date().toISOString(),
  };

  state.role = 'a';
  state.chatKey = chatKey;
  state.invite = invite;
  state.inviteText = encodeInvite(invite);
  state.log.unshift('Pessoa A criada. Convite pronto para copiar.');
}

async function joinInvite() {
  const invite = decodeInvite(state.inviteText.trim());
  await setupLocalVault();
  state.role = 'b';
  state.relayUrl = invite.relayUrl;
  state.invite = invite;
  state.chatKey = await crypto.subtle.importKey('jwk', invite.chatKey, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  state.log.unshift('Pessoa B entrou. Agora pode enviar e receber mensagens.');
}

async function setupLocalVault() {
  if (state.db && state.historyKey) return;
  if (!crypto.subtle) {
    throw new Error('Seu navegador bloqueou a criacao de chaves neste endereco. Abra pela URL HTTPS da Zuri.');
  }

  const device = await generateDeviceKeyPair();
  const historyKey = await generateHistoryKey();
  const db = await openLocalHistoryDb();
  state.backup = await exportZuriKeyBackup('demo-local-password', device, historyKey);
  state.historyKey = historyKey;
  state.db = db;
  state.log.unshift('Cofre local criado neste navegador.');
}

async function persistStorage() {
  const persisted = await requestPersistentStorage();
  state.log.unshift(`Storage persistente: ${persisted ? 'aceito pelo navegador' : 'nao garantido pelo navegador'}.`);
}

async function copyInvite() {
  if (!state.invite) throw new Error('Crie o convite primeiro.');
  await navigator.clipboard.writeText(encodeInvite(state.invite));
  state.log.unshift('Convite copiado. Cole na outra janela.');
}

async function sendMessage() {
  ensureReady();
  const text = state.messageText.trim();
  if (!text) throw new Error('Escreva uma mensagem antes de enviar.');

  const direction = sendDirection();
  const client = new ZuriSecureRelayClient({ relayUrl: state.invite!.relayUrl });
  const message: ChatMessage = {
    from: state.role!,
    text,
    createdAt: new Date().toISOString(),
  };
  const envelope = await encryptEnvelope(
    {
      kind: 'text',
      body: JSON.stringify(message),
      markdown: false,
      createdAt: message.createdAt,
    },
    state.chatKey!,
  );

  await client.enqueue({
    queueId: direction.queueId,
    sendToken: direction.sendToken,
    ciphertext: envelope.ciphertext,
    nonce: envelope.nonce,
    clientMessageId: crypto.randomUUID(),
  });
  await saveConversationMessage(message);
  state.messageText = '';
  state.log.unshift('Mensagem enviada criptografada. O relay recebeu apenas ciphertext.');
}

async function receiveMessages() {
  ensureReady();
  const direction = receiveDirection();
  const client = new ZuriSecureRelayClient({ relayUrl: state.invite!.relayUrl });
  const response = (await client.pull({
    queueId: direction.queueId,
    receiveToken: direction.receiveToken,
  })) as {
    data: Array<{ id: string; ciphertext: string; nonce: string }>;
  };

  for (const item of response.data) {
    const decrypted = await decryptEnvelope(item.ciphertext, item.nonce, state.chatKey!);
    const message = JSON.parse(decrypted.body ?? '{}') as ChatMessage;
    await saveConversationMessage(message);
    await client.delivered({
      messageId: item.id,
      queueId: direction.queueId,
      receiveToken: direction.receiveToken,
    });
  }

  state.log.unshift(
    response.data.length
      ? `${response.data.length} mensagem(ns) recebida(s), descriptografada(s) localmente e apagada(s) do relay.`
      : 'Nenhuma mensagem nova agora.',
  );
}

async function refreshOps() {
  const response = await fetch(`${state.relayUrl}/admin/overview`, {
    headers: {
      'x-admin-token': state.adminToken,
    },
  });
  if (!response.ok) throw new Error(`Nao consegui ler a fila: ${response.status}`);
  const payload = await response.json() as { data: RelayOverview };
  state.ops = payload.data;
  state.log.unshift('Painel da fila atualizado.');
}

function renderOps() {
  if (!state.ops) {
    return `
      <div class="emptyOps">
        Clique em Atualizar fila para enxergar o que esta pendente no relay.
      </div>
    `;
  }

  return `
    <div class="opsTotals">
      <span><strong>${state.ops.totals.queues}</strong><small>filas</small></span>
      <span><strong>${state.ops.totals.activeQueues}</strong><small>ativas</small></span>
      <span><strong>${state.ops.totals.pendingMessages}</strong><small>pendentes</small></span>
      <span><strong>${formatBytes(state.ops.totals.pendingBytes)}</strong><small>ciphertext</small></span>
    </div>

    <div class="opsGrid">
      <div class="opsTable">
        <h4>Filas</h4>
        ${state.ops.queues.length ? state.ops.queues.map((queue) => `
          <article>
            <div>
              <strong>${escapeHtml(shortId(queue.queueId))}</strong>
              <small>${escapeHtml(queue.status)} · criada ${escapeHtml(formatDate(queue.createdAt))}</small>
            </div>
            <span>${queue.pendingCount} msg · ${formatBytes(queue.pendingBytes)}</span>
          </article>
        `).join('') : '<p>Nenhuma fila criada ainda.</p>'}
      </div>

      <div class="opsTable">
        <h4>Envelopes pendentes</h4>
        ${state.ops.pendingMessages.length ? state.ops.pendingMessages.map((message) => `
          <article>
            <div>
              <strong>${escapeHtml(shortId(message.id))}</strong>
              <small>${escapeHtml(shortId(message.queueId))} · hash ${escapeHtml(message.ciphertextHash.slice(0, 12))}</small>
            </div>
            <span>${formatBytes(message.byteSize)}</span>
          </article>
        `).join('') : '<p>Nenhum envelope pendente. Quando entrega, some do relay.</p>'}
      </div>
    </div>

    <p class="opsFootnote">
      Atualizado em ${escapeHtml(formatDate(state.ops.generatedAt))}. Plaintext no relay: ${state.ops.relayStoresPlaintext ? 'sim' : 'nao'}.
    </p>
  `;
}

async function saveConversationMessage(message: ChatMessage) {
  await saveLocalMessage({
    db: state.db!,
    historyKey: state.historyKey!,
    conversationRef: conversationRef(),
    message: {
      kind: 'text',
      body: JSON.stringify(message),
      markdown: false,
      createdAt: message.createdAt,
    },
  });
}

async function refreshLocalMessages() {
  const element = document.querySelector<HTMLDivElement>('#messages');
  if (!element || !state.db || !state.historyKey || !state.invite) return;

  const records = await listLocalMessages({
    db: state.db,
    historyKey: state.historyKey,
    conversationRef: conversationRef(),
  });
  if (!records.length) return;

  element.innerHTML = records
    .map(({ message }) => {
      const parsed = JSON.parse(message.body ?? '{}') as ChatMessage;
      const mine = parsed.from === state.role;
      return `
        <article class="bubble ${mine ? 'mine' : 'theirs'}">
          <span>${mine ? 'Voce' : parsed.from === 'a' ? 'Pessoa A' : 'Pessoa B'}</span>
          <p>${escapeHtml(parsed.text)}</p>
          <small>${escapeHtml(new Date(parsed.createdAt).toLocaleString())}</small>
        </article>
      `;
    })
    .join('');
}

function sendDirection() {
  if (state.role === 'a') return state.invite!.aToB;
  return state.invite!.bToA;
}

function receiveDirection() {
  if (state.role === 'a') return state.invite!.bToA;
  return state.invite!.aToB;
}

function conversationRef() {
  return `conversation_${state.invite!.aToB.queueId}_${state.invite!.bToA.queueId}`;
}

function ensureReady() {
  if (!state.role || !state.invite || !state.chatKey || !state.historyKey || !state.db) {
    throw new Error('Crie um convite ou entre em uma conversa primeiro.');
  }
}

function encodeInvite(invite: Invite) {
  return btoa(JSON.stringify(invite));
}

function decodeInvite(value: string): Invite {
  try {
    const invite = JSON.parse(atob(value)) as Invite;
    if (!invite.aToB?.queueId || !invite.bToA?.queueId || !invite.chatKey || !invite.relayUrl) {
      throw new Error('Convite incompleto.');
    }
    return invite;
  } catch {
    throw new Error('Convite invalido. Copie o bloco inteiro da janela A.');
  }
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

function shortId(value: string) {
  if (value.length <= 22) return value;
  return `${value.slice(0, 14)}...${value.slice(-5)}`;
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(value: string) {
  return new Date(value).toLocaleString();
}
