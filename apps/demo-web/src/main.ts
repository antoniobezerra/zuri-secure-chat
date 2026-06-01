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
  }>;
  pendingMessages: Array<{
    id: string;
    queueId: string;
    ciphertextHash: string;
    byteSize: number;
    createdAt: string;
    expiresAt: string;
  }>;
};

type AppState = {
  relayUrl: string;
  adminToken: string;
  role: Role | null;
  inviteText: string;
  messageText: string;
  log: string[];
  autoReceive: boolean;
  isPolling: boolean;
  lastPollAt?: string;
  ops?: RelayOverview;
  backup?: VaultBackup;
  historyKey?: CryptoKey;
  chatKey?: CryptoKey;
  db?: IDBDatabase;
  invite?: Invite;
};

let pollTimer: number | undefined;

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
  messageText: '',
  log: [],
  autoReceive: true,
  isPolling: false,
};

render();
syncPolling();

function render() {
  const canChat = isReady();
  const myName = state.role === 'a' ? 'Você: Alice' : state.role === 'b' ? 'Você: Bianca' : 'Sem sessão';
  const peerName = state.role === 'a' ? 'Bianca' : 'Alice';
  const peerSubtitle = canChat
    ? state.autoReceive ? 'online · recebimento automático' : 'online · recebimento manual'
    : 'aguardando convite seguro';

  document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
    <main class="phoneShell">
      <aside class="contactPane">
        <header class="contactHeader">
          <div>
            <strong>Zuri Chat</strong>
            <span>A segurança é nossa. A conversa é sua.</span>
          </div>
          <button class="iconButton" id="persist" title="Guardar melhor neste navegador">↧</button>
        </header>

        <section class="setupCard">
          <h2>Começar conversa</h2>
          <p>Use duas janelas. Uma cria o convite; a outra cola e entra.</p>
          <label>Relay
            <input id="relayUrl" value="${escapeHtml(state.relayUrl)}" />
          </label>
          <div class="setupActions">
            <button id="createInvite">Criar convite</button>
            <button class="secondary" id="copyInvite" ${state.invite ? '' : 'disabled'}>Copiar</button>
          </div>
          <label>Convite recebido
            <textarea id="inviteInput" placeholder="Cole aqui o convite da outra pessoa">${escapeHtml(state.inviteText)}</textarea>
          </label>
          <button class="secondary" id="joinInvite">Entrar na conversa</button>
        </section>

        <section class="contactList" aria-label="Contatos">
          ${renderContact('Bianca', 'Contato seguro', canChat && state.role === 'a', canChat ? 'Chat ativo' : 'Crie ou cole um convite')}
          ${renderContact('Alice', 'Contato seguro', canChat && state.role === 'b', canChat ? 'Chat ativo' : 'Crie ou cole um convite')}
          ${renderContact('Observabilidade', 'Fila do relay', false, `${state.ops?.totals.pendingMessages ?? 0} pendente(s)`)}
        </section>
      </aside>

      <section class="chatPane">
        <header class="chatTop">
          <div class="avatar">${escapeHtml(canChat ? peerName.charAt(0) : 'Z')}</div>
          <div>
            <strong>${escapeHtml(canChat ? peerName : 'Chat seguro')}</strong>
            <span>${escapeHtml(peerSubtitle)}</span>
          </div>
          <div class="chatTopActions">
            <button class="ghost" id="toggleAuto">${state.autoReceive ? 'Auto ligado' : 'Auto desligado'}</button>
            <button class="ghost" id="receive" ${canChat ? '' : 'disabled'}>Receber agora</button>
          </div>
        </header>

        <section class="chatBody">
          ${state.invite ? `
            <details class="inviteDrawer">
              <summary>Convite desta conversa</summary>
              <textarea readonly>${escapeHtml(encodeInvite(state.invite))}</textarea>
            </details>
          ` : ''}
          <div class="notice">
            <strong>${escapeHtml(myName)}</strong>
            <span>O servidor não recebe texto puro. Ele só guarda envelope criptografado até a entrega.</span>
          </div>
          <div id="messages" class="messages">
            <div class="empty">As mensagens aparecem aqui. Envie numa janela e veja chegar na outra automaticamente.</div>
          </div>
        </section>

        <footer class="composer">
          <textarea id="messageText" placeholder="${canChat ? 'Mensagem' : 'Crie ou entre em uma conversa primeiro'}" ${canChat ? '' : 'disabled'}>${escapeHtml(state.messageText)}</textarea>
          <button id="send" ${canChat ? '' : 'disabled'}>Enviar</button>
        </footer>
      </section>

      <aside class="infoPane">
        <section class="opsPanel">
          <div class="opsHeader">
            <div>
              <h2>Fila do servidor</h2>
              <p>Somente metadados: fila, tamanho, hash e contagem.</p>
            </div>
            <button id="refreshOps">Atualizar</button>
          </div>
          <label>Token admin
            <input id="adminToken" value="${escapeHtml(state.adminToken)}" />
          </label>
          ${renderOps()}
        </section>

        <section class="logPanel">
          <h2>Eventos</h2>
          <pre>${escapeHtml(state.log.join('\n') || 'Nada ainda.')}</pre>
        </section>
      </aside>
    </main>
  `;

  bind();
  refreshLocalMessages();
}

function renderContact(name: string, kind: string, active: boolean, meta: string) {
  return `
    <article class="contact ${active ? 'active' : ''}">
      <span class="avatar">${escapeHtml(name.charAt(0))}</span>
      <div>
        <strong>${escapeHtml(name)}</strong>
        <small>${escapeHtml(kind)}</small>
      </div>
      <em>${escapeHtml(meta)}</em>
    </article>
  `;
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
  document.querySelector<HTMLButtonElement>('#receive')?.addEventListener('click', () => run(() => receiveMessages({ announceEmpty: true })));
  document.querySelector<HTMLButtonElement>('#refreshOps')?.addEventListener('click', () => run(refreshOps));
  document.querySelector<HTMLButtonElement>('#toggleAuto')?.addEventListener('click', () => {
    state.autoReceive = !state.autoReceive;
    state.log.unshift(state.autoReceive ? 'Recebimento automático ligado.' : 'Recebimento automático desligado.');
    syncPolling();
    render();
  });
  document.querySelector<HTMLTextAreaElement>('#messageText')?.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void run(sendMessage);
    }
  });
}

async function createInvite() {
  await setupLocalVault();
  const client = new ZuriSecureRelayClient({ relayUrl: state.relayUrl });
  const queues = await Promise.all([client.createQueue(), client.createQueue()]) as [
    { data: Direction },
    { data: Direction },
  ];
  const chatKey = await generateHistoryKey();
  const invite: Invite = {
    version: 1,
    relayUrl: state.relayUrl,
    chatKey: await crypto.subtle.exportKey('jwk', chatKey),
    aToB: queues[0].data,
    bToA: queues[1].data,
    createdAt: new Date().toISOString(),
  };

  state.role = 'a';
  state.chatKey = chatKey;
  state.invite = invite;
  state.inviteText = encodeInvite(invite);
  state.log.unshift('Convite criado. Copie e cole na segunda janela.');
  syncPolling();
}

async function joinInvite() {
  const invite = decodeInvite(state.inviteText.trim());
  await setupLocalVault();
  state.role = 'b';
  state.relayUrl = invite.relayUrl;
  state.invite = invite;
  state.chatKey = await crypto.subtle.importKey('jwk', invite.chatKey, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  state.log.unshift('Você entrou na conversa. O recebimento automático está ligado.');
  syncPolling();
}

async function setupLocalVault() {
  if (state.db && state.historyKey) return;
  if (!crypto.subtle) {
    throw new Error('Seu navegador bloqueou a criação de chaves neste endereço. Abra pela URL HTTPS da Zuri.');
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
  state.log.unshift(`Storage persistente: ${persisted ? 'aceito pelo navegador' : 'não garantido pelo navegador'}.`);
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
  state.log.unshift('Mensagem enviada. O servidor recebeu só ciphertext.');
  void refreshOps().catch(() => undefined);
}

async function receiveMessages(options: { announceEmpty?: boolean; silent?: boolean } = {}) {
  ensureReady();
  if (state.isPolling) return;
  state.isPolling = true;
  try {
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

    state.lastPollAt = new Date().toISOString();
    if (response.data.length) {
      state.log.unshift(`${response.data.length} mensagem(ns) recebida(s) automaticamente e apagada(s) do relay.`);
      await refreshOps().catch(() => undefined);
      render();
    } else if (options.announceEmpty && !options.silent) {
      state.log.unshift('Nenhuma mensagem nova agora.');
    }
  } finally {
    state.isPolling = false;
  }
}

async function refreshOps() {
  const response = await fetch(`${state.relayUrl}/admin/overview`, {
    headers: { 'x-admin-token': state.adminToken },
  });
  if (!response.ok) throw new Error(`Não consegui ler a fila: ${response.status}`);
  const payload = await response.json() as { data: RelayOverview };
  state.ops = payload.data;
}

function renderOps() {
  if (!state.ops) {
    return `<div class="emptyOps">Clique em Atualizar para enxergar a fila do relay.</div>`;
  }

  return `
    <div class="opsTotals">
      <span><strong>${state.ops.totals.queues}</strong><small>filas</small></span>
      <span><strong>${state.ops.totals.pendingMessages}</strong><small>pendentes</small></span>
      <span><strong>${formatBytes(state.ops.totals.pendingBytes)}</strong><small>ciphertext</small></span>
    </div>
    <div class="opsTable">
      ${state.ops.pendingMessages.length ? state.ops.pendingMessages.map((message) => `
        <article>
          <div>
            <strong>${escapeHtml(shortId(message.id))}</strong>
            <small>${escapeHtml(shortId(message.queueId))} · hash ${escapeHtml(message.ciphertextHash.slice(0, 12))}</small>
          </div>
          <span>${formatBytes(message.byteSize)}</span>
        </article>
      `).join('') : '<p>Nenhum envelope pendente. Quando entrega, some.</p>'}
    </div>
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
          <p>${escapeHtml(parsed.text)}</p>
          <small>${escapeHtml(new Date(parsed.createdAt).toLocaleTimeString())}</small>
        </article>
      `;
    })
    .join('');
  element.scrollTop = element.scrollHeight;
}

function syncPolling() {
  if (pollTimer) {
    window.clearInterval(pollTimer);
    pollTimer = undefined;
  }
  if (!state.autoReceive) return;

  pollTimer = window.setInterval(() => {
    if (document.hidden || !isReady()) return;
    void receiveMessages({ silent: true }).catch((error) => {
      state.log.unshift(error instanceof Error ? error.message : 'Falha ao buscar mensagens.');
      render();
    });
  }, 2500);
}

function sendDirection() {
  return state.role === 'a' ? state.invite!.aToB : state.invite!.bToA;
}

function receiveDirection() {
  return state.role === 'a' ? state.invite!.bToA : state.invite!.aToB;
}

function conversationRef() {
  return `conversation_${state.invite!.aToB.queueId}_${state.invite!.bToA.queueId}`;
}

function isReady() {
  return Boolean(state.role && state.invite && state.chatKey && state.historyKey && state.db);
}

function ensureReady() {
  if (!isReady()) throw new Error('Crie um convite ou entre em uma conversa primeiro.');
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
    throw new Error('Convite inválido. Copie o bloco inteiro da outra janela.');
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
  if (value.length <= 20) return value;
  return `${value.slice(0, 12)}...${value.slice(-5)}`;
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}
