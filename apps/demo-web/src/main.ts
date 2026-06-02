import {
  decryptEnvelope,
  encryptEnvelope,
  exportZuriKeyBackup,
  generateDeviceKeyPair,
  generateHistoryKey,
  importZuriKeyBackup,
  listLocalMessages,
  openLocalHistoryDb,
  requestPersistentStorage,
  saveLocalMessage,
  ZuriSecureRealtimeClient,
  ZuriSecureRelayClient,
  type VaultBackup,
} from '@zuri-secure-chat/web-sdk';
import type { QueuedMessage, RelayConnectionBundle, WsServerEvent } from '@zuri-secure-chat/protocol';
import './style.css';

type Direction = {
  queueId: string;
  sendToken: string;
  receiveToken: string;
};

type Invite = {
  version: 1;
  inviteId: string;
  relayUrl: string;
  chatKey: JsonWebKey;
  aToB: Direction;
  bToA: Direction;
  expiresAt: string;
  createdAt: string;
  securityCode: string;
};

type InviteLinkPayload = {
  version: 1;
  inviteId: string;
  relayUrl: string;
  inviteSecret: string;
  chatKey: JsonWebKey;
  expiresAt: string;
};

type PendingInvite = {
  inviteId: string;
  relayUrl: string;
  creatorClaimToken: string;
  chatKey: JsonWebKey;
  expiresAt: string;
};

type Role = 'a' | 'b';

type ChatMessage = {
  from: Role;
  text: string;
  createdAt: string;
  clientMessageId?: string;
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
  vaultUnlocked: boolean;
  vaultPasswordInput: string;
  vaultPasswordVisible: boolean;
  role: Role | null;
  inviteText: string;
  messageText: string;
  log: string[];
  autoReceive: boolean;
  isPolling: boolean;
  realtimeStatus: 'offline' | 'connecting' | 'online';
  lastPollAt?: string;
  ops?: RelayOverview;
  backup?: VaultBackup;
  historyKey?: CryptoKey;
  chatKey?: CryptoKey;
  db?: IDBDatabase;
  invite?: Invite;
  pendingInvite?: PendingInvite;
};

const vaultBackupKey = 'zuri-secure-chat:vault-backup';
const vaultPasswordMinLength = 14;

let pollTimer: number | undefined;
let claimTimer: number | undefined;
let realtimeClient: ZuriSecureRealtimeClient | undefined;
const sentStatuses = new Map<string, 'sending' | 'stored' | 'delivered'>();

function defaultRelayUrl() {
  const configured = import.meta.env.VITE_RELAY_URL as string | undefined;
  if (configured) return configured;
  if (window.location.protocol === 'https:') return `${window.location.origin}/relay`;
  return `${window.location.protocol}//${window.location.hostname}:4088`;
}

const state: AppState = {
  relayUrl: defaultRelayUrl(),
  adminToken: 'zuri-demo-admin',
  vaultUnlocked: false,
  vaultPasswordInput: '',
  vaultPasswordVisible: false,
  role: null,
  inviteText: inviteTextFromLocation(),
  messageText: '',
  log: [],
  autoReceive: true,
  isPolling: false,
  realtimeStatus: 'offline',
};

render();
syncRealtime();
bindVaultAutoLock();

function render() {
  const canChat = isReady();
  const hasBackup = hasVaultBackup();
  const myName = state.role === 'a' ? 'Você: Alice' : state.role === 'b' ? 'Você: Bianca' : 'Sem sessão';
  const peerName = state.role === 'a' ? 'Bianca' : 'Alice';
  const peerSubtitle = canChat
    ? state.autoReceive ? `${realtimeLabel()} · WebSocket` : 'online · recebimento manual'
    : state.pendingInvite ? 'aguardando a outra pessoa aceitar' : 'aguardando convite seguro';

  document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
    <main class="phoneShell">
      <aside class="contactPane">
        <header class="contactHeader">
          <div class="brandLock">Z</div>
          <div class="brandCopy">
            <strong>Zuri Chat</strong>
            <span>A segurança é nossa. A conversa é sua.</span>
          </div>
          <button class="iconButton" id="lockVault" title="${state.vaultUnlocked ? 'Bloquear cofre local' : 'Cofre bloqueado'}">${state.vaultUnlocked ? '×' : '⌁'}</button>
        </header>

        <section class="vaultCard ${state.vaultUnlocked ? 'unlocked' : ''}">
          <div class="sectionTitle">
            <h2>Cofre local</h2>
            <span>${state.vaultUnlocked ? 'Aberto' : 'Bloqueado'}</span>
          </div>
          <p>${state.vaultUnlocked ? 'Chaves carregadas só na memória desta sessão.' : 'Digite sua senha local para liberar chaves e histórico.'}</p>
          ${state.vaultUnlocked ? `
            <button class="secondary" id="persist">Guardar storage do navegador</button>
          ` : `
            <label>Senha do cofre
              <span class="passwordField">
                <input id="vaultPassword" type="${state.vaultPasswordVisible ? 'text' : 'password'}" autocomplete="off" placeholder="Mínimo ${vaultPasswordMinLength} caracteres" value="${escapeHtml(state.vaultPasswordInput)}" />
                <button class="passwordToggle" id="toggleVaultPassword" type="button" aria-label="${state.vaultPasswordVisible ? 'Ocultar senha' : 'Mostrar senha'}" title="${state.vaultPasswordVisible ? 'Ocultar senha' : 'Mostrar senha'}">
                  ${renderEyeIcon(state.vaultPasswordVisible)}
                </button>
              </span>
            </label>
            <button id="unlockVault">Desbloquear cofre</button>
          `}
          <div class="vaultActions">
            <button class="secondary" id="exportVault" ${hasBackup ? '' : 'disabled'}>Exportar chave</button>
            <button class="secondary" id="importVault">Importar chave</button>
            <input class="fileInput" id="importVaultFile" type="file" accept=".zuri-key,application/json" />
          </div>
          <small>Exporta só o pacote criptografado. A senha e as chaves abertas não saem do dispositivo.</small>
        </section>

        <section class="setupCard">
          <div class="sectionTitle">
            <h2>Começar conversa</h2>
            <span>One-time</span>
          </div>
          <p>Use duas janelas. Uma cria o convite; a outra cola e entra.</p>
          <label>Relay
            <input id="relayUrl" value="${escapeHtml(state.relayUrl)}" />
          </label>
          <div class="setupActions">
            <button id="createInvite" ${state.vaultUnlocked ? '' : 'disabled'}>Criar convite</button>
            <button class="secondary" id="copyInvite" ${state.inviteText ? '' : 'disabled'}>Copiar</button>
          </div>
          <label>Convite recebido
            <textarea id="inviteInput" placeholder="Cole aqui o link one-time da outra pessoa">${escapeHtml(state.inviteText)}</textarea>
          </label>
          <button class="secondary" id="joinInvite" ${state.vaultUnlocked ? '' : 'disabled'}>Entrar na conversa</button>
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
            <span class="presence"><i></i>${escapeHtml(peerSubtitle)}</span>
          </div>
          <div class="chatTopActions">
            <button class="ghost" id="toggleAuto">${state.autoReceive ? 'WS ligado' : 'WS desligado'}</button>
            <button class="ghost" id="receive" ${canChat ? '' : 'disabled'}>Receber agora</button>
          </div>
        </header>

        <section class="chatBody">
          ${state.invite || state.pendingInvite ? `
            <details class="inviteDrawer">
              <summary>Convite one-time desta conversa</summary>
              <textarea readonly>${escapeHtml(state.inviteText)}</textarea>
            </details>
          ` : ''}
          <div class="notice">
            <strong>${escapeHtml(myName)}</strong>
            <span>O servidor não recebe texto puro.</span>
            <em>${escapeHtml(state.invite?.securityCode ?? 'aguardando')}</em>
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
      <em><i></i>${escapeHtml(meta)}</em>
    </article>
  `;
}

function bind() {
  document.querySelector<HTMLInputElement>('#vaultPassword')?.addEventListener('input', (event) => {
    state.vaultPasswordInput = (event.target as HTMLInputElement).value;
  });
  document.querySelector<HTMLInputElement>('#vaultPassword')?.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      void run(unlockVault);
    }
  });
  document.querySelector<HTMLButtonElement>('#toggleVaultPassword')?.addEventListener('click', () => {
    state.vaultPasswordVisible = !state.vaultPasswordVisible;
    render();
    document.querySelector<HTMLInputElement>('#vaultPassword')?.focus();
  });
  document.querySelector<HTMLButtonElement>('#unlockVault')?.addEventListener('click', () => run(unlockVault));
  document.querySelector<HTMLButtonElement>('#exportVault')?.addEventListener('click', () => run(exportVaultBackupFile));
  document.querySelector<HTMLButtonElement>('#importVault')?.addEventListener('click', () => {
    document.querySelector<HTMLInputElement>('#importVaultFile')?.click();
  });
  document.querySelector<HTMLInputElement>('#importVaultFile')?.addEventListener('change', (event) => {
    void run(() => importVaultBackupFile(event));
  });
  document.querySelector<HTMLButtonElement>('#lockVault')?.addEventListener('click', () => {
    if (state.vaultUnlocked) lockVault('Cofre bloqueado manualmente.');
  });
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
    state.log.unshift(state.autoReceive ? 'WebSocket ligado.' : 'WebSocket desligado.');
    syncRealtime();
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
  const response = (await client.createInvite()) as {
    data: {
      inviteId: string;
      inviteSecret: string;
      creatorClaimToken: string;
      expiresAt: string;
    };
  };
  const chatKey = await generateHistoryKey();
  const chatKeyJwk = await crypto.subtle.exportKey('jwk', chatKey);

  state.role = 'a';
  state.chatKey = chatKey;
  state.invite = undefined;
  state.pendingInvite = {
    inviteId: response.data.inviteId,
    relayUrl: state.relayUrl,
    creatorClaimToken: response.data.creatorClaimToken,
    chatKey: chatKeyJwk,
    expiresAt: response.data.expiresAt,
  };
  state.inviteText = encodeInviteLink({
    version: 1,
    inviteId: response.data.inviteId,
    relayUrl: state.relayUrl,
    inviteSecret: response.data.inviteSecret,
    chatKey: chatKeyJwk,
    expiresAt: response.data.expiresAt,
  });
  state.log.unshift('Convite one-time criado. Aguardando a outra janela aceitar para abrir o chat.');
  syncClaiming();
}

async function joinInvite() {
  const inviteLink = decodeInviteLink(state.inviteText.trim());
  await setupLocalVault();
  const client = new ZuriSecureRelayClient({ relayUrl: inviteLink.relayUrl });
  const accepted = await client.acceptInvite({
    inviteId: inviteLink.inviteId,
    inviteSecret: inviteLink.inviteSecret,
  });
  const securityCode = await conversationSecurityCode(accepted.data.bundle, inviteLink.chatKey);
  const invite: Invite = {
    version: 1,
    inviteId: accepted.data.inviteId,
    relayUrl: inviteLink.relayUrl,
    chatKey: inviteLink.chatKey,
    aToB: accepted.data.bundle.aToB,
    bToA: accepted.data.bundle.bToA,
    expiresAt: inviteLink.expiresAt,
    createdAt: accepted.data.consumedAt,
    securityCode,
  };
  state.role = 'b';
  state.relayUrl = inviteLink.relayUrl;
  state.invite = invite;
  state.chatKey = await crypto.subtle.importKey('jwk', inviteLink.chatKey, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  state.log.unshift('Convite aceito. Se outra pessoa tentar usar o mesmo link, o relay recusa.');
  syncRealtime();
}

async function setupLocalVault() {
  if (state.db && state.historyKey) return;
  if (!state.vaultUnlocked) {
    throw new Error('Desbloqueie o cofre local antes de abrir ou criar conversa.');
  }
}

async function unlockVault() {
  const password = state.vaultPasswordInput;
  validateVaultPassword(password);
  if (!crypto.subtle) {
    throw new Error('Seu navegador bloqueou a criação de chaves neste endereço. Abra pela URL HTTPS da Zuri.');
  }

  const storedBackup = localStorage.getItem(vaultBackupKey);
  const db = await openLocalHistoryDb();
  if (storedBackup) {
    const backup = JSON.parse(storedBackup) as VaultBackup;
    const imported = await importZuriKeyBackup(password, backup);
    state.backup = backup;
    state.historyKey = imported.historyKey;
  } else {
    const device = await generateDeviceKeyPair();
    const historyKey = await generateHistoryKey();
    const backup = await exportZuriKeyBackup(password, device, historyKey);
    localStorage.setItem(vaultBackupKey, JSON.stringify(backup));
    state.backup = backup;
    state.historyKey = historyKey;
  }
  state.db = db;
  state.vaultUnlocked = true;
  state.vaultPasswordInput = '';
  state.vaultPasswordVisible = false;
  state.log.unshift('Cofre local desbloqueado. A senha não foi salva.');
}

async function persistStorage() {
  const persisted = await requestPersistentStorage();
  state.log.unshift(`Storage persistente: ${persisted ? 'aceito pelo navegador' : 'não garantido pelo navegador'}.`);
}

async function exportVaultBackupFile() {
  const backup = state.backup ?? readVaultBackupFromStorage();
  if (!backup) throw new Error('Nenhum cofre local encontrado para exportar.');

  const text = `${JSON.stringify(backup, null, 2)}\n`;
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const date = new Date().toISOString().slice(0, 10);
  link.href = url;
  link.download = `zuri-vault-${date}.zuri-key`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  state.log.unshift('Backup criptografado exportado em arquivo .zuri-key.');
}

async function importVaultBackupFile(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;

  try {
    const backup = parseVaultBackup(await file.text());
    localStorage.setItem(vaultBackupKey, JSON.stringify(backup));
    if (state.vaultUnlocked) {
      lockVault('Cofre bloqueado para carregar o backup importado.');
    }
    state.backup = backup;
    state.log.unshift('Backup importado. Digite a senha desse arquivo para desbloquear.');
  } finally {
    input.value = '';
  }
}

async function copyInvite() {
  if (!state.inviteText) throw new Error('Crie o convite primeiro.');
  await navigator.clipboard.writeText(state.inviteText);
  state.log.unshift('Link one-time copiado. Cole na outra janela.');
}

async function sendMessage() {
  ensureReady();
  const text = state.messageText.trim();
  if (!text) throw new Error('Escreva uma mensagem antes de enviar.');

  const direction = sendDirection();
  const client = new ZuriSecureRelayClient({ relayUrl: state.invite!.relayUrl });
  const clientMessageId = crypto.randomUUID();
  const message: ChatMessage = {
    from: state.role!,
    text,
    createdAt: new Date().toISOString(),
    clientMessageId,
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

  sentStatuses.set(clientMessageId, 'sending');
  await saveConversationMessage(message);
  if (realtimeClient && state.realtimeStatus === 'online') {
    realtimeClient.send({
      type: 'message.send',
      queueId: direction.queueId,
      sendToken: direction.sendToken,
      ciphertext: envelope.ciphertext,
      nonce: envelope.nonce,
      envelopeVersion: 1,
      clientMessageId,
    });
  } else {
    await client.enqueue({
      queueId: direction.queueId,
      sendToken: direction.sendToken,
      ciphertext: envelope.ciphertext,
      nonce: envelope.nonce,
      clientMessageId,
    });
    sentStatuses.set(clientMessageId, 'stored');
  }
  state.messageText = '';
  state.log.unshift('Mensagem enviada criptografada. Aguardando recibo do relay.');
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
      await storeReceivedMessage(item);
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

async function storeReceivedMessage(item: Pick<QueuedMessage, 'ciphertext' | 'nonce'>) {
  if (!item.nonce) throw new Error('Envelope sem nonce.');
  const decrypted = await decryptEnvelope(item.ciphertext, item.nonce, state.chatKey!);
  const message = JSON.parse(decrypted.body ?? '{}') as ChatMessage;
  await saveConversationMessage(message);
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
      const status = mine && parsed.clientMessageId ? sentStatuses.get(parsed.clientMessageId) ?? 'stored' : undefined;
      return `
        <article class="bubble ${mine ? 'mine' : 'theirs'}">
          <p>${escapeHtml(parsed.text)}</p>
          <small>${escapeHtml(new Date(parsed.createdAt).toLocaleTimeString())}${status ? ` · ${renderReceipt(status)}` : ''}</small>
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

function syncRealtime() {
  realtimeClient?.close();
  realtimeClient = undefined;

  if (!state.autoReceive || !isReady()) {
    state.realtimeStatus = 'offline';
    return;
  }

  const direction = receiveDirection();
  realtimeClient = new ZuriSecureRealtimeClient({
    relayUrl: state.invite!.relayUrl,
    queueId: direction.queueId,
    receiveToken: direction.receiveToken,
    onStatus: (status) => {
      state.realtimeStatus = status === 'open' ? 'online' : status === 'connecting' ? 'connecting' : 'offline';
      render();
    },
    onError: (error) => {
      state.log.unshift(error.message);
      render();
    },
    onEvent: (event) => {
      void handleRealtimeEvent(event).catch((error) => {
        state.log.unshift(error instanceof Error ? error.message : 'Falha no WebSocket.');
        render();
      });
    },
  });
  realtimeClient.connect();
}

function lockVault(reason = 'Cofre local bloqueado.') {
  realtimeClient?.close();
  realtimeClient = undefined;
  if (claimTimer) window.clearInterval(claimTimer);
  claimTimer = undefined;
  state.vaultUnlocked = false;
  state.vaultPasswordInput = '';
  state.vaultPasswordVisible = false;
  state.realtimeStatus = 'offline';
  state.historyKey = undefined;
  state.chatKey = undefined;
  state.db?.close();
  state.db = undefined;
  state.invite = undefined;
  state.pendingInvite = undefined;
  state.role = null;
  state.messageText = '';
  state.log.unshift(reason);
  render();
}

function bindVaultAutoLock() {
  window.addEventListener('pagehide', () => {
    if (state.vaultUnlocked) lockVault('Cofre bloqueado ao sair da página.');
  });
}

function syncClaiming() {
  if (claimTimer) {
    window.clearInterval(claimTimer);
    claimTimer = undefined;
  }
  if (!state.pendingInvite) return;

  claimTimer = window.setInterval(() => {
    if (document.hidden || !state.pendingInvite) return;
    void claimCreatorBundle().catch((error) => {
      const message = error instanceof Error ? error.message : 'Falha ao verificar aceite.';
      if (!message.includes('409')) {
        state.log.unshift(message);
        render();
      }
    });
  }, 2000);
  void claimCreatorBundle().catch(() => undefined);
}

async function claimCreatorBundle() {
  if (!state.pendingInvite || !state.chatKey) return;
  const pending = state.pendingInvite;
  const client = new ZuriSecureRelayClient({ relayUrl: pending.relayUrl });
  const claimed = await client.claimInvite({
    inviteId: pending.inviteId,
    creatorClaimToken: pending.creatorClaimToken,
  });
  if (claimTimer) {
    window.clearInterval(claimTimer);
    claimTimer = undefined;
  }
  const securityCode = await conversationSecurityCode(claimed.data.bundle, pending.chatKey);
  state.invite = {
    version: 1,
    inviteId: claimed.data.inviteId,
    relayUrl: pending.relayUrl,
    chatKey: pending.chatKey,
    aToB: claimed.data.bundle.aToB,
    bToA: claimed.data.bundle.bToA,
    expiresAt: pending.expiresAt,
    createdAt: claimed.data.claimedAt,
    securityCode,
  };
  state.pendingInvite = undefined;
  state.log.unshift('A outra janela aceitou. Chat conectado com convite one-time consumido.');
  syncRealtime();
  render();
}

async function handleRealtimeEvent(event: WsServerEvent) {
  if (event.type === 'ready') {
    state.log.unshift(`WebSocket pronto. ${event.pending} envelope(s) pendente(s).`);
    return;
  }

  if (event.type === 'message.stored') {
    sentStatuses.set(event.clientMessageId, 'stored');
    state.log.unshift(`✓ enviada: ${shortId(event.clientMessageId)}`);
    void refreshOps().catch(() => undefined);
    render();
    return;
  }

  if (event.type === 'message.delivered') {
    if (event.clientMessageId) sentStatuses.set(event.clientMessageId, 'delivered');
    state.log.unshift(`✓✓ entregue: ${shortId(event.clientMessageId ?? event.messageId)}`);
    void refreshOps().catch(() => undefined);
    render();
    return;
  }

  if (event.type === 'message.deliver') {
    await storeReceivedMessage(event.message);
    realtimeClient?.send({
      type: 'message.received',
      messageId: event.message.id,
      queueId: event.message.queueId,
      receiveToken: receiveDirection().receiveToken,
    });
    state.log.unshift('Nova mensagem recebida via WebSocket e confirmada para apagar.');
    await refreshOps().catch(() => undefined);
    render();
    return;
  }

  if (event.type === 'message.deleted') {
    state.log.unshift(`Relay apagou envelope ${shortId(event.messageId)}.`);
    return;
  }

  if (event.type === 'error') {
    state.log.unshift(event.message);
    render();
  }
}

function sendDirection() {
  return state.role === 'a' ? state.invite!.aToB : state.invite!.bToA;
}

function receiveDirection() {
  return state.role === 'a' ? state.invite!.bToA : state.invite!.aToB;
}

function realtimeLabel() {
  if (state.realtimeStatus === 'online') return 'online';
  if (state.realtimeStatus === 'connecting') return 'conectando';
  return 'offline';
}

function renderReceipt(status: 'sending' | 'stored' | 'delivered') {
  if (status === 'delivered') return '✓✓';
  if (status === 'stored') return '✓';
  return '...';
}

function renderEyeIcon(visible: boolean) {
  if (visible) {
    return `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M3 3l18 18" />
        <path d="M10.6 10.6a2.5 2.5 0 0 0 3.4 3.4" />
        <path d="M9.9 4.2A10.8 10.8 0 0 1 12 4c5.2 0 8.7 4.3 10 8a12.2 12.2 0 0 1-2.4 3.8" />
        <path d="M6.4 6.5A12.3 12.3 0 0 0 2 12c1.3 3.7 4.8 8 10 8 1.5 0 2.8-.3 4-.9" />
      </svg>
    `;
  }

  return `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M2 12s3.7-7 10-7 10 7 10 7-3.7 7-10 7S2 12 2 12z" />
      <path d="M12 15.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4z" />
    </svg>
  `;
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

function validateVaultPassword(password: string) {
  const classes = [
    /[a-z]/.test(password),
    /[A-Z]/.test(password),
    /[0-9]/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ].filter(Boolean).length;
  if (password.length < vaultPasswordMinLength || classes < 3) {
    throw new Error(`Use uma senha com pelo menos ${vaultPasswordMinLength} caracteres e 3 tipos de caracteres.`);
  }
}

function hasVaultBackup() {
  return Boolean(state.backup ?? localStorage.getItem(vaultBackupKey));
}

function readVaultBackupFromStorage() {
  const stored = localStorage.getItem(vaultBackupKey);
  if (!stored) return undefined;
  return parseVaultBackup(stored);
}

function parseVaultBackup(text: string): VaultBackup {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('Arquivo .zuri-key inválido: JSON não reconhecido.');
  }
  return validateVaultBackupShape(parsed);
}

function validateVaultBackupShape(value: unknown): VaultBackup {
  if (!value || typeof value !== 'object') {
    throw new Error('Arquivo .zuri-key inválido: estrutura ausente.');
  }
  const backup = value as Partial<VaultBackup>;
  const requiredStringFields = [
    'salt',
    'nonce',
    'encryptedPrivateKey',
    'encryptedHistoryKey',
    'createdAt',
  ] as const;
  const hasRequiredStrings = requiredStringFields.every((field) => typeof backup[field] === 'string' && backup[field]);
  if (
    backup.version !== 1 ||
    backup.kdf !== 'PBKDF2-SHA256' ||
    typeof backup.iterations !== 'number' ||
    !Number.isFinite(backup.iterations) ||
    backup.iterations < 100000 ||
    !hasRequiredStrings ||
    !backup.publicKey ||
    typeof backup.publicKey !== 'object'
  ) {
    throw new Error('Arquivo .zuri-key inválido ou incompatível com este app.');
  }
  return backup as VaultBackup;
}

function encodeInviteLink(payload: InviteLinkPayload) {
  const encoded = btoa(JSON.stringify(payload));
  return `${window.location.origin}/i/${encodeURIComponent(payload.inviteId)}#zuri=${encoded}`;
}

function decodeInviteLink(value: string): InviteLinkPayload {
  try {
    const hash = value.includes('#') ? value.split('#')[1] : value;
    const params = new URLSearchParams(hash);
    const encoded = params.get('zuri') ?? value;
    const invite = JSON.parse(atob(encoded)) as InviteLinkPayload;
    if (!invite.inviteId || !invite.inviteSecret || !invite.chatKey || !invite.relayUrl) {
      throw new Error('Convite incompleto.');
    }
    return invite;
  } catch {
    throw new Error('Convite inválido. Copie o link inteiro da outra janela.');
  }
}

function inviteTextFromLocation() {
  const hash = window.location.hash;
  if (!hash.includes('zuri=')) return '';
  return window.location.href;
}

async function conversationSecurityCode(bundle: RelayConnectionBundle, chatKey: JsonWebKey) {
  const bytes = new TextEncoder().encode(JSON.stringify({
    a: bundle.aToB.queueId,
    b: bundle.bToA.queueId,
    k: chatKey.k,
  }));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const parts = [digest[0] ?? 0, digest[1] ?? 0, digest[2] ?? 0].map((byte) => String(byte % 100).padStart(2, '0'));
  return parts.join('-');
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
