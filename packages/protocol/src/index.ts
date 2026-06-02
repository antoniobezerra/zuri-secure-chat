import { z } from 'zod';

export const RELAY_PRODUCT = {
  name: 'zuri-secure-chat',
  publicName: 'Chat Zuri Seguro',
  slogan: 'A seguranca e nossa. A conversa e sua.',
} as const;

export const idSchema = z.string().min(8).max(160);
export const capabilityTokenSchema = z.string().min(32).max(256);
export const ciphertextSchema = z.string().min(16).max(262144);
export const nonceSchema = z.string().min(8).max(256).optional();

export const queueSchema = z.object({
  id: idSchema,
  status: z.enum(['active', 'disabled']),
  createdAt: z.string(),
});

export const queueCapabilitySchema = z.object({
  queueId: idSchema,
  sendToken: capabilityTokenSchema,
  receiveToken: capabilityTokenSchema,
  createdAt: z.string(),
});

export const relayConnectionBundleSchema = z.object({
  aToB: queueCapabilitySchema,
  bToA: queueCapabilitySchema,
});

export const createQueueResponseSchema = z.object({
  data: queueCapabilitySchema,
});

export const inviteStatusSchema = z.enum(['pending', 'consumed', 'expired', 'revoked']);
export const inviteSecretSchema = z.string().min(32).max(256);

export const createInviteResponseSchema = z.object({
  data: z.object({
    inviteId: idSchema,
    inviteSecret: inviteSecretSchema,
    creatorClaimToken: inviteSecretSchema,
    status: inviteStatusSchema,
    createdAt: z.string(),
    expiresAt: z.string(),
  }),
});

export const acceptInviteInputSchema = z.object({
  inviteSecret: inviteSecretSchema,
}).strict();

export const acceptInviteResponseSchema = z.object({
  data: z.object({
    inviteId: idSchema,
    status: z.literal('consumed'),
    consumedAt: z.string(),
    bundle: relayConnectionBundleSchema,
  }),
});

export const claimInviteInputSchema = z.object({
  creatorClaimToken: inviteSecretSchema,
}).strict();

export const claimInviteResponseSchema = z.object({
  data: z.object({
    inviteId: idSchema,
    status: z.literal('consumed'),
    claimedAt: z.string(),
    bundle: relayConnectionBundleSchema,
  }),
});

export const enqueueMessageInputSchema = z.object({
  queueId: idSchema,
  sendToken: capabilityTokenSchema,
  clientMessageId: z.string().min(1).max(160).optional(),
  envelopeVersion: z.number().int().positive().default(1),
  ciphertext: ciphertextSchema,
  nonce: nonceSchema,
}).strict();

export const queuedMessageSchema = z.object({
  id: idSchema,
  queueId: idSchema,
  clientMessageId: z.string().optional(),
  envelopeVersion: z.number().int().positive(),
  ciphertext: ciphertextSchema,
  nonce: nonceSchema,
  byteSize: z.number().int().positive(),
  createdAt: z.string(),
  expiresAt: z.string(),
});

export const pullMessagesQuerySchema = z.object({
  queueId: idSchema,
  receiveToken: capabilityTokenSchema,
  afterCursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
}).strict();

export const deliveredMessageInputSchema = z.object({
  queueId: idSchema,
  receiveToken: capabilityTokenSchema,
}).strict();

export const wsOpenInputSchema = z.object({
  queueId: idSchema,
  receiveToken: capabilityTokenSchema,
}).strict();

export const wsClientEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('message.send'),
    queueId: idSchema,
    sendToken: capabilityTokenSchema,
    clientMessageId: z.string().min(1).max(160),
    envelopeVersion: z.number().int().positive().default(1),
    ciphertext: ciphertextSchema,
    nonce: nonceSchema,
  }).strict(),
  z.object({
    type: z.literal('message.received'),
    messageId: idSchema,
    queueId: idSchema,
    receiveToken: capabilityTokenSchema,
  }).strict(),
  z.object({
    type: z.literal('ping'),
    at: z.string().optional(),
  }).strict(),
]);

export const wsServerEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('ready'),
    queueId: idSchema,
    pending: z.number().int().nonnegative(),
  }).strict(),
  z.object({
    type: z.literal('message.stored'),
    clientMessageId: z.string().min(1).max(160),
    messageId: idSchema,
    queueId: idSchema,
    createdAt: z.string(),
  }).strict(),
  z.object({
    type: z.literal('message.deliver'),
    message: queuedMessageSchema,
  }).strict(),
  z.object({
    type: z.literal('message.deleted'),
    messageId: idSchema,
    queueId: idSchema,
    deliveredAt: z.string(),
  }).strict(),
  z.object({
    type: z.literal('message.delivered'),
    clientMessageId: z.string().min(1).max(160).optional(),
    messageId: idSchema,
    queueId: idSchema,
    deliveredAt: z.string(),
  }).strict(),
  z.object({
    type: z.literal('pong'),
    at: z.string(),
  }).strict(),
  z.object({
    type: z.literal('error'),
    message: z.string().min(1).max(240),
  }).strict(),
]);

export const reportReasonSchema = z.enum([
  'minor_safety',
  'non_consensual',
  'fraud',
  'spam',
  'harassment',
  'illegal_content',
  'other',
]);

export const createReportInputSchema = z.object({
  queueId: idSchema.optional(),
  reason: reportReasonSchema,
  publicContextRef: z.string().min(1).max(240).optional(),
  approximateEventAt: z.string().optional(),
  evidenceCiphertextHash: z.string().min(16).max(256).optional(),
}).strict();

export const reportSchema = z.object({
  id: idSchema,
  queueId: idSchema.optional(),
  reason: reportReasonSchema,
  publicContextRef: z.string().optional(),
  approximateEventAt: z.string().optional(),
  evidenceCiphertextHash: z.string().optional(),
  createdAt: z.string(),
});

export const hourlyMetricSchema = z.object({
  bucketAt: z.string(),
  metricHash: z.string(),
  enqueuedCount: z.number().int().nonnegative(),
  deliveredCount: z.number().int().nonnegative(),
  expiredCount: z.number().int().nonnegative(),
});

export const localPlaintextMessageSchema = z.object({
  kind: z.enum(['text', 'location', 'event']).default('text'),
  body: z.string().max(4000).optional(),
  markdown: z.boolean().default(false),
  location: z
    .object({
      lat: z.number(),
      lng: z.number(),
      label: z.string().max(160).optional(),
    })
    .optional(),
  event: z
    .object({
      name: z.string().min(1).max(120),
      payload: z.record(z.string(), z.unknown()).optional(),
    })
    .optional(),
  createdAt: z.string(),
});

export type Queue = z.infer<typeof queueSchema>;
export type QueueCapability = z.infer<typeof queueCapabilitySchema>;
export type RelayConnectionBundle = z.infer<typeof relayConnectionBundleSchema>;
export type CreateQueueResponse = z.infer<typeof createQueueResponseSchema>;
export type InviteStatus = z.infer<typeof inviteStatusSchema>;
export type CreateInviteResponse = z.infer<typeof createInviteResponseSchema>;
export type AcceptInviteInput = z.infer<typeof acceptInviteInputSchema>;
export type AcceptInviteResponse = z.infer<typeof acceptInviteResponseSchema>;
export type ClaimInviteInput = z.infer<typeof claimInviteInputSchema>;
export type ClaimInviteResponse = z.infer<typeof claimInviteResponseSchema>;
export type EnqueueMessageInput = z.infer<typeof enqueueMessageInputSchema>;
export type QueuedMessage = z.infer<typeof queuedMessageSchema>;
export type PullMessagesQuery = z.infer<typeof pullMessagesQuerySchema>;
export type DeliveredMessageInput = z.infer<typeof deliveredMessageInputSchema>;
export type WsOpenInput = z.infer<typeof wsOpenInputSchema>;
export type WsClientEvent = z.infer<typeof wsClientEventSchema>;
export type WsServerEvent = z.infer<typeof wsServerEventSchema>;
export type CreateReportInput = z.infer<typeof createReportInputSchema>;
export type Report = z.infer<typeof reportSchema>;
export type HourlyMetric = z.infer<typeof hourlyMetricSchema>;
export type LocalPlaintextMessage = z.infer<typeof localPlaintextMessageSchema>;

export function assertNoPlaintextFields(payload: Record<string, unknown>) {
  const forbidden = ['text', 'plaintext', 'body', 'message', 'uid1', 'uid2', 'memberUid', 'advertiserUid', 'phone'];
  const present = forbidden.filter((key) => key in payload);
  if (present.length > 0) {
    throw new Error(`Payload contains forbidden relay field(s): ${present.join(', ')}`);
  }
}
