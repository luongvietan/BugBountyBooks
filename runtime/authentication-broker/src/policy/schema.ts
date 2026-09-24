import { z } from 'zod';

const Alias = z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/);
const Method = z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const UtcTimestamp = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/);
const OriginText = z.string().min(1).max(2048);
const PolicyReference = z.string().min(1).max(512);

export const BrokerPolicySchema = z.object({
  schemaVersion: z.literal(1),
  engagementId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$/),
  policySnapshot: z.object({
    url: z.string().min(1).max(2048),
    revision: z.string().min(1).max(128),
    capturedAtUtc: UtcTimestamp,
    freshUntilUtc: UtcTimestamp
  }).strict(),
  accountAliases: z.array(Alias).min(1).max(32),
  loginOrigins: z.array(z.object({
    origin: OriginText,
    purpose: z.literal('user-attended sign-in only')
  }).strict()).max(32),
  refreshOrigins: z.array(z.object({
    origin: OriginText,
    methods: z.array(Method).min(1).max(7),
    policyReference: PolicyReference
  }).strict()).max(16),
  targetOrigins: z.array(OriginText).min(1).max(64),
  grants: z.array(z.object({
    accountAlias: Alias,
    technique: z.string().min(1).max(128),
    methods: z.array(Method).min(1).max(7),
    policyReference: PolicyReference
  }).strict()).min(1).max(256),
  limits: z.object({
    requestsPerSecond: z.number().positive().max(1),
    maxConcurrentRequests: z.number().int().positive().max(1),
    maxRequestsPerCapability: z.number().int().positive().max(100),
    maxRequestBodyBytes: z.number().int().nonnegative().max(65536),
    expiresAtUtc: UtcTimestamp
  }).strict(),
  stopConditions: z.array(z.string().min(1).max(256)).min(1).max(64)
}).strict();

export type BrokerPolicy = z.infer<typeof BrokerPolicySchema>;

export type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer U)[]
    ? readonly DeepReadonly<U>[]
    : T extends object
      ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
      : T;
