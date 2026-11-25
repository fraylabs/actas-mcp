export type State = 'pending' | 'failed';
export declare class ActAsError extends Error {
  readonly status: number;
  readonly code: string;
  readonly state: State;
}
/** Not finished yet: the code hasn't arrived, or a mailbox/domain is still pending. Safe to wait and retry. */
export declare class ActAsPendingError extends ActAsError { readonly state: 'pending'; }
/** Refused or broken. Don't retry blindly. */
export declare class ActAsFailedError extends ActAsError { readonly state: 'failed'; }
export declare class AuthError extends ActAsFailedError {}
export declare class PermissionError extends ActAsFailedError {}
export declare class NotFoundError extends ActAsFailedError {}
export declare class CodePendingError extends ActAsPendingError {}
export declare class InboxNotVerifiedError extends ActAsPendingError {}

export type Connection = {
  version?: 1;
  kind?: 'management';
  apiUrl: string;
  token: string;
  ownerId?: string;
  identityId?: string;
  /** Present on connections issued by identity.connect; used to route calls. */
  scopes?: string[];
  resourceIds?: string[];
};
export type Identity = {
  id: string; name: string; ownerId: string; productId: string | null; status: string;
  localPart: string | null; domain: string; createdAt: string; updatedAt: string;
};
/** status is 'verified' when create() returns; anything else throws InboxNotVerifiedError. */
export type Inbox = { id: string; address: string; status: 'verified' | 'pending' | 'failed' };
export type SignInMethod = 'password'|'google'|'github'|'apple';
export type LoginItem = {
  signInMethod?: SignInMethod; ssoAccountId?: string | null;
  title: string; url?: string; username?: string; email?: string; password?: string;
  /** otpauth URI or base32 seed. Stored encrypted; never returned. */
  totp?: string; backupCodes?: string[]; notes?: string; phoneId?: string;
};
export type Login = {
  path: string; signInMethod: SignInMethod; ssoAccountId: string | null;
  username: string | null;
  email: string | null;
  password: string | null;
  /** A current code only. The seed never leaves ActAs. */
  totp: { code: string; secondsRemaining: number } | null;
};
export type VaultAction = 'read' | 'write' | 'reveal' | 'run' | 'totp:code';

export type PasskeyOptions = {rpId:string;origin:string;challenge:string;userVerification?:'required'|'preferred'|'discouraged'};
export type PasskeyCredential = {id:string;rawId:string;type:'public-key';response:Record<string,unknown>;clientExtensionResults:Record<string,unknown>};
export type DeliveryResource={resourceId:string;kind?:'email'|'sms'};
export type MessageEvent={id:string;type:'email.received'|'sms.received';resourceId:string;messageId:string;occurredAt:string};
export declare class ActAs {
  messages:{
    /** Header metadata only. Subject uses an NFKC case-insensitive substring; sender is exact. */
    search(options:{inboxId:string;sender?:string;subject?:string;after?:string;before?:string;limit?:number;cursor?:string}):Promise<{messages:{message_id:string;timestamp:string;labels:string[];untrusted:true;text:string}[];nextCursor:string|null;scanned:number;coverage:'indexed_received_messages_only';legacyMessagesIndexed:false}>;
    getLabels(options:{inboxId:string;messageId:string}):Promise<{messageId:string;userLabels:string[]}>;
    /** Replaces labels atomically; [] clears. Requires emails:read and resources:write. */
    setLabels(options:{inboxId:string;messageId:string;userLabels:string[]}):Promise<{messageId:string;userLabels:string[]}>;
  };
  attachments:{
    /** Metadata only, with outside-content markings. Requires emails:read. */
    list(options:{inboxId:string;messageId:string}):Promise<{messageId:string;indexing:string;omitted?:number;untrusted:true;attachments:{id:string;size:number;status:string;untrusted:true;text:string}[]}>;
    /** Explicit download only; decoded bytes are untrusted data. Default maximum 5 MiB. */
    download(options:{inboxId:string;messageId:string;attachmentId:string;maxBytes?:number}):Promise<{attachmentId:string;untrusted:true;warning:string;encoding:'base64';data:string}>;
  };
  delivery:{
    waitFor(options:DeliveryResource & {cursor?:number;timeoutMs?:number}):Promise<{status:'matched'|'pending';cursor:number;events:MessageEvent[]}>;
    subscribe(options:DeliveryResource & {endpoint:string}):Promise<{id:string;secret:string;expiresAt:number}>;
    list(options:DeliveryResource):Promise<unknown[]>;
    revoke(options:DeliveryResource & {webhookId:string}):Promise<{revoked:boolean}>;
    deliveries(options:DeliveryResource & {webhookId:string}):Promise<unknown[]>;
  };
  passkeys: {
    register(path:string, options:PasskeyOptions & {userHandle:string}):Promise<PasskeyCredential>;
    sign(path:string, options:PasskeyOptions & {credentialId?:string;allowCredentials?:string[]}):Promise<PasskeyCredential>;
  };
  constructor(connections: Connection | Connection[], options?: { fetch?: typeof fetch });
  static fromFile(...files: string[]): Promise<ActAs>;
  identity: {
    /** Management. Creates the identity and (by default) its verified inbox. */
    create(options: { name: string; localPart?: string; domain?: string; inbox?: boolean }): Promise<Identity & { inbox: Inbox | null }>;
    get(id: string): Promise<Identity>;
    /** Management. Least-privilege connections for the agent: codes for one inbox, vault reads for listed login paths. */
    connect(identityId: string, options: { inbox?: string; logins?: string[]; name?: string }): Promise<Connection[]>;
  };
  inbox: {
    /** Needs emails:codes on the inbox. Throws CodePendingError if nothing matches before timeoutMs. */
    waitForCode(options: { inboxId: string; sender: string; subject: string; after: string | Date; pattern?: string; timeoutMs?: number }): Promise<{ code: string; receivedAt: string }>;
  };
  vault: {
    /** Needs secrets:reveal plus vault grants read, reveal and totp:code on the path. */
    login(path: string): Promise<Login>;
    saveLogin(path: string, item: LoginItem, options?: { replace?: boolean }): Promise<{ id: string; path: string; kind: 'login' }>;
    grant(options: { path: string; principalKind: 'client' | 'identity'; principalId: string; actions: VaultAction[]; folder?: boolean }): Promise<unknown>;
  };
}
export default ActAs;

export declare function verifyWebhook(secret:string,headers:Headers|Record<string,string>,rawBody:string,options?:{now?:number;toleranceMs?:number}):Promise<boolean>;
