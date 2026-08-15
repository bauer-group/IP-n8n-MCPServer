/**
 * Two-language string table for the consent screen.
 *
 * German first because that is the operator's and most users' language; English
 * because a gateway that serves several n8n instances will sooner or later
 * serve someone who does not read German. Selected from `Accept-Language`,
 * which costs nothing and is right often enough — there is no locale to
 * remember here, the page is seen once per connector.
 *
 * The table is exhaustive by type: adding a key to `de` fails the build until
 * `en` has it too.
 */

export type Locale = 'de' | 'en';

export interface Strings {
  readonly connectTitle: string;
  readonly connectIntro: string;
  readonly instanceLabel: string;
  readonly usernameLabel: string;
  readonly usernameHint: string;
  readonly apiKeyLabel: string;
  readonly apiKeyHint: string;
  readonly submit: string;
  readonly clientLabel: string;
  readonly privacyNote: string;
  readonly errorTitle: string;
  readonly backHint: string;
  /** Keyed by the failure codes surfaced from probe.ts / api-key.ts. */
  readonly errors: Readonly<Record<string, string>>;
}

const de: Strings = {
  connectTitle: 'n8n verbinden',
  connectIntro:
    'Melden Sie sich mit Ihrem persönlichen n8n-API-Key an. Der Key wird verschlüsselt gespeichert und niemals an den KI-Client weitergegeben.',
  instanceLabel: 'n8n-Instanz',
  usernameLabel: 'Benutzername oder E-Mail',
  usernameHint: 'Wird nur für das Protokoll dieser Verbindung verwendet.',
  apiKeyLabel: 'API-Key',
  apiKeyHint: 'In n8n unter Einstellungen → n8n API → API-Key erstellen.',
  submit: 'Verbinden',
  clientLabel: 'Anfragender Client',
  privacyNote:
    'Ihre Berechtigungen in n8n bleiben unverändert — der KI-Client sieht genau das, was Sie sehen dürfen.',
  errorTitle: 'Das hat nicht geklappt',
  backHint: 'Schließen Sie dieses Fenster und starten Sie die Verbindung im KI-Client erneut.',
  errors: {
    bad_key:
      'Dieser API-Key wird von der Instanz abgelehnt. Bitte in n8n unter Einstellungen → n8n API einen neuen Key erzeugen.',
    insufficient_permissions:
      'Der Key ist gültig, das Konto darf aber keine Workflows lesen. Bitte an die Administration der Instanz wenden.',
    proxy_auth:
      'Vor dieser Instanz sitzt ein Proxy mit eigener Anmeldung — Ihr API-Key wurde nie an n8n weitergereicht. Die Administration der Instanz muss den Pfad /api/v1/ von dieser Anmeldung ausnehmen. Ein neuer Key hilft hier nicht.',
    api_disabled:
      'Unter /api/v1 antwortet keine API. Entweder ist die Public API auf dieser Instanz nicht aktiviert, oder für diesen Hostnamen ist derzeit nichts erreichbar — etwa weil der Container gestoppt ist. Bitte an die Administration der Instanz wenden.',
    rate_limited:
      'Die Instanz hat zu viele Anfragen abgelehnt. Bitte in einigen Minuten erneut versuchen.',
    unreachable:
      'Die Instanz ist derzeit nicht erreichbar. Läuft sie, und ist sie öffentlich per HTTPS erreichbar?',
    not_n8n: 'Unter dieser Adresse antwortet keine n8n-API.',
    expired: 'Dieser API-Key ist abgelaufen. Bitte in n8n einen neuen Key erzeugen.',
    wrong_audience:
      'Das ist kein n8n-API-Key. Bitte den Key aus Einstellungen → n8n API verwenden.',
    empty: 'Bitte einen API-Key eingeben.',
    no_username: 'Bitte einen Benutzernamen oder eine E-Mail-Adresse eingeben.',
    rate_limited_login: 'Zu viele Fehlversuche. Bitte in 15 Minuten erneut versuchen.',
    unknown_instance: 'Diese n8n-Instanz ist auf diesem Gateway nicht freigegeben.',
    invalid_request: 'Die Anfrage war unvollständig oder ungültig.',
    unknown_client: 'Der anfragende Client ist nicht registriert.',
    invalid_redirect: 'Die Rücksprungadresse des Clients passt nicht zur Registrierung.',
    session_expired: 'Die Anmeldung hat zu lange gedauert. Bitte im KI-Client neu verbinden.',
  },
};

const en: Strings = {
  connectTitle: 'Connect n8n',
  connectIntro:
    'Sign in with your personal n8n API key. It is stored encrypted and is never handed to the AI client.',
  instanceLabel: 'n8n instance',
  usernameLabel: 'Username or e-mail',
  usernameHint: 'Used only in the audit log for this connection.',
  apiKeyLabel: 'API key',
  apiKeyHint: 'In n8n: Settings → n8n API → Create an API key.',
  submit: 'Connect',
  clientLabel: 'Requesting client',
  privacyNote:
    'Your n8n permissions are unchanged — the AI client sees exactly what you are allowed to see.',
  errorTitle: 'That did not work',
  backHint: 'Close this window and start the connection again from your AI client.',
  errors: {
    bad_key:
      'The instance rejected this API key. Create a new one in n8n under Settings → n8n API.',
    insufficient_permissions:
      'The key is valid but the account may not read workflows. Ask the instance administrator for access.',
    proxy_auth:
      'A proxy in front of this instance asks for its own login, so your API key never reached n8n. Ask the instance administrator to exempt /api/v1/ from that login. A new key will not help.',
    api_disabled:
      'Nothing answers at /api/v1. Either the public API is not enabled on this instance, or nothing is currently routed for this hostname — a stopped container, say. Ask the instance administrator.',
    rate_limited: 'The instance rejected too many requests. Please try again in a few minutes.',
    unreachable:
      'The instance is not reachable right now. Is it running, and publicly reachable over HTTPS?',
    not_n8n: 'There is no n8n API at this address.',
    expired: 'This API key has expired. Create a new one in n8n.',
    wrong_audience: 'That is not an n8n API key. Use the key from Settings → n8n API.',
    empty: 'Please enter an API key.',
    no_username: 'Please enter a username or e-mail address.',
    rate_limited_login: 'Too many failed attempts. Please try again in 15 minutes.',
    unknown_instance: 'This n8n instance is not enabled on this gateway.',
    invalid_request: 'The request was incomplete or invalid.',
    unknown_client: 'The requesting client is not registered.',
    invalid_redirect: 'The client redirect URI does not match its registration.',
    session_expired: 'Sign-in took too long. Please reconnect from your AI client.',
  },
};

const TABLES: Record<Locale, Strings> = { de, en };

/**
 * Pick a locale from an `Accept-Language` header.
 *
 * Deliberately crude — first matching primary subtag wins, German otherwise.
 * Full RFC 4647 negotiation would be more code than the two-entry table it
 * selects from.
 */
export function pickLocale(acceptLanguage: string | undefined): Locale {
  if (!acceptLanguage) return 'de';
  for (const part of acceptLanguage.split(',')) {
    const tag = part.split(';')[0]?.trim().toLowerCase() ?? '';
    const primary = tag.split('-')[0];
    if (primary === 'de') return 'de';
    if (primary === 'en') return 'en';
  }
  return 'de';
}

export function strings(locale: Locale): Strings {
  return TABLES[locale];
}

/** Resolve a failure code to a sentence, falling back to a generic one. */
export function errorText(locale: Locale, code: string): string {
  const table = TABLES[locale].errors;
  return table[code] ?? table['invalid_request'] ?? code;
}
