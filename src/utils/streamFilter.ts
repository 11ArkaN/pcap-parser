import type { PcapStreamSummary } from '../types';

type NumericField = 'packets' | 'bytes';
type CompareOp = '>' | '>=' | '<' | '<=' | '=';

interface NumericRule {
  field: NumericField;
  op: CompareOp;
  value: number;
}

interface ParsedQuery {
  textInclude: string[];
  textExclude: string[];
  ipInclude: string[];
  ipExclude: string[];
  portInclude: number[];
  portExclude: number[];
  protoInclude: string[];
  protoExclude: string[];
  serviceInclude: string[];
  serviceExclude: string[];
  idInclude: string[];
  idExclude: string[];
  numericInclude: NumericRule[];
  numericExclude: NumericRule[];
}

export function filterStreams(
  streams: PcapStreamSummary[],
  search: string,
  protocolFilter: string
): PcapStreamSummary[] {
  const query = parseQuery(search);
  return streams.filter((stream) => {
    if (protocolFilter !== 'all' && stream.protocol !== protocolFilter) {
      return false;
    }
    return matchesQuery(stream, query);
  });
}

function parseQuery(search: string): ParsedQuery {
  const query: ParsedQuery = {
    textInclude: [],
    textExclude: [],
    ipInclude: [],
    ipExclude: [],
    portInclude: [],
    portExclude: [],
    protoInclude: [],
    protoExclude: [],
    serviceInclude: [],
    serviceExclude: [],
    idInclude: [],
    idExclude: [],
    numericInclude: [],
    numericExclude: []
  };

  for (const rawToken of tokenize(search)) {
    const negated = rawToken.startsWith('!');
    const token = normalize(rawToken.slice(negated ? 1 : 0));
    if (!token) continue;

    const idx = token.indexOf(':');
    if (idx > 0 && idx < token.length - 1) {
      const key = token.slice(0, idx);
      const value = token.slice(idx + 1);
      if (assignKeyValue(query, key, value, negated)) {
        continue;
      }
      pushTerm(query, `${key}:${value}`, negated);
      continue;
    }

    if (looksLikeIp(token)) {
      pushIp(query, token, negated);
      continue;
    }

    if (/^\d+$/.test(token)) {
      const port = Number(token);
      if (Number.isInteger(port) && port >= 0 && port <= 65535) {
        pushPort(query, port, negated);
        continue;
      }
    }

    if (isServiceToken(token)) {
      pushService(query, token, negated);
      continue;
    }

    pushTerm(query, token, negated);
  }

  return query;
}

function assignKeyValue(query: ParsedQuery, key: string, value: string, negated: boolean): boolean {
  if (!value) return false;
  switch (key) {
    case 'ip':
    case 'host':
      pushIp(query, value, negated);
      return true;
    case 'port':
    case 'p': {
      const port = Number(value);
      if (Number.isInteger(port) && port >= 0 && port <= 65535) {
        pushPort(query, port, negated);
        return true;
      }
      return false;
    }
    case 'proto':
    case 'protocol':
      pushProto(query, value, negated);
      return true;
    case 'service':
    case 'svc':
    case 'app':
      pushService(query, value, negated);
      return true;
    case 'id':
    case 'stream':
      pushId(query, value, negated);
      return true;
    case 'packets':
    case 'pkt': {
      const rule = parseNumericRule('packets', value);
      if (!rule) return false;
      pushNumeric(query, rule, negated);
      return true;
    }
    case 'bytes':
    case 'size': {
      const rule = parseNumericRule('bytes', value);
      if (!rule) return false;
      pushNumeric(query, rule, negated);
      return true;
    }
    default:
      return false;
  }
}

function parseNumericRule(field: NumericField, raw: string): NumericRule | null {
  const value = normalize(raw);
  if (!value) return null;
  const match = value.match(/^(>=|<=|>|<|=)?\s*([0-9]+(?:\.[0-9]+)?)([a-z]+)?$/i);
  if (!match) return null;

  const op = (match[1] as CompareOp | undefined) ?? '=';
  const parsed = Number(match[2]);
  if (!Number.isFinite(parsed)) return null;

  let multiplier = 1;
  const unit = (match[3] ?? '').toLowerCase();
  if (field === 'bytes') {
    if (unit === '' || unit === 'b') multiplier = 1;
    else if (unit === 'k' || unit === 'kb') multiplier = 1024;
    else if (unit === 'm' || unit === 'mb') multiplier = 1024 * 1024;
    else if (unit === 'g' || unit === 'gb') multiplier = 1024 * 1024 * 1024;
    else return null;
  } else if (unit !== '') {
    return null;
  }

  const numeric = Math.round(parsed * multiplier);
  return { field, op, value: numeric };
}

function matchesQuery(stream: PcapStreamSummary, query: ParsedQuery): boolean {
  const haystack = buildHaystack(stream);
  const ips = [normalize(stream.clientIp), normalize(stream.serverIp), normalize(stream.endpointA), normalize(stream.endpointB)];
  const ports = [stream.clientPort, stream.serverPort].filter((value): value is number => Number.isInteger(value));
  const proto = normalize(stream.protocol);
  const services = inferServiceTags(stream);
  const streamId = normalize(stream.streamId);

  if (!query.textInclude.every((term) => haystack.includes(term))) return false;
  if (query.textExclude.some((term) => haystack.includes(term))) return false;

  if (!query.ipInclude.every((term) => ips.some((candidate) => candidate.includes(term)))) return false;
  if (query.ipExclude.some((term) => ips.some((candidate) => candidate.includes(term)))) return false;

  if (!query.portInclude.every((port) => ports.includes(port))) return false;
  if (query.portExclude.some((port) => ports.includes(port))) return false;

  if (!query.protoInclude.every((term) => proto.includes(term))) return false;
  if (query.protoExclude.some((term) => proto.includes(term))) return false;

  if (!query.serviceInclude.every((term) => services.includes(term))) return false;
  if (query.serviceExclude.some((term) => services.includes(term))) return false;

  if (!query.idInclude.every((term) => streamId.includes(term))) return false;
  if (query.idExclude.some((term) => streamId.includes(term))) return false;

  if (!query.numericInclude.every((rule) => evaluateNumericRule(stream, rule))) return false;
  if (query.numericExclude.some((rule) => evaluateNumericRule(stream, rule))) return false;

  return true;
}

function evaluateNumericRule(stream: PcapStreamSummary, rule: NumericRule): boolean {
  const actual = rule.field === 'packets' ? stream.packets : stream.bytes;
  switch (rule.op) {
    case '>':
      return actual > rule.value;
    case '>=':
      return actual >= rule.value;
    case '<':
      return actual < rule.value;
    case '<=':
      return actual <= rule.value;
    case '=':
      return actual === rule.value;
    default:
      return false;
  }
}

function buildHaystack(stream: PcapStreamSummary): string {
  return normalize(
    [
      stream.streamId,
      stream.protocol,
      stream.endpointA,
      stream.endpointB,
      stream.clientIp,
      stream.serverIp,
      stream.clientPort ?? '',
      stream.serverPort ?? '',
      inferServiceTags(stream).join(' '),
      stream.packets,
      stream.bytes
    ].join(' ')
  );
}

function tokenize(input: string): string[] {
  if (!input) return [];
  return input
    .split(/\s+/)
    .map((token) => token.trim())
    .filter(Boolean);
}

function looksLikeIp(value: string): boolean {
  return /[.:]/.test(value);
}

function normalize(value: string): string {
  return value.trim().toLowerCase();
}

function pushTerm(query: ParsedQuery, value: string, negated: boolean): void {
  if (negated) query.textExclude.push(value);
  else query.textInclude.push(value);
}

function pushIp(query: ParsedQuery, value: string, negated: boolean): void {
  if (negated) query.ipExclude.push(value);
  else query.ipInclude.push(value);
}

function pushPort(query: ParsedQuery, value: number, negated: boolean): void {
  if (negated) query.portExclude.push(value);
  else query.portInclude.push(value);
}

function pushProto(query: ParsedQuery, value: string, negated: boolean): void {
  if (negated) query.protoExclude.push(value);
  else query.protoInclude.push(value);
}

function pushService(query: ParsedQuery, value: string, negated: boolean): void {
  const normalized = normalize(value);
  if (!normalized) return;
  if (negated) query.serviceExclude.push(normalized);
  else query.serviceInclude.push(normalized);
}

function pushId(query: ParsedQuery, value: string, negated: boolean): void {
  if (negated) query.idExclude.push(value);
  else query.idInclude.push(value);
}

function pushNumeric(query: ParsedQuery, value: NumericRule, negated: boolean): void {
  if (negated) query.numericExclude.push(value);
  else query.numericInclude.push(value);
}

function isServiceToken(token: string): boolean {
  return token === 'http' || token === 'https' || token === 'dns' || token === 'ssh' || token === 'rdp';
}

function inferServiceTags(stream: PcapStreamSummary): string[] {
  const ports = [stream.clientPort, stream.serverPort];
  const tags = new Set<string>();
  for (const rawPort of ports) {
    if (!Number.isInteger(rawPort)) continue;
    const port = rawPort as number;
    if (port === 80 || port === 8080 || port === 8000 || port === 8888) tags.add('http');
    if (port === 443 || port === 8443) tags.add('https');
    if (port === 53) tags.add('dns');
    if (port === 22) tags.add('ssh');
    if (port === 3389) tags.add('rdp');
  }
  return Array.from(tags);
}
