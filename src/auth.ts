import sjcl from 'sjcl';
import * as crypto from 'crypto';

interface AuthorizationHeaderParams {
  id: string;
  key: string;
  host: string;
  url: string;
  method: string;
}

const authorizationScheme = 'VERACODE-HMAC-SHA-256';
const requestVersion = 'vcode_request_version_1';
const nonceSize = 16;

function computeHashHex(message: string, key_hex: string): string {
  const key_bits = sjcl.codec.hex.toBits(key_hex);
  const hmac_bits = new sjcl.misc.hmac(key_bits, sjcl.hash.sha256).mac(message);
  const hmac = sjcl.codec.hex.fromBits(hmac_bits);
  return hmac;
}

function calulateDataSignature(apiKeyBytes: string, nonceBytes: string, dateStamp: string, data: string): string {
  const kNonce = computeHashHex(nonceBytes, apiKeyBytes);
  const kDate = computeHashHex(dateStamp, kNonce);
  const kSig = computeHashHex(requestVersion, kDate);
  const kFinal = computeHashHex(data, kSig);
  return kFinal;
}

function newNonce(): string {
  return crypto.randomBytes(nonceSize).toString('hex').toUpperCase();
}

function toHexBinary(input: string): string {
  return sjcl.codec.hex.fromBits(sjcl.codec.utf8String.toBits(input));
}

export function calculateAuthorizationHeader(params: AuthorizationHeaderParams): string {
  const uriString = params.url;
  const data = `id=${params.id}&host=${params.host}&url=${uriString}&method=${params.method}`;
  const dateStamp = Date.now().toString();
  const nonceBytes = newNonce();
  const dataSignature = calulateDataSignature(params.key, nonceBytes, dateStamp, data);
  const authorizationParam = `id=${params.id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
  const header = authorizationScheme + ' ' + authorizationParam;
  return header;
}
