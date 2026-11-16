// SPDX-License-Identifier: Apache-2.0
// abiz: the consumer side of ABIZ 1.1 (Agentic Business Record). Runtime-neutral: this entry
// point uses only fetch, WebCrypto and URL, and runs on Node 20+, Deno, Cloudflare Workers and
// browsers. `abiz/node` adds a Node transport that pins the checked address.
export {
  resolve,
  checkRecord,
  checkRecordDetailed,
  recordUrl,
  wellKnownUrl,
  statusOf,
  type ErrorCode,
  type RecordProblemCode,
  type RecordCheck,
  type Discovery,
  type ResolveInput,
  type ResolveOptions,
  type ResolveResult,
  type ResolveStatus,
  type Warning,
} from './resolve.js';
export { parseAssertion, parseTagList, isAbizAssertion, isNearMissAssertion, isAbizPublicKey, decodeTxtData, type AbizAssertion, type ParsedAssertion } from './txt.js';
export { verifySignature, signRecord, signingInput, publicKeyFromSeed, type SignatureCheck } from './signature.js';
export { canonicalJson as canonicalize, JcsError } from './jcs.js';
export { normaliseInput, identityParts, isSafeHttpsUrl, apexSuggestion, type NormalisedInput } from './host.js';
export { parseBusinessKey, sameBusinessKey, type BusinessKey } from './businessKey.js';
export { isPublicAddress } from './address.js';
export { validateSchema, semanticProblems, MAX_PROBLEMS, type Problem } from './validate.js';
export { MAX_RECORD_BYTES, MAX_RECORD_DEPTH, MAX_RECORD_KEYS } from './json.js';
export {
  guardedFetch,
  DNS_TIMEOUT_MS,
  FETCH_TIMEOUT_MS,
  LIBRARY_VERSION,
  USER_AGENT,
  type AddressLookup,
  type FetchOutcome,
  type Transport,
  type TxtLookup,
} from './transport.js';
export { dohTransport, dohTxtLookup, dohAddressLookup, platformFetch, DEFAULT_DOH_ENDPOINT, type DohOptions } from './doh.js';
export { ABIZ_VERSION, ABIZ_SCHEMA, ABIZ_SCHEMA_ID, ABIZ_WELL_KNOWN_SCHEMA, ABIZ_SPEC_SOURCE, BUNDLED_FILES } from './schema.js';
