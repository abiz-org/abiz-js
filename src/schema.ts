// SPDX-License-Identifier: Apache-2.0
// The bundled ABIZ 1.1 files. ../schema/ holds byte-for-byte copies of
// schemas/abiz-business-record-v1.1.schema.json, schemas/abiz-well-known-v1.1.schema.json and
// data/iso3166.json from abiz-org/abiz-agentic-business-record (commit
// 3fb26a34e3cb1402a28352b5071a150e87853d5c, tag v1.1.0 and later). test/packaging.test.ts checks
// their SHA-256 against the values below. The build inlines them into dist/ as well; the files
// themselves ship in the package under schema/.
import recordSchema from '../schema/abiz-business-record-v1.1.schema.json';
import wellKnownSchema from '../schema/abiz-well-known-v1.1.schema.json';

/** The ABIZ revision this library implements. */
export const ABIZ_VERSION = '1.1';

/** The JSON Schema (Draft 2020-12) every record is checked against. */
export const ABIZ_SCHEMA: Readonly<Record<string, unknown>> = recordSchema as Record<string, unknown>;

/** The schema of `/.well-known/abiz.json`, bundled for reference. Resolution applies the same rules in code. */
export const ABIZ_WELL_KNOWN_SCHEMA: Readonly<Record<string, unknown>> = wellKnownSchema as Record<string, unknown>;

export const ABIZ_SCHEMA_ID = 'https://abizrecord.org/schema/abiz-business-record-v1.1.schema.json';

/** SHA-256 (hex) of each bundled file. */
export const BUNDLED_FILES = {
  'abiz-business-record-v1.1.schema.json': '3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24',
  'abiz-well-known-v1.1.schema.json': '5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741',
  'iso3166.json': '0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527',
} as const;

export const ABIZ_SPEC_SOURCE = {
  repository: 'https://github.com/abiz-org/abiz-agentic-business-record',
  commit: '3fb26a34e3cb1402a28352b5071a150e87853d5c',
} as const;
