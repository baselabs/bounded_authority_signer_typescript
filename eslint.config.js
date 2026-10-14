// ESLint config for @bounded-authority-protocol/signer: the browser-safety gate for src/ (since 0.5.0).
// test/guards.test.ts holds every rule below to a probe that must trip it, linted against THIS file.
//
// src/ runs in browsers, Deno, Bun and workers, so it uses no Node built-in module (prefixed or bare),
// no Node global (Buffer, process, require, ...) including through globalThis, no dynamic import(), and
// no eval, implied eval or Function constructor (a strict CSP forbids them). Unlike the verifier, the
// signer has no Node backend file: the exception list is empty, and every crypto operation it needs
// (strict verification, SHA-256) comes from the verifier package, which selects its own backend.
//
// The private key never enters this library: src/ reaches no @noble module, no key-generation,
// key-derivation, import, export, wrapping, encryption or digest entry point by name, and no WebCrypto
// (crypto.subtle) at all, with ONE exception since 0.6.0: src/webcrypto.ts (the WebCrypto key handles)
// may reach crypto.subtle for exactly two direct calls, subtle.sign(...) and subtle.exportKey("raw", ...)
// with the literal "raw". Its override is built from the same shared arrays below, minus exactly the
// subtle and exportKey allowances, so every other ban still applies there. Everywhere, sign and exportKey
// may only be called directly: never read as a value, reached by a string key, destructured, or routed
// through .call, .apply or .bind. Signing is otherwise always the caller's handle.sign().
import { builtinModules } from "node:module";
import tseslint from "typescript-eslint";

const NODE_MESSAGE = "Node built-in modules are forbidden in src/ (browser safety)";
const NODE_BUILTINS = [...new Set(builtinModules.flatMap((name) => (name.startsWith("node:") ? [name, name.slice(5)] : [name, `node:${name}`])))].sort();
const NOBLE_MESSAGE = "@noble is forbidden in src/: signing is the caller's handle, and verification and hashing come from the verifier package";

const RESTRICTED_IMPORTS = [
  "error",
  {
    paths: NODE_BUILTINS.map((name) => ({ name, message: NODE_MESSAGE })),
    patterns: [
      { group: ["node:*"], message: NODE_MESSAGE },
      { group: ["@noble/**"], message: NOBLE_MESSAGE },
    ],
  },
];

const NETWORK_GLOBALS = ["fetch", "XMLHttpRequest", "WebSocket"].map((name) => ({
  name,
  message: `${name} is forbidden in src/: the signer is not a transport`,
}));
const NODE_GLOBALS = ["Buffer", "process", "global", "require", "module", "exports", "__dirname", "__filename", "setImmediate"].map((name) => ({
  name,
  message: `the Node global ${name} is forbidden in src/ (browser safety)`,
}));

const GLOBAL_OBJECTS = ["globalThis", "window", "self", "global"];
const NODE_GLOBAL_PROPERTIES = GLOBAL_OBJECTS.flatMap((object) =>
  ["Buffer", "process", "require"].map((property) => ({
    object,
    property,
    message: `${object}.${property} is a Node global, forbidden in src/ (browser safety)`,
  })),
);
const KEY_MATERIAL_NAMES = [
  "keygen", "getPublicKey", "getSharedSecret", "randomSecretKey",
  "generateKey", "deriveKey", "deriveBits", "importKey", "exportKey", "wrapKey", "unwrapKey", "encrypt", "decrypt", "digest",
];
const keyMaterialProperties = (names) => names.map((property) => ({
  property,
  message: `.${property} is a key-generation or key-derivation entry point, forbidden in src/ (the private key never enters this library)`,
}));

// no-restricted-syntax entries. Each has its own message: test/guards.test.ts removes an entry by its
// message to red-prove the probe it catches.
const SYNTAX = {
  dynamicImport: {
    selector: "ImportExpression",
    message: "dynamic import() forbidden in src/ (browser safety: every dependency is static)",
  },
  subtle: {
    selector: "MemberExpression[property.name='subtle']",
    message: "WebCrypto (crypto.subtle) is forbidden in src/: signing is the caller's handle, verification the verifier package's",
  },
  subtleDestructured: {
    selector: "ObjectPattern > Property[key.name='subtle']",
    message: "destructuring subtle is forbidden in src/ (it would hide crypto.subtle from the member rule)",
  },
  require: {
    selector: "CallExpression[callee.name='require']",
    message: "require() is forbidden in src/ (ESM only, browser safety)",
  },
  // A type cast hides the object from no-restricted-properties ((globalThis as unknown as {...}).Buffer),
  // so the property name is banned on ANY object, dotted or as a string key.
  nodePropertyDotted: {
    selector: "MemberExpression[computed=false][property.name=/^(Buffer|process|require)$/]",
    message: "a Buffer, process or require property is forbidden in src/ on any object (browser safety; casts do not hide it)",
  },
  nodePropertyComputed: {
    selector: "MemberExpression[computed=true][property.value=/^(Buffer|process|require)$/]",
    message: "a Buffer, process or require property, by string key, is forbidden in src/ on any object (browser safety)",
  },
  // sign and exportKey: direct calls only.
  signNotCalled: {
    selector: "MemberExpression[computed=false][property.name='sign']:not(CallExpression > MemberExpression.callee)",
    message: ".sign may only be called directly in src/ (never read as a value, or routed through .call, .apply or .bind)",
  },
  exportKeyNotCalled: {
    selector: "MemberExpression[computed=false][property.name='exportKey']:not(CallExpression[arguments.0.type='Literal'][arguments.0.value='raw'] > MemberExpression.callee)",
    message: ".exportKey may only be called directly with the literal \"raw\" format, and only in src/webcrypto.ts",
  },
  signOrExportByString: {
    selector: "Literal[value=/^(sign|exportKey|subtle)$/]",
    message: "the strings \"sign\", \"exportKey\" and \"subtle\" are forbidden in src/ (no string-keyed or Reflect access to them)",
  },
  signOrExportDestructured: {
    selector: "ObjectPattern > Property[key.name=/^(sign|exportKey)$/]",
    message: "destructuring sign or exportKey is forbidden in src/ (direct calls only)",
  },
  templateKeyMaterial: {
    selector: "TemplateElement[value.cooked=/^(sign|exportKey|subtle|pkcs8|spki|jwk)$/]",
    message: "a template string spelling sign, exportKey, subtle or a private-key export format is forbidden in src/",
  },
};

const BASE_SYNTAX = Object.values(SYNTAX);
// src/webcrypto.ts: the shared entries minus exactly the subtle ban (exportKey's direct-call-with-"raw"
// form is already the only one SYNTAX.exportKeyNotCalled allows).
const WEBCRYPTO_SYNTAX = BASE_SYNTAX.filter((entry) => entry !== SYNTAX.subtle);
const BASE_PROPERTIES = [...NODE_GLOBAL_PROPERTIES, ...keyMaterialProperties(KEY_MATERIAL_NAMES)];
// src/webcrypto.ts: the shared entries minus exactly the .exportKey property ban.
const WEBCRYPTO_PROPERTIES = [...NODE_GLOBAL_PROPERTIES, ...keyMaterialProperties(KEY_MATERIAL_NAMES.filter((name) => name !== "exportKey"))];

export default tseslint.config(
  {
    // web/** is the GitHub Pages playground and browser/** the browser test page: DOM-context code,
    // typechecked by their own tsc configs, outside the library gate above.
    ignores: ["dist/**", "node_modules/**", "test/**", "web/**", "browser/**", "site-dist/**", ".kimosabe/**", ".playwright-mcp/**"],
  },
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts"],
    rules: {
      "no-restricted-imports": RESTRICTED_IMPORTS,
      "no-restricted-globals": ["error", ...NETWORK_GLOBALS, ...NODE_GLOBALS],
      "no-restricted-properties": ["error", ...BASE_PROPERTIES],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-syntax": ["error", ...BASE_SYNTAX],
    },
  },
  {
    // The WebCrypto key handles: the only file allowed to reach crypto.subtle (sign, and exportKey "raw").
    files: ["src/webcrypto.ts"],
    rules: {
      "no-restricted-properties": ["error", ...WEBCRYPTO_PROPERTIES],
      "no-restricted-syntax": ["error", ...WEBCRYPTO_SYNTAX],
    },
  },
);
