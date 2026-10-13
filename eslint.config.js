// ESLint config for @bounded-authority-protocol/signer: the browser-safety gate for src/ (since 0.5.0).
// test/guards.test.ts holds every rule below to a probe that must trip it, linted against THIS file.
//
// src/ runs in browsers, Deno, Bun and workers, so it uses no Node built-in module (prefixed or bare),
// no Node global (Buffer, process, require, ...) including through globalThis, no dynamic import(), and
// no eval, implied eval or Function constructor (a strict CSP forbids them). Unlike the verifier, the
// signer has no Node backend file: the exception list is empty, and every crypto operation it needs
// (strict verification, SHA-256) comes from the verifier package, which selects its own backend.
//
// The private key never enters this library: src/ reaches no @noble module and no WebCrypto
// (crypto.subtle) at all, and no key-generation or key-derivation entry point by name. Signing is
// always the caller's handle.sign().
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
const KEY_MATERIAL_PROPERTIES = ["keygen", "getPublicKey", "getSharedSecret", "randomSecretKey", "generateKey", "deriveKey", "importKey", "exportKey"].map((property) => ({
  property,
  message: `.${property} is a key-generation or key-derivation entry point, forbidden in src/ (the private key never enters this library)`,
}));

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
      "no-restricted-properties": ["error", ...NODE_GLOBAL_PROPERTIES, ...KEY_MATERIAL_PROPERTIES],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector: "ImportExpression",
          message: "dynamic import() forbidden in src/ (browser safety: every dependency is static)",
        },
        {
          selector: "MemberExpression[property.name='subtle']",
          message: "WebCrypto (crypto.subtle) is forbidden in src/: signing is the caller's handle, verification the verifier package's",
        },
        {
          selector: "CallExpression[callee.name='require']",
          message: "require() is forbidden in src/ (ESM only, browser safety)",
        },
        // A type cast hides the object from no-restricted-properties ((globalThis as unknown as {...}).Buffer),
        // so the property name is banned on ANY object, dotted or as a string key.
        {
          selector: "MemberExpression[computed=false][property.name=/^(Buffer|process|require)$/]",
          message: "a Buffer, process or require property is forbidden in src/ on any object (browser safety; casts do not hide it)",
        },
        {
          selector: "MemberExpression[computed=true][property.value=/^(Buffer|process|require)$/]",
          message: "a Buffer, process or require property is forbidden in src/ on any object (browser safety; casts do not hide it)",
        },
      ],
    },
  },
);
