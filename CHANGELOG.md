## [0.4.1](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.4.0...v0.4.1) (2026-08-21)

### 🐛 Bug Fixes

* **mcp:** repaired intermittent connector failures ([7985952](https://github.com/bauer-group/IP-n8n-MCPServer/commit/79859528f83a0337356e966fcf6ca11fa43f8808))

## [0.4.0](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.3.4...v0.4.0) (2026-08-20)

### 🚀 Features

* **consent:** named the redirect target on the form ([19f0dba](https://github.com/bauer-group/IP-n8n-MCPServer/commit/19f0dbacf78a4b6b301be91bdda1dc54bafd4a42))

### 🐛 Bug Fixes

* **oauth:** bounded unauthenticated endpoints ([07b068e](https://github.com/bauer-group/IP-n8n-MCPServer/commit/07b068eab8243bdfe12ec4f65e4d43ff729b59af))

## [0.3.4](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.3.3...v0.3.4) (2026-08-19)

### 🐛 Bug Fixes

* **security:** emitted a scheme-source for private-use redirect URIs ([875da2f](https://github.com/bauer-group/IP-n8n-MCPServer/commit/875da2f8773660dc9b7744394f0bba60caa8b77e))

## [0.3.3](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.3.2...v0.3.3) (2026-08-19)

### 🐛 Bug Fixes

* **security:** let the consent form reach the client callback ([9741409](https://github.com/bauer-group/IP-n8n-MCPServer/commit/9741409be06404b51a17d2748b7e0a5a84da6ac2))

## [0.3.2](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.3.1...v0.3.2) (2026-08-19)

### 🐛 Bug Fixes

* **oauth:** stopped reporting a completed sign-in as expired ([2057198](https://github.com/bauer-group/IP-n8n-MCPServer/commit/2057198874fd973c8b2f6f47ed329a326d939431))

## [0.3.1](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.3.0...v0.3.1) (2026-08-19)

### 🐛 Bug Fixes

* **oauth:** restored the consent claim on a thrown error ([e7d5f71](https://github.com/bauer-group/IP-n8n-MCPServer/commit/e7d5f711b91f205bff9dbe75262f092d9eda9628))

## [0.3.0](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.2.2...v0.3.0) (2026-08-19)

### 🚀 Features

* **oauth:** logged the expired-consent branch ([160cc06](https://github.com/bauer-group/IP-n8n-MCPServer/commit/160cc06c76d667dd38fc237c5f365e01cb765853))

### 🐛 Bug Fixes

* **oauth:** gave the consent screen thirty minutes ([7cf17a2](https://github.com/bauer-group/IP-n8n-MCPServer/commit/7cf17a259c2367784213a5e8fbc54ae38a310da7))

## [0.2.2](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.2.1...v0.2.2) (2026-08-16)

## [0.2.1](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.2.0...v0.2.1) (2026-08-15)

### 🐛 Bug Fixes

* **ui:** hardened fill and marked the English parts ([f11ef14](https://github.com/bauer-group/IP-n8n-MCPServer/commit/f11ef1476324c090e5806916eee71c05d5636eee))

## [0.2.0](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.1.2...v0.2.0) (2026-08-15)

### 🚀 Features

* **ui:** localized the landing page prose ([8225a42](https://github.com/bauer-group/IP-n8n-MCPServer/commit/8225a42b05b44c0acb74977c512be3d95cd17795))

## [0.1.2](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.1.1...v0.1.2) (2026-08-15)

### 🐛 Bug Fixes

* **oauth:** claimed the consent request atomically ([125ea49](https://github.com/bauer-group/IP-n8n-MCPServer/commit/125ea4922d2e8e03912ef21ce992d0fbdd050781))
* **probe:** named both causes of an API 404 ([e82f17f](https://github.com/bauer-group/IP-n8n-MCPServer/commit/e82f17feccc2e2273e63dbaf99e9d3bc3568ee36))
* **tenant:** bounded and cached DNS resolution ([8bc9f74](https://github.com/bauer-group/IP-n8n-MCPServer/commit/8bc9f74488defd2a02cb3589205551de4e68ee94))

## [0.1.1](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.1.0...v0.1.1) (2026-08-15)

### 🐛 Bug Fixes

* **ci:** declared amd64-only builds instead of claiming arm64 ([326d512](https://github.com/bauer-group/IP-n8n-MCPServer/commit/326d512f514e06ec93bb3e8169ace2501c814460))
* **ci:** passed the release version to the build ([7c51c65](https://github.com/bauer-group/IP-n8n-MCPServer/commit/7c51c65abf4ebc240b0d097d28f9613883ad745c))
* **probe:** separated edge 401 from rejected key ([b993784](https://github.com/bauer-group/IP-n8n-MCPServer/commit/b9937843ef39cf2ca68490bc005a77f1438d0912))
* **ui:** corrected the landing page subtitle ([1ff617f](https://github.com/bauer-group/IP-n8n-MCPServer/commit/1ff617f793eb1c69ff288713f4917f5a83d6a25e))

## [0.1.0](https://github.com/bauer-group/IP-n8n-MCPServer/compare/v0.0.0...v0.1.0) (2026-08-15)

### 🚀 Features

* **deploy:** added three compose flavours and env template ([b1b3d8a](https://github.com/bauer-group/IP-n8n-MCPServer/commit/b1b3d8ad8f8a30c0ce8091965119cc9c88918c7e))
* **gateway:** added OAuth 2.1 gateway for n8n-mcp ([909903f](https://github.com/bauer-group/IP-n8n-MCPServer/commit/909903f85bc7a6ffed736717cf2d61d5cfa07b7d))

### 🐛 Bug Fixes

* **ci:** omitted the pnpm version input entirely ([b30df62](https://github.com/bauer-group/IP-n8n-MCPServer/commit/b30df62245eaac65f23b903885693152ed4dbd5f))
* **ci:** pointed pnpm setup at the app manifest ([94bc373](https://github.com/bauer-group/IP-n8n-MCPServer/commit/94bc37325bec2330571b142a69253990b7e27f17))
* **deps:** bump @types/node ([#3](https://github.com/bauer-group/IP-n8n-MCPServer/issues/3)) ([a66626e](https://github.com/bauer-group/IP-n8n-MCPServer/commit/a66626e0996de80417a414c04da7f96104852c94))

# Changelog

All notable changes to this project are documented here.

This file is maintained by [semantic-release](https://semantic-release.gitbook.io/)
from Conventional Commit messages — see [CONTRIBUTING.md](CONTRIBUTING.md). Do
not edit it by hand; the next release will overwrite the change.
