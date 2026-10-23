# IoT CyberShield — working software prototype

A small full-stack Node.js/Express prototype for a secure OTA update hackathon demo. It includes a responsive cream/terracotta UI, virtual device registry, backend endpoints, a SHA-256 file hash calculation in the browser, firmware version policy checks, request-ID replay checks, attack scenarios, and event logs.

## Run locally

Requirements: Node.js 18+

```bash
npm install
npm start
```

Open `http://localhost:8080`.

## Important scope notes

- Virtual devices only; this app does not connect to physical IoT hardware.
- Firmware files are hashed but never executed.
- The SHA-256 check only confirms integrity when a trusted reference hash is supplied.
- Signature verification is represented by an explicitly supplied verifier result; this starter does not yet implement a full public-key signature verification workflow.
- Events and replay request IDs are held in server memory and reset when the server restarts. Add a database for persistent records before treating this as more than a demo.
- Attack scenarios are controlled simulations, not real-world device attacks.

## Google AI Studio

In Google AI Studio Build mode, use **Add files (+) → Import from GitHub** if you put this project in a GitHub repository. Alternatively, use the project files as context and ask AI Studio to continue the implementation. Build mode supports natural-language app creation and GitHub import; direct ZIP-as-project import may not be available in every interface.
