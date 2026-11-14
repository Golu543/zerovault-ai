# 🛡️ ZeroVault AI
**Cryptographic Blind-Proxy & Vandermonde Secret-Sharded Execution Engine for Privacy-Preserving AI Pipelines**

Built for the **Mathematics for Systems Security Hackathon** (*AI Pipeline Secret Sharing Track*).

---

## 🚨 Real-World Problem
When enterprises and developers use hosted LLM APIs (Google Gemini, OpenAI, AWS Bedrock) for DevSecOps or financial workflows, sensitive **Master Keys, Database Credentials, and Confidential Numbers** are sent in plaintext to third-party inference servers—exposing organizations to log leaks, data retention risks, and memory dump side-channel attacks.

## 🔐 Mathematical & Cryptographic Architecture
ZeroVault AI intercepts high-entropy secrets and numerical data locally before any network call leaves `localhost`:

1. **Shamir's Secret Sharing over Finite Field $\mathbb{GF}(2^{61}-1)$ (Number Theory):**
   - Splits intercepted secrets into $n=5$ polynomial shards $f(x) = (S + a_1 x + a_2 x^2) \pmod{2^{61}-1}$ with threshold $k=3$.
   - Replaces raw credentials with blind tokens (`<<ZV_SHARD_TOKEN_0x01>>`), guaranteeing **0% Master Key Exposure** to the LLM host.
2. **Vandermonde Matrix Inversion & Ephemeral RAM Zeroization (Linear Algebra):**
   - Reconstructs secrets locally using Gaussian elimination over $\mathbb{GF}(p)$ ($\mathbf{V}\mathbf{a} \equiv \mathbf{y} \pmod p$) in microseconds and immediately overwrites RAM buffers (`memset(0)`) to mitigate side-channel attacks.
3. **Paillier Additive Homomorphic Encryption:**
   - Allows the AI pipeline to aggregate encrypted financial numbers ($E(m_1) \cdot E(m_2) \bmod n^2 = E(m_1 + m_2)$) without decrypting them.

---

## 🚀 Run Locally
```bash
npm install
npm run dev