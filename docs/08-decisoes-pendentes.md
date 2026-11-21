# 08 — Decisões Arquiteturais Pendentes (Pré-Fase 1)

Conforme o princípio de **não inventar requisitos nem assumir decisões sem validação**, este documento lista os pontos em aberto que precisam da sua definição (ou confirmação da recomendação proposta) antes de iniciarmos a **Fase 1**.

---

## D-01 — Primeiro Provedor de IA para a Fase 3 (MVP)

**Contexto:** O `Agent Gateway` será agnóstico de provedor desde o início, mas na Fase 3 implementaremos um único adaptador oficial para validar o ciclo completo de *tool calling* sem dispersão de esforço.

| Opção | SDK Oficial | Prós | Contras |
| :--- | :--- | :--- | :--- |
| **A. Anthropic (Claude)** | `@anthropic-ai/sdk` | Excelente confiabilidade em *tool calling* e raciocínio de código; API limpa e previsível. | Exige conta/créditos ativos na Anthropic Console (separado de assinatura Claude Pro). |
| **B. OpenAI** | `openai` | SDK também serve como base para futuros provedores *OpenAI-compatible* (ex.: Ollama, OpenRouter). | Transição entre APIs Chat Completions e Responses exige cuidado no contrato do adaptador. |
| **C. Google Gemini** | `@google/genai` | Bom custo-benefício e tier gratuito limitado para testes iniciais na AI Studio API. | Restrições pontuais em JSON Schema para *function declarations* exigem tradutor dedicado. |

**Recomendação técnica:** escolher o provedor para o qual você já possui (ou pretende manter) **chave de API ativa** para testes reais na Fase 3. Se ainda não houver preferência definida por billing, **Anthropic (`@anthropic-ai/sdk`)** ou **OpenAI (`openai`)** oferecem o fluxo de *tool calling* mais maduro e direto.

---

## D-02 — Formato de Arquivos de Configuração e Políticas

**Contexto:** O SYNAPSE precisará de configuração global do usuário (ex.: `~/.synapse/`) e configuração local por workspace (ex.: `.synapse/config.*` e `.synapse/policy.*`).

| Opção | Prós | Contras |
| :--- | :--- | :--- |
| **A. JSON / JSONC (Recomendada para o MVP)** | Zero dependência externa (ou parser mínimo para comentários), suporte nativo a JSON Schema para autocomplete em editores, validação direta com Zod. | Menos ergonômico que YAML para comentários extensos se usar JSON puro. |
| **B. YAML (`yaml`)** | Muito legível para políticas humanas e comentários. | Adiciona dependência de parser e armadilhas conhecidas de tipagem implícita do YAML. |
| **C. TOML** | Claro e sem ambiguidades de indentação. | Menos familiar no ecossistema Node/TypeScript do que JSON/YAML. |

**Recomendação técnica:** **JSON** (com suporte opcional a JSONC ou chave `$schema` gerada a partir do Zod) para simplicidade e zero dependências extras no MVP.

---

## D-03 — Armazenamento de Credenciais de API no Windows

**Contexto:** Chaves de API dos provedores nunca devem ser versionadas nem gravadas em texto puro no repositório.

| Opção | Prós | Contras |
| :--- | :--- | :--- |
| **A. Variáveis de ambiente locais no MVP + opção de Windows Credential Manager na Fase 4 (Recomendada)** | Zero dependência nativa na Fase 1–3; compatível com CI e multiplataforma; evolui para cofre do SO na Fase 4. | Exige que o usuário exporte variáveis de ambiente ou use `.env` local (fora do Git) durante o MVP inicial. |
| **B. Cofre do SO obrigatório desde a Fase 1 (DPAPI / Credential Manager)** | Segredos criptografados em repouso desde o início. | Complexidade extra no setup inicial no Windows (evitando addons nativos C++, exigiria ponte segura com PowerShell/DPAPI). |

**Recomendação técnica:** **Opção A** — variáveis de ambiente + suporte a carregamento controlado de `.env` local (protegido contra leitura pelo agente e removido de subprocessos) no MVP inicial, adicionando integração opcional com cofre de credenciais do Windows (DPAPI / Credential Manager) na Fase 4.

---

## D-04 — Escopo da Licença do Repositório SYNAPSE

**Contexto:** Todas as dependências avaliadas são MIT ou Apache-2.0, mas o repositório `SirGusttavo/synapse` ainda não possui arquivo `LICENSE`.

- **Opções:** MIT, Apache-2.0, ou projeto proprietário/sem licença open-source por enquanto.
- **Recomendação técnica:** definir explicitamente antes do primeiro push público (ex.: **MIT** para máxima adoção ou **Apache-2.0** se quiser proteção explícita de patentes).

---

## D-05 — Ferramenta de Lint e Formatação (Fase 1)

**Contexto:** Precisamos padronizar estilo e análise estática desde o primeiro código TypeScript na Fase 1.

| Opção | Prós | Contras |
| :--- | :--- | :--- |
| **A. Biome (Recomendada)** | Único binário rápido (lint + format), configuração mínima, excelente suporte a TypeScript. | Ecossistema de plugins menor que ESLint (não é problema para um projeto TypeScript limpo). |
| **B. ESLint + Prettier** | Padrão histórico com amplo ecossistema de regras customizadas. | Mais pacotes e configuração mais verbosa. |

**Recomendação técnica:** **Biome** pela simplicidade, velocidade e menor número de dependências transitivas.

---

## D-06 — Política Padrão para Exclusão de Arquivo Único no Workspace

**Contexto:** A especificação define:
- "Excluir arquivos mediante autorização" (File Manager);
- "Exclusão de diretórios" em `AUTORIZAÇÃO HUMANA`;
- "Exclusão indiscriminada de arquivos" em `BLOQUEADO POR PADRÃO`.

**Pergunta:** para **exclusão de um único arquivo dentro do workspace**, você prefere classificar por padrão como:
- **Opção A (Recomendada):** `HUMAN_APPROVAL` (sempre confirmar antes de deletar qualquer arquivo).
- **Opção B:** `CONDITIONAL` (permitir automático apenas para arquivos temporários/criados na mesma sessão e exigir confirmação para os demais).

---

## D-07 — Push dos Commits da Fase 0 para o Repositório Remoto

**Contexto:** Os commits da Fase 0 foram versionados localmente na branch `main` com o remoto `origin` apontando para `https://github.com/SirGusttavo/synapse.git`. Conforme sua regra, nenhum `git push` foi executado.

**Ação aguardada:** confirmar se deseja autorizar `git push -u origin main` agora ou após eventuais ajustes na documentação da Fase 0.
