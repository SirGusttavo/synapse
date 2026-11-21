# 04 — Definição da Stack Tecnológica

## 1. Diagnóstico do Ambiente Local (Baseline Verificado)

Antes de definir dependências, o ambiente de desenvolvimento local foi inspecionado diretamente:

| Componente | Resultado Verificado | Impacto Arquitetural |
| :--- | :--- | :--- |
| **Sistema Operacional** | Windows (`Microsoft Windows NT 10.0.22621.0` — Windows 11) | Foco inicial em Windows/PowerShell; manter núcleo agnóstico de SO. |
| **Node.js** | `v26.13.0` (com `node:sqlite` nativo expondo `Database` e `DatabaseSync`) | Permite persistência SQLite nativa sem compilação C++. |
| **Gerenciador de Pacotes** | `npm 11.20.0` (`pnpm`, `yarn` e `corepack` ausentes) | Usar **npm** como padrão oficial no MVP para zero fricção de setup. |
| **Shells Windows** | PowerShell `7.7.0` (`pwsh`) e Windows PowerShell `5.1.22621.4249` (`powershell.exe`) | `PowerShellAdapter` priorizará `pwsh`, com detecção/fallback explícito para `powershell.exe` 5.1. |
| **Git** | `2.54.0.windows.1` (`user.name` e `user.email` configurados; `init.defaultbranch=master`) | Repositório inicializado explicitamente na branch `main` (`git init -b main`). |
| **Autenticação Git** | Git Credential Manager `2.7.3` autenticado para `SirGusttavo`; remoto `https://github.com/SirGusttavo/synapse.git` acessível e vazio | Pronto para versionamento local; push permanece bloqueado até autorização do operador. |
| **GitHub CLI (`gh`)** | Não instalado | Não depender de `gh` no núcleo; integração GitHub futura usará `@octokit/rest` via API oficial. |
| **Compilador C++ (`cl.exe`)** | Não encontrado no PATH | **Achado crítico:** evita escolher dependências que exijam `node-gyp`/MSVC obrigatório no Windows (ex.: `better-sqlite3` sem prebuild para Node 26). |
| **Docker** | Não instalado | Sandboxing via containers não pode ser pré-requisito do MVP; entra como estratégia opcional na Fase 5. |

---

## 2. Stack Definitiva Recomendada (MVP)

### 2.1 Linguagem, Runtime e Módulo
- **Linguagem:** **TypeScript** (modo `strict: true`, ESM nativo `"type": "module"`).
- **Runtime:** **Node.js** (`>= 22.13.0`, validado localmente em `v26.13.0`).
  - *Nota técnica:* usar `DatabaseSync` de `node:sqlite` (ou wrapper compatível com `Database`/`DatabaseSync`) garante compatibilidade desde Node 22.13+ (onde `--experimental-sqlite` deixou de ser exigido), Node 24 LTS e Node 26+.
- **Gerenciador de pacotes:** **npm** (com `package-lock.json` versionado para builds determinísticos).

### 2.2 Dependências Core do MVP

| Categoria | Tecnologia Recomendada | Licença | Papel no SYNAPSE | Alternativas Avaliadas e Justificativa |
| :--- | :--- | :--- | :--- | :--- |
| **Validação de Dados** | `zod` | MIT | Validação em runtime de config, argumentos de ferramentas, schemas JSON para *tool calling* e respostas externas | Padrão maduro em TypeScript, inferência estática nativa, excelente integração com schemas de ferramentas de LLMs. |
| **Persistência Local** | `node:sqlite` (nativo do Node.js) atrás de interface de repositório | Licença Node.js (MIT) | Armazenar sessões, tarefas, aprovações e trilha de auditoria SQLite | **Comparado a `better-sqlite3` (MIT):** `better-sqlite3` tem maior vazão em benchmarks extremos e funções SQL customizadas, mas exige binário nativo/C++ (`node-gyp` + MSVC) quando não há prebuild para a versão do Node (especialmente no Windows com Node 26 sem `cl.exe`). Como o volume local do SYNAPSE é moderado (logs/sessões/tarefas) e o acesso ficará abstraído por repositórios, `node:sqlite` elimina falhas de instalação mantendo migração trivial caso `better-sqlite3` seja necessário no futuro. |
| **Logs Estruturados** | `pino` (+ `pino-pretty` apenas em `devDependencies`) | MIT | Logs estruturados em JSON com suporte nativo a `redact` para mascaramento de segredos | Baixíssimo overhead, suporte de primeira classe a redaction de campos aninhados e formato JSON facilmente ingerível por ferramentas futuras. |
| **Testes** | `vitest` | MIT | Testes unitários, de integração e de segurança | Suporte nativo a TypeScript/ESM, execução rápida, mocking ergonômico e boa compatibilidade no Windows. |
| **CLI** | `commander` | MIT | Parsing de subcomandos, flags e ajuda estruturada da CLI | Leve, zero magia oculta, amplamente mantido e sem dependências pesadas; permite manter a CLI fina sobre o núcleo. |
| **Execução de Processos** | `node:child_process` (`spawn` com `shell: false`) encapsulado no `ProcessRunner` interno | Nativo (MIT) | Controle fino de processos, streams `stdout`/`stderr`, timeout, `AbortSignal`, env scrubbing e encerramento de árvore no Windows | **Comparado a `execa` (MIT):** `execa` é ótimo, mas no SYNAPSE o `Execution Engine` precisa de controle explícito sobre truncamento por byte em streaming, sanitização estrita de `env`, auditoria e *kill tree* no Windows (`taskkill /PID /T /F`). Um `ProcessRunner` pequeno e dedicado sobre `node:child_process` oferece controle total sem dependência extra. |
| **Integração Git** | Binário `git` invocado via `ProcessRunner` (`shell: false` + arrays de args) | Nativo / Git GPLv2 externo | Operações Git controladas e auditadas com *pre-flight checks* | **Comparado a `simple-git` (MIT):** `simple-git` abstrai bem comandos comuns, mas o SYNAPSE exige bloqueio estrutural de flags, *pre-flight checks*, timeouts unificados e auditoria uniforme via `Execution Engine`. Chamar `git` diretamente sem shell intermediário reduz superfície de ataque e evita dupla abstração. |
| **Qualidade de Código** | `typescript`, `eslint` ou `biome` (ver Decisão Pendente D-05) | MIT / Apache-2.0 | Verificação estática e padronização | Definir ferramenta única na aprovação da Fase 0 antes de criar o setup da Fase 1. |

---

## 3. Avaliação das Integrações Previstas (Instalação Sob Demanda)

> **Regra de engenharia:** nenhuma biblioteca de provedor externo será instalada na Fase 1 ou Fase 2. Na Fase 3 será instalado **apenas o SDK do primeiro provedor escolhido**; demais provedores e GitHub API entram apenas quando suas respectivas entregas forem ativadas (Fase 5).

| Integração | Pacote Oficial | Licença | Manutenção & Status | Compatibilidade & Limitações Conhecidas |
| :--- | :--- | :--- | :--- | :--- |
| **Anthropic API** | `@anthropic-ai/sdk` | Apache-2.0 | SDK oficial mantido pela Anthropic; TypeScript nativo, suporte completo a *tool use* e streaming. | Faturamento por token via Anthropic Console; exige gestão de rate limits (`429`) e janela de contexto; formatos de *tool result* possuem semântica própria (blocos `tool_use`/`tool_result`). |
| **OpenAI API** | `openai` | Apache-2.0 | SDK oficial da OpenAI; amplamente mantido; suporta APIs Responses e Chat Completions, além de provedores *OpenAI-compatible*. | Mudanças frequentes de major/minor e transição gradual de endpoints legados; necessário isolar o adaptador para absorver evolução de API sem vazar tipos do SDK para o núcleo. |
| **Google Gemini API** | `@google/genai` | Apache-2.0 | **SDK oficial atual** do Google para Gemini (substitui o antigo `@google/generative-ai`, que foi descontinuado). | Atenção para **não** adotar o pacote depreciado `@google/generative-ai`. Limitações de JSON Schema suportado em *function declarations* exigem um conversor cuidadoso de Zod para schema compatível. |
| **GitHub API** | `@octokit/rest` | MIT | SDK oficial mantido pelo GitHub (ecossistema Octokit); TypeScript completo, paginação e throttling integrados. | Requer PAT (*Personal Access Token*) com escopos mínimos ou GitHub App; sujeito a rate limits da API REST do GitHub; no MVP não é necessário (operações Git locais já cobrem o fluxo inicial). |

### Compatibilidade de Licenças
Todas as dependências avaliadas utilizam licenças permissivas (**MIT** ou **Apache-2.0**), 100% compatíveis entre si e sem conflitos de copyleft forte para projetos open-source ou comerciais. O binário `git` (GPLv2) e o PowerShell são executados como processos externos do sistema operacional, não sendo linkados ao código do SYNAPSE.

---

## 4. Taxonomia: Modelos, Ferramentas e Integrações de Agentes

Para evitar decisões arquiteturais equivocadas ou expectativas irreais sobre custos e capacidades, o SYNAPSE estabelece uma separação explícita entre **quatro categorias distintas**:

### 4.1 Uso de Modelos por API (Cloud API Providers)
- **Como funciona:** o `Agent Gateway` envia requisições HTTPS autenticadas (via API key) para provedores como Anthropic, OpenAI ou Google Gemini usando seus SDKs oficiais.
- **Modelo de custo:** cobrado por uso (tokens de entrada/saída, cache de prompt quando disponível). **Assinaturas de consumidor final (ex.: Claude Pro, ChatGPT Plus, Gemini Advanced) NÃO concedem créditos ilimitados nem acesso automático a APIs externas.**
- **Implicação no SYNAPSE:** o sistema deve limitar iterações (*max steps*), truncar saídas grandes de ferramentas antes de reenviá-las ao modelo e registrar métricas de uso de tokens retornadas pela API para visibilidade de custo.

### 4.2 Uso de Modelos por Ferramentas Externas / Runtimes Locais
- **Como funciona:** conexão com servidores locais de inferência (ex.: Ollama, LM Studio, vLLM) ou CLIs/proxies externos que expõem endpoint local (muitas vezes compatível com protocolo OpenAI).
- **Características:** sem custo por token em nuvem, mas limitado por hardware local (GPU/RAM), latência e qualidade variável de *tool calling* estruturado em modelos menores.
- **Implicação no SYNAPSE:** suportável na Fase 5 por meio de um adaptador `OpenAICompatibleProvider` na interface `IAgentProvider`, mantendo validação estrita com Zod pois modelos locais erram mais frequentemente argumentos de ferramentas.

### 4.3 Execução Local de Ferramentas (Deterministic Local Tools)
- **Como funciona:** execução direta e determinística no sistema operacional conduzida pelo `Execution Engine` (`PowerShellAdapter`, `File Manager`, `Git Manager`).
- **Características:** não envolve inferência de IA para executar a ação em si; o custo de IA ocorre apenas quando o resultado é serializado e enviado de volta ao modelo. A segurança e previsibilidade dependem 100% da `Security Layer` e dos adaptadores locais do SYNAPSE.

### 4.4 Integrações Nativas com Agentes / Protocolos de Ecossistema
- **Como funciona:** interoperabilidade padronizada com ecossistemas de agentes externos — em especial o **Model Context Protocol (MCP)** ou adaptadores de agentes nativos.
- **Duas direções possíveis (Fase 5+):**
  1. **SYNAPSE como cliente (consumidor):** conectar-se a servidores MCP externos para adicionar novas ferramentas sob a governança da `Security Layer`.
  2. **SYNAPSE como servidor (provedor):** expor as capacidades auditadas e controladas do SYNAPSE (execução, arquivos, Git, aprovações) para clientes/agentes externos compatíveis.
- **Implicação no MVP:** não implementar MCP prematuramente; manter `ToolDefinition` (nome, descrição, schema JSON/Zod, metadados de risco) estruturalmente alinhado ao modelo de ferramentas JSON Schema para facilitar interoperabilidade futura.
