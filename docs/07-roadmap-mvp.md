# 07 — Roadmap Técnico e Critérios de Aceitação do MVP

## 1. Alinhamento Arquitetural Crítico: Segurança Incremental

O roadmap estrutural do produto organiza o desenvolvimento em 6 fases (Fase 0 a Fase 5), com dedicação explícita à segurança na **Fase 4**. Ao mesmo tempo, o projeto estabelece como regra inegociável que **a segurança deve fazer parte da arquitetura desde o primeiro commit**.

Para evitar qualquer conflito entre essas diretrizes, o plano adota **Segurança Incremental**:

- **Fases 1, 2 e 3 (Security Baseline ativa desde o dia 1):** os contratos `IPolicyEngine`, `IApprovalHandler`, `IAuditLogger`, `WorkspaceGuard`, `EnvSanitizer`, `Redactor` e bloqueios de operações destrutivas já nascem integrados ao `Execution Engine`, `File Manager` e `Git Manager`.
- **Fase 4 (Endurecimento Completo de Segurança e Governança):** expande a baseline com política configurável completa por arquivo, fluxo interativo rico de aprovações condicionais, proteção reforçada de credenciais, controles avançados de processos/recursos, consulta completa de auditoria e suíte dedicada de testes adversariais de segurança.

---

## 2. Roadmap Técnico Detalhado

### FASE 0 — Discovery e Arquitetura *(Concluída e Aprovada)*
- [x] Inspeção do ambiente local (Windows 11, Node.js v26.13.0, npm 11.20.0, PowerShell 7.7/5.1, Git 2.54, GCM autenticado).
- [x] Inicialização do repositório Git na branch `main` e configuração do remoto `origin`.
- [x] Documentação completa: visão, requisitos (RF/RNF), arquitetura, diagramas, estrutura de diretórios, stack, matriz de permissões, riscos, roadmap, critérios do MVP e decisões aprovadas (D-01 a D-06).

---

### FASE 1 — Core e Execução Controlada *(Concluída, Auditada e Publicada)*
- [x] Bootstrap do projeto TypeScript (`strict`, ESM), `package.json`, `tsconfig.json`, `vitest.config.ts`, `biome.json`, `.gitignore` e `.env.example`.
- [x] Camada `config` (JSON/JSONC + `.env` isolado + Zod) e persistência SQLite (`node:sqlite` + migrations v1).
- [x] Security Baseline e Auditoria (`PolicyEngine`, `CommandAnalyzer`, `WorkspaceGuard`, `EnvSanitizer`, `Redactor`, Pino + `audit_events`).
- [x] `Execution Engine` (`ToolRegistry`, `NodeProcessRunner` com `shell: false`, timeout, `AbortSignal`, truncamento por byte e encerramento de árvore no Windows).
- [x] `Shell Manager` + `PowerShellAdapter` (`pwsh.exe` prioritário, UTF-8 forçado, wrapper isolado via Base64 e propagação fiel de códigos de saída).
- [x] `Task Manager` (criação de tarefa, máquina de estados validada e cancelamento).
- [x] CLI funcional (`synapse exec`, `synapse status`, `synapse audit`, `synapse config`) consumindo `SynapseRuntime` desacoplado.
- [x] Auditoria técnica e de segurança concluída com suíte adversarial (`tests/security/adversarial-audit.test.ts`).

---

### FASE 2 — Sistema de Arquivos e Git *(Concluída — Aguardando Revisão para Fase 3)*
- [x] `WorkspaceLock` (RWLock justo FIFO por workspace canônico, leituras concorrentes e mutações exclusivas com suporte a `AbortSignal`).
- [x] Amarração criptográfica de parâmetros (`inputDigest` SHA-256 em `AuthorizedOperation`) e revalidação pré-mutação (`PolicyEngine.revalidateAuthorized`).
- [x] `File Manager` tipado (`file.list`, `file.read`, `file.create`, `file.edit`, `file.search`, `file.move`, `file.delete`) com escrita atômica, detecção de binários e confinamento via `WorkspaceGuard` sem depender de `shell.exec`.
- [x] `Git Manager` tipado (`git.status`, `git.diff`, `git.log`, `git.branch`, `git.tag`, `git.init`, `git.clone`, `git.checkout`, `git.add`, `git.commit`, `git.pull`, `git.push`, `git.merge`) via `NodeProcessRunner` com `shell: false`.
- [x] `GitPreflight` com defesa contra *option injection*, bloqueio de commit de arquivos sensíveis e contenção obrigatória de hooks (`-c core.hooksPath=.git/__synapse_disabled_hooks__`, `-c core.fsmonitor=false`, `-c protocol.ext.allow=never`).
- [x] Subcomandos CLI `synapse file` e `synapse git` + testes de integração, concorrência e segurança aprovados no Vitest.

---

### FASE 3 — Agent Gateway e Ciclo Agêntico
- **Escopo técnico:**
  - Interface `IAgentProvider` e modelos normalizados (`SynapseMessage`, `ToolDefinition`, `ToolCall`, `ToolResult`).
  - Persistência de sessões e mensagens no SQLite.
  - Conversor de schemas Zod para definições de ferramentas compatíveis com o provedor.
  - Implementação do **primeiro adaptador oficial** (conforme Decisão D-01: Anthropic, OpenAI ou Google Gemini) com tratamento de erros, timeouts e retries.
  - `AgentLoop` completo (envio ao modelo -> validação -> `Task Manager` -> `Security Layer` -> `Execution Engine` -> retorno do resultado real ao modelo -> repetição até resposta final ou `maxAgentSteps`).
  - Comando CLI interativo de sessão com agente (`synapse chat` / `synapse run`).
- **Critério de conclusão da Fase 3:** ciclo ponta a ponta validado com provedor mock em testes automatizados e teste real controlado com o primeiro provedor configurado, executando ferramentas locais e devolvendo resultados reais ao agente.

---

### FASE 4 — Segurança, Aprovações e Auditoria Completa
- **Escopo técnico:**
  - Motor completo de política configurável (arquivo de política por workspace + política global do usuário, com precedência segura).
  - `CommandAnalyzer` aprofundado para análise estrutural de comandos PowerShell, argumentos, redirecionamentos e operações em lote.
  - `ApprovalBroker` completo com prompt CLI rico (exibindo risco, caminho canônico, comando exato, impacto e opção aprovar/negar com motivo).
  - Reforço da proteção de credenciais (integração opcional com cofre de credenciais conforme Decisão D-03 + verificação anti-leak em `stdout`/`stderr`/logs/SQLite).
  - Consulta e filtragem completa da trilha de auditoria via CLI (`synapse audit --session ... --status ...`).
  - Suíte dedicada `tests/security/` (testes adversariais de path traversal, symlink escape, command injection, vazamento de env, flags destrutivas Git, recusa de aprovação e limites de recursos).
- **Critério de conclusão da Fase 4:** todos os critérios de aceitação do MVP atendidos e validados por testes automatizados e demonstração real.

---

### FASE 5 — Expansão Pós-MVP *(Avaliada após validação do MVP)*
- Novos provedores de IA no `Agent Gateway` (os outros dois entre Anthropic / OpenAI / Gemini + suporte a endpoints locais *OpenAI-compatible* como Ollama).
- Novos adaptadores no `Shell Manager` (`BashAdapter`, `ZshAdapter`) e validação em Linux/macOS.
- Integração com GitHub API (`@octokit/rest`) para automações de PRs/Issues.
- Arquitetura de plugins extensíveis e avaliação de interoperabilidade **MCP** (Model Context Protocol).
- Orquestração de múltiplos agentes com coordenação de workspaces/locks.
- Interface gráfica (Web ou Desktop) consumindo o núcleo e o barramento de eventos sem acoplamento.
- Execução isolada em sandboxes (containers / AppContainer / WSL2) e execução remota se tecnicamente justificada.

---

## 3. Critérios de Aceitação do MVP

O MVP do **SYNAPSE** (conclusão da Fase 4) será considerado **entregue e funcional** somente quando **todos** os critérios abaixo forem verificados empiricamente:

| ID | Critério de Aceitação | Forma de Verificação |
| :--- | :--- | :--- |
| **CA-01** | **Ciclo Agêntico Completo:** o SYNAPSE recebe um objetivo via CLI, comunica-se com o provedor de IA configurado, interpreta ao menos uma chamada de ferramenta (*tool calling*), executa a operação localmente e devolve o resultado real ao agente até a resposta final. | Teste automatizado ponta a ponta (mock provider) + validação real com chave de API do provedor escolhido. |
| **CA-02** | **Execução Controlada com PowerShell:** executa comandos autorizados no PowerShell no Windows capturando corretamente `stdout`, `stderr`, código de saída real e respeitando `timeout` com encerramento completo de processos filhos. | Testes de integração reais no Windows (`pwsh`) incluindo teste de timeout e árvore de processos. |
| **CA-03** | **Gerenciamento Seguro de Arquivos:** lista, lê, cria, edita, pesquisa e move arquivos dentro do workspace, bloqueando tentativas de leitura/escrita fora da raiz (incluindo `..`, caminhos absolutos externos, symlinks e arquivos `.env`/chaves). | Testes de integração e suíte `tests/security/`. |
| **CA-04** | **Operações Git Controladas:** executa operações de leitura (`status`, `diff`, `log`) automaticamente, exige aprovação/validação em mutações configuradas (`commit`, `push`) e bloqueia por padrão `git push --force`, `git reset --hard` e `git clean -fd`. | Testes de integração em repositório Git temporário + testes de política. |
| **CA-05** | **Motor de Permissões e Aprovação Humana:** operações classificadas como `HUMAN_APPROVAL` ou `CONDITIONAL` (quando aplicável) pausam a tarefa, exibem contexto claro na CLI e respeitam fielmente aprovação ou negação do operador, informando o agente em caso de recusa. | Testes automatizados com `MockApprovalHandler` + teste interativo na CLI. |
| **CA-06** | **Histórico e Auditoria Sem Vazamentos:** toda operação (autorizada, falhada ou negada) é persistida no SQLite com metadados completos e pode ser consultada pela CLI; nenhuma API key, senha ou token aparece em logs, banco de auditoria ou ambiente dos subprocessos. | Testes automatizados de auditoria e testes adversariais de redaction/env scrubbing. |
| **CA-07** | **Orquestração e Concorrência Segura:** o `Task Manager` mantém estados consistentes, permite cancelamento de tarefas e evita execução simultânea conflitante de operações mutáveis no mesmo workspace. | Testes unitários de máquina de estados e testes de concorrência com `WorkspaceLock`. |
| **CA-08** | **Qualidade de Engenharia:** build TypeScript (`tsc --noEmit`) sem erros, suíte Vitest (unitários + integração + segurança) 100% aprovada, arquitetura sem dependências circulares e documentação alinhada ao código implementado. | Execução verificada de build, linter e suíte completa de testes. |
