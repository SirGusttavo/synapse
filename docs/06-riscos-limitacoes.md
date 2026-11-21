# 06 — Análise de Riscos e Limitações

Este documento mapeia riscos técnicos, de segurança, operacionais e de produto identificados durante a Fase 0, acompanhados de mitigações concretas e limitações conhecidas do MVP.

---

## 1. Matriz de Riscos

| ID | Categoria | Risco | Probabilidade | Impacto | Mitigação Arquitetural |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **R-01** | Segurança | **Prompt Injection indireta** (conteúdo malicioso em arquivos, diffs ou saídas de comandos induzindo o agente a executar ações perigosas) | Alta | Crítico | O modelo **nunca** detém autoridade direta: toda ação passa pela `Security Layer`, `WorkspaceGuard`, `CommandAnalyzer` e aprovação humana obrigatória para operações sensíveis. |
| **R-02** | Segurança | **Bypass de validação no PowerShell** via aliases (`rm`, `ri`, `iex`), codificação Base64 (`-EncodedCommand`), subexpressões (`$()`) ou scripts externos | Alta | Crítico | Preferir ferramentas tipadas (`File Manager`, `Git Manager`) sobre shell genérico; no `Shell Manager`, analisar tokens/operadores suspeitos, bloquear `-EncodedCommand`/`iex`/`RunAs` por padrão e exigir aprovação humana fora da allowlist. |
| **R-03** | Segurança | **Escape do workspace** via `..`, caminhos UNC (`\\?\`, `\\server\share`), drives alternativos (`D:\`), links simbólicos ou junctions NTFS | Média | Alto | `WorkspaceGuard` resolve caminho canônico (`path.resolve` + `fs.realpath`), compara com comparação case-insensitive no Windows e valida prefixo completo de diretório + bloqueio de UNC/escape. |
| **R-04** | Segurança | **Vazamento de credenciais** para subprocessos, logs, SQLite ou contexto retornado ao provedor de IA | Média | Crítico | `EnvSanitizer` remove segredos do `env` filho; `File Manager` bloqueia `.env`/chaves privadas; `Redactor` centralizado mascara padrões sensíveis antes de logs Pino, SQLite e `ToolResult`. |
| **R-05** | Operacional | **Processos órfãos no Windows** após timeout ou cancelamento (ex.: `npm test` gera filhos que sobrevivem ao `child.kill()` simples) | Alta | Alto | `ProcessRunner` implementa encerramento explícito de árvore no Windows (`taskkill /PID <pid> /T /F`) e testes de integração verificando limpeza de processos filhos. |
| **R-06** | Operacional | **Corrupção ou conflito de estado Git/FS** por tarefas concorrentes no mesmo workspace (ex.: `.git/index.lock`) | Média | Alto | `Task Manager` serializa operações mutáveis via `WorkspaceLock` e `GitPreflight` verifica estado do repositório antes de executar mutações. |
| **R-07** | Custos / IA | **Loop infinito de *tool calling* ou explosão de tokens** por saídas enormes de shell/arquivos | Alta | Médio | Limite rígido de iterações (`maxAgentSteps`), teto de bytes em `stdout`/`stderr` e leituras de arquivos com truncamento explícito, mais telemetria de tokens por sessão. |
| **R-08** | Plataforma | **Encoding e exit codes inconsistentes no PowerShell** (CP850/CP1252 vs UTF-8 no Windows; erros não-terminantes retornando exit code `0`) | Alta | Médio | Forçar UTF-8 explícito no `PowerShellAdapter`, padronizar tratamento de `$LASTEXITCODE` e `$?`, e validar em testes reais com `pwsh` 7.7 e `powershell.exe` 5.1. |
| **R-09** | Dependência | **Evolução da API `node:sqlite`** entre versões do Node.js (ex.: `DatabaseSync` vs `Database` no Node 26.11+) | Baixa | Médio | Isolar 100% do acesso SQLite atrás de `src/storage/database.ts` e interfaces de repositório; usar API compatível com Node 22.13+ / 24 / 26 e validar via testes automatizados. |
| **R-10** | Produto | **Acoplamento prematuro a um provedor de IA** (vazar tipos ou semântica específica de Anthropic/OpenAI/Gemini para o núcleo) | Média | Alto | Fronteira estrita em `IAgentProvider` + tipos internos normalizados (`SynapseMessage`, `ToolCall`, `ToolResult`); testes do `AgentLoop` com provedor mock independente de SDK. |
| **R-11** | Arquitetura | **Atrasar a implementação de segurança até a Fase 4** e acumular dívida estrutural nas Fases 1–3 | Média | Crítico | Adotar **Security Baseline desde a Fase 1** (interfaces `IPolicyEngine`, `WorkspaceGuard`, `EnvSanitizer`, `Redactor` e bloqueios críticos já ativos), usando a Fase 4 para endurecimento completo e testes adversariais. |

---

## 2. Limitações Conhecidas e Assumidas no MVP

Ser explícito sobre limitações evita falsa sensação de segurança e orienta corretamente o uso do MVP:

1. **Isolamento ao nível de processo (sem sandbox de kernel/container no MVP):**
   - O ambiente local não possui Docker instalado e o MVP executa processos diretamente sob a conta do usuário local do Windows.
   - Consequência: um script local autorizado pelo usuário (ex.: `npm install` com `postinstall` malicioso ou um teste que acessa a rede/arquivos) ainda terá as permissões do usuário local do SO.
   - Mitigação no MVP: transparência máxima nas aprovações, env scrubbing e bloqueios preventivos; evolução prevista para sandboxes reais (containers/AppContainer/WSL2) na Fase 5.
2. **Suporte inicial concentrado em Windows + PowerShell:**
   - Embora o núcleo seja multiplataforma por design, o adaptador validado no MVP será o `PowerShellAdapter`. Bash e Zsh serão implementados e testados na Fase 5.
3. **Um provedor de IA ativo na Fase 3:**
   - O `Agent Gateway` será projetado para múltiplos provedores, mas o MVP validará primeiro um adaptador oficial completo para evitar dispersão de esforço e custos múltiplos de API durante o desenvolvimento inicial.
4. **Custo de APIs sob responsabilidade do operador:**
   - O SYNAPSE não fornece créditos de IA nem contorna limites de faturamento dos provedores. Requer chave de API válida configurada pelo usuário para testes reais com modelos em nuvem (testes automatizados em CI/dev usarão mocks determinísticos).
5. **Interface apenas via CLI no MVP:**
   - Monitoramento em tempo real via Web/Desktop UI fica para a Fase 5, consumindo o mesmo barramento de eventos e serviços do núcleo.
6. **Ausência de `gh` CLI no ambiente local:**
   - Automação avançada de Pull Requests/Issues no GitHub não faz parte do núcleo Git do MVP; será integrada via `@octokit/rest` em etapa posterior quando priorizada.
