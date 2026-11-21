# 08 — Decisões Arquiteturais (Registro de Aprovação Pré-Fase 1)

Este documento registra as decisões tomadas na revisão da Fase 0 que guiam o desenvolvimento do **SYNAPSE**.

| ID | Tópico | Status | Decisão Aprovada |
| :--- | :--- | :--- | :--- |
| **D-01** | Primeiro provedor de IA (Fase 3) | **Adiado para Fase 3** | Adiar escolha do primeiro provedor para a Fase 3; manter a arquitetura 100% independente de fornecedor. Nenhum SDK de IA é integrado na Fase 1. |
| **D-02** | Formato de configurações e políticas | **Aprovado** | **JSON / JSONC** com validação estrita via **Zod**. |
| **D-03** | Armazenamento de credenciais no Windows | **Aprovado** | Utilizar `.env` local protegido e ignorado pelo Git no MVP; planejar integração com o Windows Credential Manager para evolução futura; garantir que segredos nunca sejam propagados indevidamente a processos filhos. |
| **D-04** | Licença do repositório | **Aprovado** | Manter o repositório sem licença por enquanto (`"private": true` no `package.json`, sem arquivo `LICENSE`). |
| **D-05** | Ferramenta de Lint e Formatação | **Aprovado** | **Biome** (`@biomejs/biome`). |
| **D-06** | Política padrão para exclusão de arquivo único | **Aprovado** | Classificada como **`HUMAN_APPROVAL`** por padrão. |
| **D-07** | Push para o repositório remoto | **Aguardando autorização** | Manter todos os commits localmente na branch `main` até autorização explícita do operador. |

---

## Notas de Impacto Técnico

- **D-02 (JSONC):** o carregador de configuração suportará comentários (`//` e `/* ... */`) e vírgulas finais em arquivos `.json`/`.jsonc` antes da validação com Zod, sem depender de parsers pesados de YAML/TOML.
- **D-03 (`.env` seguro):** o carregador de ambiente do SYNAPSE fará leitura isolada de `.env` para a configuração interna do processo pai sem exportar segredos para o ambiente dos subprocessos executados pelo `ProcessRunner`, que passa obrigatoriamente pelo `EnvSanitizer`.
- **D-05 (Biome):** toda entrega da Fase 1 será verificada com `biome check` além de `tsc --noEmit` e `vitest run`.
- **D-06 (`HUMAN_APPROVAL`):** a matriz em [05 — Segurança e Permissões](05-seguranca-permissoes.md) e o `PolicyEngine` refletem `HUMAN_APPROVAL` como padrão para exclusão de arquivo individual no workspace.
