# Arquitetura de Cibersegurança & Threat Model

Este documento apresenta a análise de ameaças e os mecanismos de segurança implementados na suíte **mikrotik-mesh**.

---

## 1. Superfície de Ataque e Ameaças Mitigadas

| Vetor de Ataque | Risco | Mecanismo de Defesa Implementado |
| :--- | :--- | :--- |
| **Timing Attacks na Autenticação** | Dedução de hashes ou senhas medindo variações de milissegundos no processamento. | Comparações em tempo constante estrito via crate `subtle::ConstantTimeEq`. Zero ramificações condicionais dependentes de dados secretos. |
| **Extração de Senhas da RAM (Memory Dumping)** | Vazamento de senhas ou chaves efêmeras após término da sessão. | Tipo `SensitiveBytes` com o trait `ZeroizeOnDrop` da crate `zeroize`. A memória é sobrescrita com zeros assim que sai de escopo. |
| **Ataques de Subgrupos Pequenos em Curvas Elípticas** | Forjar chaves compartilhadas nulas injetando pontos fracos na Curve25519. | Validação estrita do ponto efêmero recebido (`!pt.is_small_order()`). Chaves de baixa ordem são rejeitadas imediatamente. |
| **Estouro de Buffer / Corrupção de Memória** | Pacotes com comprimentos declarados falsos para ler dados fora do buffer (*Heartbleed-like*). | Parsing estritamente bounds-checked sem uso de blocos `unsafe`. Comprimento declarado maior que o buffer gera `ProtoError::EoipLengthMismatch`. |
| **Esgotamento de Recursos (DoS / Flood de Sessão)** | Envio massivo de requisições de sessão forjadas para travar o daemon. | Tabela de sessões finita e assíncrona gerenciada pelo Tokio runtime, com timeout automático para conexões inativas. |

---

## 2. A Bateria de Testes de Segurança

A suíte inclui um comando dedicado para auditoria contínua de segurança:

```bash
cargo run -p mkt-cli -- security-audit
```

Esse comando executa testes unitários nos seguintes pontos:
1. **Verificação de Tempo Constante:** Confirma que comparações de proofs \(M_1\) e \(M_2\) utilizam avaliação bit a bit constante.
2. **Zeroização da Memória:** Confirma a limpeza de buffers sensíveis ao sair de escopo.
3. **Fuzzing de Pacotes Malformados:** Testa resistências contra pacotes com cabeçalhos corrompidos, comprimentos gigantes e TLVs incompletos.
4. **Integridade de Autenticação ZK:** Valida a troca matemática de chaves mútua em ambas as pontas.
