# Testes de falha

Substitua os campos de resultado pelas evidências reais após executar os testes.

| Caso | Teste | Resultado esperado | Resultado observado |
|---|---|---|---|
| 1 | Retorno sem cookie de transação | Recusar e não criar sessão | PREENCHER |
| 2 | Alteração de um caractere de state | Recusar antes da troca do código | PREENCHER |
| 3 | Reutilização de callback | Recusar porque a transação foi removida | PREENCHER |
| 4 | Sessão expirada no D1 | `/api/me` retorna 401 | PREENCHER |
| 5 | Logout com Origin diferente | Recusar operação | PREENCHER |
| 6 | Cookie de sessão revogado | `/api/me` retorna 401 | PREENCHER |
