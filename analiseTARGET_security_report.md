RELATÓRIO DE SEGURANÇA: 0b2eed34-3ad3-401b-bdde-ad5c8a32e3e0
------------------------------------------------------------
[RED TEAM]
Concatenacão de strings em queries detectada; possível SQLi.
Uso de pickle/deserialize em dados não confiáveis.
Exploitability: HIGH

[ANALISADOR ESTÁTICO]
-> SQL_INJECTION (Linha 0): Concatenacão de strings em queries detectada; possível SQLi.
-> INSECURE_DESERIALIZATION (Linha 0): Uso de pickle/deserialize em dados não confiáveis.

[AVALIADOR CENTRAL]
⚠️  2 vulnerabilidade(s) encontrada(s): 1 alta(s), 1 média(s)

[FIX GENERATOR]
-> SQL_INJECTION: Substitua concatenação/interpolação de strings em queries SQL por queries parametrizadas.
-> INSECURE_DESERIALIZATION: Substitua pickle por JSON para dados não confiáveis. Se pickle for necessário, use hmac para verificar integridade.
------------------------------------------------------------
CONCLUSÃO FINAL (RISCO): 23.0/100