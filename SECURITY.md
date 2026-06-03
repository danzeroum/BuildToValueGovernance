# Política de Segurança

## Reportar uma vulnerabilidade

Se você encontrar uma vulnerabilidade de segurança neste projeto, por favor **não**
abra uma issue pública. Em vez disso, reporte de forma responsável por e-mail:

- **Contato:** danniellau@gmail.com

Inclua, quando possível: descrição do problema, passos para reproduzir, impacto
potencial e qualquer sugestão de correção. Faremos o possível para responder em
tempo hábil e creditá-lo na correção, se desejar.

## Credenciais no repositório

Para evitar confusão durante auditorias:

- Quaisquer valores como `BTV_JWT_SECRET`, `BTV_API_KEY`, `BTV_ADMIN_PASSWORD` ou
  `GF_ADMIN_PASSWORD` presentes nos workflows de CI (`.github/workflows/*`), nos
  arquivos `docker-compose*.yml` e em `*.env.example` são **placeholders de
  teste/desenvolvimento** — não são segredos de produção e não concedem acesso a
  nenhum sistema real.
- Segredos reais nunca são commitados. Arquivos `.env` são ignorados pelo
  `.gitignore`; use os arquivos `*.env.example` como modelo e forneça os valores
  via variáveis de ambiente.
- O pipeline de CI roda **TruffleHog** (`--only-verified`) como gate bloqueante
  para impedir a introdução de segredos verificáveis.

## Boas práticas para contribuidores

- Nunca commite arquivos `.env`, chaves privadas (`*.key`, `*.pem`) ou tokens.
- Configure sua identidade git com um e-mail apropriado antes de contribuir.
- Não realize commits diretamente de servidores de produção como `root`.
