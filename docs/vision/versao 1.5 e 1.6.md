## O que é o BuildToValue?

Imagine um **porteiro inteligente** que fica entre um robô de IA e os usuários. Toda vez que o robô vai responder algo, o porteiro verifica se a resposta contém dados sensíveis (como CPF, e-mail, cartão de crédito) e decide se deve liberar, bloquear ou mascarar essa informação.

---

## O que fizemos na v1.5 (o alicerce)

Cinco melhorias no "motor" do porteiro:

1. **Declaração de viés** — Agora cada módulo de detecção é obrigado a dizer "eu erro X% das vezes". É como um médico declarar a margem de erro de um exame. Transparência.

2. **Rastreamento completo** — O sistema tinha espaço para registrar apenas 8 módulos em funcionamento. Expandimos para 32, porque já temos 11 e vão crescer.

3. **Processamento em lote** — Antes era um input por vez. Agora pode enviar 100 de uma vez, com controle de timeout (se demorar demais, para e avisa em vez de travar).

4. **Recuperação após crash** — Se o sistema cai, ao reiniciar ele lê o "diário de bordo" (WAL) e reconstrói tudo em menos de 5 segundos. Também verifica se alguém adulterou os registros.

5. **Pipeline organizado** — O porteiro agora trabalha em 3 etapas ordenadas: primeiro decodifica truques (base64, leetspeak), depois analisa estatísticas, depois detecta dados sensíveis. Antes era tudo misturado.

**Resultado:** 63+ testes passando, tudo verificável.

---

## O que faremos na v1.6 (as regras)

Três novos componentes:

1. **Motor de regras (PolicyEngine)** — Hoje o porteiro só detecta. Na v1.6 ele vai consultar regras escritas em YAML tipo "se contém CPF E o usuário não é admin → BLOQUEAR". Regras editáveis sem recompilar código.

2. **Guarda de saída (OutputGuard)** — Além de vigiar o que entra, vai vigiar o que sai. Se a IA gerar uma resposta com CPF exposto, o guarda mascara antes de entregar ao usuário.

3. **Desobfuscador v2 (chaining)** — Hoje detecta base64, hex e leetspeak separados. Na v1.6, detecta truques em cadeia (ex: alguém codifica um CPF em base64, depois codifica o resultado em hex).

**Em resumo:** v1.5 construiu a infraestrutura confiável. v1.6 adiciona a inteligência de decisão.