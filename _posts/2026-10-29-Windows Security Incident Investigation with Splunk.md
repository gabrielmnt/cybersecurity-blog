---
layout: post
title: "Investigando um Incidente de Segurança no Windows com Splunk"
date: 2026-10-29
tags: [cybersecurity, blue-team, soc, splunk, incident-response, windows, sysmon]
---

Após construir um laboratório de monitoramento de segurança utilizando Splunk, Sysmon e Windows, o próximo passo natural ao ao qual minha curiosidade levou foi utilizá-lo para algo mais próximo do trabalho realizado por um analista de SOC. Dai surgiu a ideia de como seria investigar um possível incidente de segurança.

Neste projeto, utilizei o laboratório desenvolvido anteriormente para simular uma atividade suspeita em um endpoint Windows. O cenário envolveu tentativas de autenticação malsucedidas, criação de uma nova conta local e posterior adição dessa conta a grupos locais, incluindo o grupo de administradores.

A proposta não foi simplesmente gerar alguns eventos e encontrá-los no Splunk. O objetivo foi praticar o processo de investigação: identificar evidências, relacionar diferentes fontes de logs, entender a sequência dos acontecimentos e, ao final, produzir uma conclusão semelhante à que poderia ser apresentada em uma investigação de incidente.

> **Observação:** todos os eventos deste projeto foram gerados intencionalmente em um ambiente de laboratório controlado. Nenhuma atividade foi realizada contra sistemas de terceiros.

---

## 1. Objetivo do projeto

O primeiro projeto deste laboratório teve como foco a construção de uma infraestrutura básica de monitoramento.

Nesse segundo projeto, a ideia foi utilizar essa infraestrutura para investigar um incidente simulado. O cenário escolhido representa uma situação que pode ser relevante em ambientes Windows: uma conta existente apresenta várias tentativas de autenticação malsucedidas e, posteriormente, uma nova conta local é criada e adicionada a grupos locais, incluindo o grupo `Administrators`

Esse tipo de atividade pode representar diferentes situações em um ambiente real. Pode ser uma ação administrativa legítima, uma configuração realizada por um usuário autorizado ou, em um cenário malicioso, uma tentativa de estabelecer persistência ou obter privilégios adicionais. Por esse motivo, o objetivo da investigação não é simplesmente observar que “uma conta foi criada”, mas entender:

* quem realizou a ação;
* quando ela aconteceu;
* quais eventos ocorreram antes e depois;
* quais comandos foram executados;
* quais privilégios foram atribuídos;
* quais evidências podem indicar comportamento suspeito.

O projeto também serviu para praticar conceitos de investigação e resposta a incidentes utilizando diferentes fontes de telemetria.

---

## 2. Arquitetura utilizada

Para a investigação, foi reutilizada a infraestrutura desenvolvida no projeto anterior.

O laboratório é composto por uma máquina Windows 10 utilizada como host, onde está instalado o Splunk Enterprise, e uma máquina virtual Windows 10 denominada `SOC-WIN10`, onde estão instalados o Sysmon e o Splunk Universal Forwarder. O fluxo de coleta funciona da seguinte maneira:

<div class="diagram">
  <img src="{{ '/assets/images/diagrams/data-flow-PJR2.svg' | relative_url }}"
       alt="Data Flow">
</div>

Essa arquitetura permitiu reutilizar praticamente toda a infraestrutura criada no primeiro projeto.

Não foi necessário instalar novamente o Splunk, configurar novamente o Universal Forwarder ou reconstruir a coleta de logs. O laboratório existente passou a funcionar como a infraestrutura de monitoramento utilizada durante a investigação.

<div class="diagram">
  <img src="{{ '/assets/images/diagrams/Architecture-PJR2.svg' | relative_url }}"
       alt="SOC Monitoring Lab Architecture">
</div>

---

## 3. Preparação do cenário

Antes de iniciar a investigação, era necessário definir um cenário de incidente. A ideia foi simular uma atividade na qual um usuário legítimo da máquina, `vboxuser`, realiza uma sequência de ações relacionadas a uma conta chamada `helpdesk`.

O cenário foi construído de forma a gerar diferentes evidências nos logs do Windows e do Sysmon. A sequência principal foi:

```text
Tentativas de autenticação malsucedidas
                |
       Investigação do usuário
                |
     Criação da conta "helpdesk"
                |
 Adição de "helpdesk" ao grupo Users
                |
Adição de "helpdesk" ao grupo Administrators
                |
      Verificação da nova conta
```

A intenção foi criar uma situação que exigisse a correlação de diferentes eventos para ser compreendida, afinal, em uma investigação real dificilmente um único evento fornece todo o contexto necessário para determinar o que aconteceu.

---

## 4. Primeiras evidências: falhas de autenticação

A primeira parte relevante da investigação foi a identificação de tentativas de login malsucedidas.

No Windows, o Event ID `4625` representa uma falha de autenticação.

Durante a simulação foram geradas várias tentativas de autenticação utilizando a própria máquina como origem.

A pesquisa inicial utilizada no Splunk foi:

```spl
index=main host="SOC-WIN10" EventCode=4625
| rex field=Message "Account Name:\s+(?<FailedAccount>\S+)"
| rex field=Message "Source Network Address:\s+(?<SourceIP>\S+)"
| rex field=Message "Logon Type:\s+(?<ParsedLogonType>\d+)"
| rex field=Message "Failure Reason:\s+(?<ParsedFailureReason>.+)"
| table _time FailedAccount SourceIP ParsedLogonType ParsedFailureReason
| sort _time
```

Essa consulta utiliza `rex` para extrair informações diretamente do campo `Message`. Isso foi necessário porque os eventos do Security Log estavam chegando ao Splunk em formato renderizado em texto, enquanto os eventos do Sysmon eram armazenados em XML.

O resultado mostrou eventos com:

* origem `127.0.0.1`;
* Logon Type `2`;
* falha de autenticação;
* motivo `Unknown user name or bad password`.

A existência de várias falhas próximas umas das outras foi utilizada como o primeiro ponto de partida para a investigação.

É importante destacar que várias falhas de autenticação, isoladamente, não significam necessariamente um ataque. Em um ambiente real, seria necessário considerar o usuário, horário, origem, frequência e contexto da atividade.

<div class="photo" id="FailedAuthentication">
  <img src="{{ '/assets/Images/Screenshots SOC N1/splunk-searches/failed-authentication-analysis.png' | relative_url }}"
       alt="Failed authentication evidence">
</div>

---

## 5. Entendendo os eventos de autenticação

Durante a investigação também foi necessário diferenciar alguns tipos de logon encontrados nos eventos do Windows, e dos valores observados foi o Logon Type `2` que representa um logon interativo, normalmente associado a alguém entrando no sistema localmente por meio da interface de login.

Também foram encontrados eventos envolvendo contas como `SOC-WIN10$`, `DWM-1` e `UMFD-1`, que não foram automaticamente interpretadas como comprometidas, mesmo que a principio possam parecem suspeitas. `SOC-WIN10$`, por exemplo, representa a conta de computador utilizada pelo Windows. Já contas como `DWM-1` e `UMFD-1` estão relacionadas a componentes internos do sistema e a processos de sessão gráfica.

Essa análise foi importante porque uma investigação real exige separar comportamento normal do sistema de evidências potencialmente suspeitas, ou seja, encontrar um evento incomum não significa automaticamente encontrar um incidente. O contexto é essencial.

---

## 6. Investigando a conta envolvida

Após identificar as falhas de autenticação, a investigação passou a buscar outras atividades relacionadas ao usuário envolvido. Uma pesquisa mais ampla foi utilizada para visualizar eventos relacionados à conta:

```spl
index=main host="SOC-WIN10"
| search Account_Name="SOC-WIN10$"
| table _time EventCode Account_Name Logon_Type Authentication_Package Source_Network_Address Failure_Reason
| sort _time
```

A pesquisa mostrou que a conta aparecia em diversos eventos diferentes, por isso, simplesmente pesquisar pelo nome não era suficiente para concluir o que estava acontecendo.

Foi necessário restringir a investigação aos Event IDs relevantes para o cenário e relacionar os resultados com outras evidências, e esse foi um dos primeiros exemplos de como uma busca ampla pode gerar muito ruído durante uma investigação.

---

## 7. Criação de uma nova conta local

A próxima evidência importante foi o Event ID `4720`, que representa a criação de uma conta de usuário. A pesquisa utilizada foi:

```spl
index=main EventCode=4720
| rex field=Message "New Account:\s+Security ID:\s+.*?\s+Account Name:\s+(?<CreatedUser>\S+)"
| search CreatedUser="helpdesk"
| table _time host CreatedUser Account_Name Message
| sort _time
```

O resultado confirmou que uma nova conta chamada `helpdesk` havia sido criada.

O evento também mostrou que a ação foi realizada pelo usuário `vboxuser`, o que é uma informação importante para a investigação porque estabelece uma relação entre o usuário que executou a ação e a conta recém-criada. A partir desse momento, a investigação deixou de estar concentrada apenas nas falhas de autenticação e passou a acompanhar as ações realizadas com a nova conta.

<div class="photo" id="HPDCreated">
  <img src="{{ '/assets/Images/Screenshots SOC N1/splunk-searches/helpdesk-account-created.png' | relative_url }}"
       alt="Account creation evidence">
</div>
---

## 8. Analisando os atributos da conta

O evento `4720` também forneceu informações adicionais sobre a conta criada. Entre os dados observados estavam:

```text
SAM Account Name: helpdesk
Primary Group ID: 513
Account Disabled
'Password Not Required' - Enabled
'Normal Account' - Enabled
```

Essas informações, isoladamente, não são suficientes para afirmar que a conta é maliciosa, entretanto, quando analisadas junto com os demais eventos do incidente, tornam-se relevantes para a investigação.

Um ponto particularmente interessante foi a indicação de que a conta foi criada com a opção `'Password Not Required'`. Esse tipo de detalhe demonstra como um analista não deve olhar apenas para o Event ID, pois os atributos presentes dentro do próprio evento também podem fornecer contexto importante para a investigação. Nesse caso, o significado desse atributo deve ser analisado junto com o restante da atividade observada, e não utilizado isoladamente como prova de comprometimento.

---

## 9. Alteração de grupos locais

Depois da criação da conta, foi investigada a possibilidade de ela ter sido adicionada a algum grupo local.

O Event ID `4732` representa a adição de um membro a um grupo local habilitado para segurança. A pesquisa utilizada foi:

```spl
index=main host="SOC-WIN10" EventCode=4732
| table _time EventCode Account_Name Message
| sort _time
```

Entre os resultados estava o evento correspondente à adição da conta `helpdesk` ao grupo `Users`.

O evento indicava:

```text
Subject Account Name: vboxuser
Member: helpdesk
Group Name: Users
```

Nesse ponto, ainda não havia evidência suficiente para considerar a atividade como um escalonamento de privilégios. O grupo `Users` é um grupo padrão de usuários e a alteração, isoladamente, não representa necessariamente uma atividade maliciosa.

Mesmo assim, ela fazia parte da sequência de eventos que estava sendo investigada.

<div class="photo" id="HPDUser">
  <img src="{{ '/assets/Images/Screenshots SOC N1/splunk-searches/helpdesk-users-group.png' | relative_url }}"
       alt="Account added to Users group">
</div>

---

## 10. Escalonamento de privilégios

A etapa mais importante da investigação ocorreu quando foi identificado que a conta `helpdesk` também havia sido adicionada ao grupo `Administrators` e o mesmo Event ID `4732` foi utilizado para identificar essa alteração. Nesse caso, o evento apresentava:

```text
Subject Account Name: vboxuser
Member: helpdesk
Group Name: Administrators
Group Domain: Builtin
```

A inclusão de uma conta recém-criada no grupo `Administrators` é significativamente mais relevante do ponto de vista de segurança porque o grupo `Administrators` possui privilégios elevados sobre a máquina. Portanto, uma conta criada durante uma sequência de atividades suspeitas e posteriormente adicionada a esse grupo merece investigação. Neste momento, a investigação começou a apresentar uma sequência muito mais significativa:

```text
Falhas de autenticação
        |
Criação de uma nova conta
        |
Alteração de grupos
        |
Adição ao grupo Administrators
```

<div class="photo" id="HPDAdmin">
  <img src="{{ '/assets/Images/Screenshots SOC N1/splunk-searches/helpdesk-added-to-administrators.png' | relative_url }}"
       alt="Account added to Administrators group">
</div>

---

## 11. Investigando os comandos executados

Até esse momento, os eventos do Security Log mostravam principalmente o resultado das ações.

A investigação seguinte buscou descobrir como essas ações haviam sido realizadas. Para isso, foi utilizado o Sysmon.

No projeto anterior, foi identificado que os campos específicos dos eventos do Sysmon não estavam sendo automaticamente extraídos pelo Splunk. Por isso, os dados foram extraídos do XML presente no campo `_raw` utilizando `rex`. A consulta utilizada foi:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where EventID="1" AND like(CommandLine,"%helpdesk%")
| table _time Image CommandLine User
| sort _time
```

O Event ID `1` do Sysmon representa a criação de processos.

A pesquisa revelou diversos comandos relacionados à conta `helpdesk`.

Entre eles estavam:

```text
net user helpdesk P@ssw0rd123! /add

net localgroup Administrators helpdesk /add

net user helpdesk
```

Também foram observados comandos `net1.exe` correspondentes aos comandos executados através de `net.exe`. Esses eventos foram particularmente importantes porque permitiram observar não apenas o resultado da alteração, mas também o comando utilizado para realizá-la.

<div class="photo" id="HPDCommands">
  <img src="{{ '/assets/Images/Screenshots SOC N1/splunk-searches/helpdesk-process-correlation.png' | relative_url }}"
       alt="Sysmon events containing commands related to `helpdesk`.">
</div>

---

## 12. Por que o Sysmon foi importante?

Os eventos do Security Log permitiram identificar que uma conta havia sido criada e adicionada a um grupo privilegiado, porém, eles não mostravam diretamente o comando utilizado para realizar essas ações. O Sysmon complementou essa informação.

Através do Event ID `1`, foi possível observar a execução de comandos como:

```text
net user helpdesk ... /add
```

e:

```text
net localgroup Administrators helpdesk /add
```

Essa correlação entre fontes diferentes é uma das partes mais importantes do projeto: O Security Log mostrou o que aconteceu e o Sysmon ajudou a mostrar como aconteceu. Essa diferença é fundamental em uma investigação.

Uma fonte de telemetria pode mostrar que determinada alteração ocorreu, enquanto outra pode fornecer informações sobre o processo, usuário ou comando responsável pela ação, e é justamente a combinação dessas evidências que permite construir uma visão mais completa do incidente.

---

## 13. Correlação dos eventos

Com as evidências reunidas, foi possível estabelecer uma sequência temporal dos acontecimentos. A atividade observada pode ser resumida da seguinte forma:

```text
18:28 a 18:31
|
|-- Múltiplas tentativas de autenticação malsucedidas
|
18:40
|
|-- Conta "helpdesk" criada
│
|-- "helpdesk" adicionada ao grupo Users
|
|-- "helpdesk" adicionada ao grupo Administrators
|
|-- Conta consultada através de "net user"
```

Além disso, o Sysmon mostrou que as ações foram executadas pelo usuário:

```text
SOC-WIN10\vboxuser
```

A combinação dessas evidências tornou o cenário muito mais significativo do que qualquer evento isolado.O ponto principal da investigação não foi simplesmente encontrar um Event ID específico, mas conectar eventos diferentes e entender como eles se relacionavam temporalmente.

<div class="photo" id="Timeline">
  <img src="{{ '/assets/Images/Screenshots SOC N1/splunk-searches/incident-timeline.png' | relative_url }}"
       alt="incident timeline">
</div>
---

## 14. Dashboard de investigação

Depois da análise individual dos eventos, foi criado um dashboard no Splunk para reunir as principais evidências em uma única interface. O dashboard foi chamado de:

```text
Incident Investigation Dashboard
```

Ele contém quatro painéis principais:

```text
Failed Authentication Attempts

Local Account Creation

Privileged Group Modification

Helpdesk Account Activity
```

A intenção não foi criar um dashboard extremamente sofisticado, mas sim construir uma visão rápida dos eventos relevantes para o incidente. Essa abordagem é importante em um ambiente SOC porque um analista precisa conseguir visualizar rapidamente as principais informações antes de aprofundar a investigação.

<div class="photo" id="Dashboards">
  <img src="{{ '/assets/Images/Screenshots SOC N1/splunk-searches/incident-investigation-dashboard.png' | relative_url }}"
       alt="Dashboards with four panels included">
</div>

---

## 15. O que o dashboard permite observar

O primeiro painel mostra as tentativas de autenticação malsucedidas.

O segundo mostra a criação da conta `helpdesk`.

O terceiro mostra alterações nos grupos locais, incluindo a adição da conta ao grupo `Administrators`.

O quarto painel apresenta a atividade do `helpdesk` observada através dos eventos de criação de processos do Sysmon.

Dessa maneira, o dashboard funciona como um ponto inicial para a investigação.

Em um ambiente real, o analista poderia utilizar essas informações para aprofundar a análise, pesquisar outros eventos associados ao usuário, verificar processos executados antes e depois da atividade e procurar evidências adicionais de persistência ou execução maliciosa. O dashboard, portanto, não substitui a investigação detalhada. Ele serve como uma forma de organizar e visualizar rapidamente as evidências mais relevantes.

---

## 16. Análise do incidente

Depois de correlacionar os eventos, foi possível identificar uma sequência de atividades potencialmente suspeita.

Primeiro foram observadas tentativas de autenticação malsucedidas originadas de `127.0.0.1`.

Posteriormente, uma nova conta chamada `helpdesk` foi criada pelo usuário `vboxuser`.

Em seguida, a conta foi adicionada a grupos locais e, mais significativamente, ao grupo `Administrators`.

Os eventos do Sysmon também mostraram que comandos administrativos foram utilizados para realizar essas ações.

A sequência pode ser resumida da seguinte maneira:

```text
Falhas de autenticação
        |
Criação da conta helpdesk
        |
Alteração de grupos
        |
Adição ao grupo Administrators
        |
Execução de comandos administrativos
```

O conjunto dessas evidências representa um comportamento que merece investigação em um ambiente real, entretanto, é importante destacar uma limitação fundamental: como todas as ações foram realizadas intencionalmente durante um laboratório controlado, não é possível classificar esse cenário como um incidente real.

O objetivo foi reproduzir características que poderiam ser encontradas em um incidente e praticar a metodologia de investigação. Essa distinção é importante porque, em segurança, uma análise responsável precisa separar aquilo que foi efetivamente observado da interpretação que pode ser feita sobre os eventos.

---

## 17. Conclusão da investigação

Com base nas evidências coletadas, o cenário simulado apresentou uma sequência de atividades compatível com uma possível tentativa de obtenção de privilégios e estabelecimento de uma conta com acesso administrativo. A principal evidência foi a combinação entre:

```text
Múltiplas tentativas de autenticação malsucedidas
        +
Criação de uma nova conta local
        +
Adição da conta ao grupo Administrators
        +
Execução de comandos administrativos
```

Nenhuma dessas atividades, isoladamente, necessariamente representa um comprometimento, porém, quando analisadas em conjunto e dentro de uma sequência temporal, elas formam um padrão que justificaria uma investigação mais aprofundada em um ambiente corporativo. Em uma situação real, o próximo passo poderia envolver:

* validação da atividade com o proprietário do endpoint;
* análise de processos adicionais;
* investigação de conexões de rede;
* verificação de mecanismos de persistência;
* análise de outros eventos relacionados ao usuário;
* busca por comportamento semelhante em outros endpoints.

A investigação também poderia ser ampliada para determinar se a conta criada permaneceu ativa, quais ações foram realizadas utilizando seus privilégios e se houve alguma comunicação com outros sistemas.

---

## 18. O que aprendi com o projeto

Este projeto teve como principal objetivo transformar o laboratório desenvolvido anteriormente em um ambiente de investigação. Durante o desenvolvimento, pratiquei principalmente:

* Investigação de eventos do Windows;
* Event IDs relacionados a autenticação e gerenciamento de contas;
* Análise de falhas de autenticação;
* Investigação de criação de usuários locais;
* Análise de alterações em grupos privilegiados;
* Utilização do Sysmon para análise de criação de processos;
* Extração de informações de eventos XML utilizando `rex`;
* Extração de informações do Security Log utilizando `rex`;
* Correlação entre diferentes fontes de logs;
* Construção de uma timeline de incidente;
* Criação de um dashboard de investigação;
* Documentação de uma investigação de segurança.

Mais importante do que aprender comandos específicos do Splunk, o projeto ajudou a entender como diferentes eventos podem ser relacionados para construir uma visão mais completa de uma atividade suspeita. Também ficou mais claro que uma investigação não consiste simplesmente em encontrar um evento “estranho”, é necessário entender o contexto, identificar o responsável pela ação, observar o que aconteceu antes e depois e buscar evidências complementares em outras fontes de telemetria.

---

## 19. Considerações finais

Este projeto foi desenvolvido como uma continuação do laboratório de monitoramento construído anteriormente. No primeiro projeto, o foco estava em construir a infraestrutura: coletar logs, configurar o Sysmon, encaminhar eventos através do Universal Forwarder e realizar consultas no Splunk.

Neste segundo projeto, a infraestrutura passou a ser utilizada para uma finalidade diferente: investigar um incidente simulado. Essa mudança de perspectiva foi importante porque um SOC não existe apenas para coletar grandes quantidades de logs, o objetivo é transformar esses dados em informação útil para identificar, investigar e responder a possíveis incidentes de segurança.

O laboratório ainda é uma representação simplificada de um ambiente corporativo, mas serviu como uma forma prática de exercitar conceitos fundamentais de Blue Team, SIEM e resposta a incidentes. Para um projeto de entrada na área de Cybersecurity, a experiência também mostrou a importância de compreender não apenas as ferramentas, mas o raciocínio necessário para investigar eventos e correlacionar evidências.

O Splunk foi a ferramenta utilizada para centralizar e consultar os dados, mas o principal aprendizado esteve no processo de investigação: partir de uma evidência inicial, formular novas perguntas, buscar eventos relacionados, correlacionar diferentes fontes e construir uma conclusão baseada nas evidências encontradas.
