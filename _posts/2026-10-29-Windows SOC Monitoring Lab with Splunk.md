---
layout: post
title: "Construindo um SOC Monitoring Lab com Splunk, Sysmon e Windows"
date: 2026-10-29
tags: [soc, splunk, sysmon, blue-team]
---

Quando comecei a estudar Cybersecurity, uma das coisas que mais chamou minha atenção foi a quantidade de informações que um analista de segurança precisa interpretar diariamente.

Uma máquina gera uma grande quantidade de eventos: logins, processos sendo executados, serviços iniciados, alterações de usuários, conexões de rede e diversas outras atividades. Para um analista SOC, o desafio não é apenas ter acesso a esses dados, mas conseguir centralizá-los, pesquisá-los e transformá-los em informações úteis para identificar comportamentos que merecem investigação.

Pensando nisso, resolvi desenvolver este laboratório: um ambiente simples de monitoramento utilizando Splunk Enterprise, Windows Event Logs, Sysmon e Splunk Universal Forwarder. Não tinha como intuito construir um SOC corporativo completo, mas gostaria de criar uma pequena representação de uma arquitetura de monitoramento para que fosse possível de colocar em prática conceitos que eu vinha estudando.

## O objetivo do projeto

O principal objetivo foi construir um ambiente capaz de coletar eventos de uma máquina Windows, centralizá-los em um SIEM e posteriormente realizar pesquisas e visualizações sobre esses dados.

Para isso, o laboratório foi dividido em duas máquinas.

A máquina principal, executando Windows 10, seria responsável por executar o Splunk Enterprise. A segunda máquina seria uma máquina virtual Windows 10, chamada `SOC-WIN10`, representando o endpoint monitorado.

Na máquina virtual, o Sysmon seria utilizado para gerar uma telemetria mais detalhada do sistema operacional. O Splunk Universal Forwarder ficaria responsável por coletar os eventos da VM e encaminhá-los para o Splunk Enterprise.

De forma simplificada, o fluxo ficou assim:

<div class="diagram">
  <img src="{{ '/assets/images/diagrams/data-flow-PJR1.svg' | relative_url }}"
       alt="Data Flow">
</div>

A ideia é semelhante ao princípio utilizado em ambientes corporativos: endpoints geram telemetria, agentes coletam esses dados e um SIEM centraliza as informações para que possam ser analisadas.

### Arquitetura do laboratório

<div class="diagram">
  <img src="{{ '/assets/images/diagrams/Architecture-PJR1.svg' | relative_url }}"
       alt="SOC Monitoring Lab Architecture">
</div>


## Construindo o ambiente

### Splunk Enterprise

O primeiro componente instalado foi o Splunk Enterprise na máquina principal. A instalação foi realizada utilizando as configurações padrão e, depois da instalação, a interface Web do Splunk foi acessada localmente através da porta 8000:

```text
http://localhost:8000
```

A partir da interface Web é possível realizar pesquisas, visualizar eventos, configurar a ingestão de dados e posteriormente construir dashboards.

<div class="photo" id="SCRinterface">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/splunk-search-interface.png' | relative_url }}"
       alt="Search Interface Splunk">
</div>

Como este é um laboratório utilizado apenas durante meus estudos, optei também por configurar o serviço do Splunk para iniciar manualmente, dessa forma, o Splunk não permanece executando constantemente em segundo plano quando o laboratório não está sendo utilizado. É uma pequena decisão de administração do ambiente, mas ajuda a manter o laboratório mais leve para uso cotidiano.

### Preparando o endpoint

Depois de instalar o Splunk, o próximo passo foi preparar a máquina que seria monitorada.

Foi criada uma máquina virtual Windows 10 com o hostname:

```text
SOC-WIN10
```

Essa máquina representa o endpoint de uma organização que possui seus eventos enviados para um servidor central de monitoramento.

### Sysmon

O Sysmon foi instalado na máquina virtual para aumentar a quantidade e a qualidade da telemetria disponível.

Os Windows Event Logs nativos já fornecem informações importantes, principalmente sobre autenticação, contas e atividades do sistema. Entretanto, o Sysmon fornece eventos mais detalhados sobre atividades realizadas no endpoint.

Para este laboratório, foi utilizada como base a configuração do projeto SwiftOnSecurity.

A instalação foi realizada com:

```text
sysmon64.exe -accepteula -i sysmon-config.xml
```

Após a instalação, os eventos passaram a aparecer no seguinte canal:

```text
Applications and Services Logs
- Microsoft
- Windows
- Sysmon
- Operational
```

<div class="photo" id="EventViewer">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/sysmon-installed-eventviewer.png' | relative_url }}"
       alt="Event viewer">
</div>


Uma das razões para incluir o Sysmon no laboratório foi poder observar atividades que seriam difíceis de analisar apenas com os logs tradicionais do Windows. Entre os eventos disponíveis estão informações relacionadas à criação de processos, carregamento de imagens, conexões de rede e outras atividades do endpoint, oque é particularmente útil em um ambiente de SOC, pois fornece mais contexto ao analista durante uma investigação.

Por exemplo, saber apenas que um usuário estava conectado ao computador fornece uma quantidade limitada de informação, mas saber que determinado usuário executou um processo específico, com determinado caminho e outros atributos associados, fornece muito mais contexto para uma investigação.

## Coletando os eventos com o Universal Forwarder

Com o Sysmon funcionando, ainda existia um problema: os eventos estavam na máquina virtual, enquanto o Splunk Enterprise estava instalado na máquina principal. Era necessário algum mecanismo para transportar esses eventos entre as duas máquinas. e para isso foi utilizado o `Splunk Universal Forwarder`.

O Universal Forwarder é um agente leve utilizado para coletar dados em endpoints e encaminhá-los para uma instância do Splunk. No laboratório, ele foi instalado na `SOC-WIN10`.

A configuração foi dividida principalmente entre dois arquivos:

```text
inputs.conf
outputs.conf
```

O `inputs.conf` define quais dados devem ser coletados, enquanto o `outputs.conf` define para onde esses dados devem ser enviados.

A comunicação entre o Forwarder e o Splunk Enterprise foi configurada através da porta TCP `9997`.

## Quando as coisas não funcionam como esperado

Essa acabou sendo uma parte muito interessantes do projeto. A implementação não funcionou perfeitamente na primeira tentativa e alguns problemas precisaram ser investigados antes que a arquitetura funcionasse corretamente.

Em vez de considerar isso apenas como erros de configuração, decidi documentá-los porque eles representam uma parte importante da experiência prática adquirida durante o laboratório, além de ressaltar que nem tudo funciona perfeitamente em uma primeira tentativa.

### IP incorreto no `outputs.conf`

O primeiro problema estava relacionado à configuração do `outputs.conf`. O endereço configurado inicialmente não correspondia à interface de rede correta da máquina principal e, como consequência, o Universal Forwarder não conseguia encaminhar corretamente os eventos para o Splunk Enterprise.

Foi necessário identificar qual interface da máquina principal deveria ser utilizada pela comunicação com a máquina virtual, atualizar a configuração e após a alteração, o encaminhamento dos eventos passou a funcionar.

<div class="photo" id="outputs">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/Outputs.conf.png' | relative_url }}"
       alt="Outputs config">
</div>


### Índice inexistente

O segundo problema estava relacionado ao índice utilizado pelo `inputs.conf`.

Inicialmente os eventos estavam configurados para serem enviados para:

```text
wineventlog
```

Porém, esse índice não existia na instância do Splunk. A solução foi alterar as entradas para utilizar o índice padrão:

```text
main
```

Depois disso, os eventos começaram a aparecer corretamente nas pesquisas.

Esse problema acabou me mostrando que em um SIEM, receber dados não significa necessariamente que eles estão sendo armazenados e indexados da maneira esperada.

### Problemas de permissão

O terceiro problema foi relacionado às permissões do serviço do Universal Forwarder. O serviço estava sendo executado utilizando a conta:

```text
NT SERVICE\SplunkForwarder
```

Essa conta não possuía as permissões necessárias para acessar o canal do Sysmon.

O problema foi identificado através do arquivo `splunkd.log`, onde apareceu uma mensagem relacionada à impossibilidade de inscrição no canal do Windows Event Log:

```text
Could not subscribe to Windows Event Log channel
errorCode=5 (Access is denied)
```

Como consequência, os logs Application, Security e System eram coletados, mas os eventos do Sysmon não. A solução foi alterar a conta utilizada pelo serviço para:

```text
Local System
```

Depois dessa alteração, o Forwarder conseguiu acessar o canal do Sysmon.

Esse foi um dos problemas mais interessantes do projeto porque mostrou que uma falha de coleta não necessariamente significa que a configuração do Splunk está errada. Permissões do próprio sistema operacional também precisam ser consideradas.

## Validando a coleta

Depois de resolver os problemas de configuração, chegou o momento de verificar se os dados estavam realmente chegando ao Splunk. A primeira pesquisa utilizada foi:

```spl
index=main
```

Essa pesquisa permitiu verificar a quantidade de eventos disponíveis e começar a explorar a estrutura dos dados.

Em determinado momento do projeto, o índice apresentava aproximadamente:

```text
8,045 events
```

com eventos provenientes de dois hosts:

```text
Host Machine
SOC-WIN10
```

As principais fontes observadas foram:

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational
WinEventLog:Security
WinEventLog:System
WinEventLog:Application
```

<div class="photo" id="MainEvents">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/search-main-events.png' | relative_url }}"
       alt="splunk search main events">
</div>

Essa foi a primeira confirmação de que o fluxo completo estava funcionando: os eventos eram gerados no endpoint, coletados pelo Forwarder, enviados pela rede e finalmente disponibilizados no Splunk para análise.

## Explorando os Event IDs

Depois de confirmar que os eventos estavam sendo coletados, comecei a analisar quais tipos de eventos estavam presentes. Uma das consultas utilizadas foi:

```spl
index=main
| stats count by EventCode
| sort -count
```

Essa consulta permite observar a distribuição dos Event IDs presentes nos dados.

Entre os eventos observados estavam:

```text
4624
5379
4672
4799
```

Esses eventos fornecem diferentes tipos de informações relacionadas à atividade do Windows, incluindo autenticação e atividades relacionadas a privilégios e grupos.

<div class="photo" id="EventsbyCount">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/eventcode-distribution.png' | relative_url }}"
       alt="EventID by number of occurrences">
</div>


## Investigando os eventos Sysmon

Essa foi uma das etapas em que precisei mudar um pouco a maneira de pensar sobre os dados. Inicialmente, eu esperava conseguir executar uma consulta como:

```spl
index=main EventCode=1
| table _time Image User Computer
```

e obter diretamente os campos `Image`, `User` e `Computer`. Entretanto, o resultado não era o esperado.

Isso aconteceu porque na configuração utilizada no laboratório as informações específicas do Sysmon estavam presentes dentro do XML bruto armazenado no campo `_raw`, mas não estavam todas disponíveis como campos pesquisáveis automaticamente.

Ou seja, a coleta estava funcionando porém o problema estava na forma como os campos estavam sendo extraídos.

### Analisando o evento bruto

Para entender o problema, foi analisado diretamente um evento Sysmon no Splunk. O evento continha informações como:

```text
EventID
ProcessId
Image
ImageLoaded
User
Hashes
Signature
```

Essas informações estavam presentes dentro do XML.

Por exemplo:

```xml
<Data Name='Image'>C:\Windows\system32\services.exe</Data>
```

e:

```xml
<Data Name='User'>NT AUTHORITY\SYSTEM</Data>
```

Isso confirmou que os dados não estavam sendo perdidos durante a coleta, eles simplesmente ainda estavam dentro da estrutura XML do evento.

<div class="photo" id="EventStructure">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/sysmon-event-structure.png' | relative_url }}"
       alt="Expanded sysmon event">
</div>

### Extraindo campos com SPL

Depois de entender a estrutura do evento, foi possível extrair os campos diretamente durante a pesquisa utilizando o comando `rex`. A consulta utilizada foi:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| table _time Image User
```

O comando `rex` permite utilizar expressões regulares para extrair informações do conteúdo de um campo.

Nesse caso, a pesquisa procura os valores associados aos elementos XML `Image` e `User` dentro de `_raw`. isso foi importante pois me mostrou a diferença entre `evento coletado` e `campo estruturado e pesquisável`

Essa distinção é importante em ambientes de SIEM, onde diferentes fontes de dados podem exigir diferentes níveis de parsing e normalização.

<div class="photo" id="FieldExtraction">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/field-extraction.md.png' | relative_url }}"
       alt="Query results showing extracted fields">
</div>

## Analisando processos e usuários

Depois de conseguir extrair os campos do Sysmon, foi possível começar a realizar análises mais interessantes. Uma das consultas utilizadas foi:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| stats count by Image
| sort -count
```

Essa consulta contabiliza quantas vezes cada processo apareceu nos eventos coletados. Entre os processos mais frequentes estavam:

```text
services.exe
svchost.exe
OneDrive.exe
MsMpEng.exe
msedge.exe
```

A presença desses processos não significa, por si só, comportamento malicioso.

Muitos deles são componentes legítimos do próprio Windows ou de aplicações instaladas no sistema, afinal, uma ferramenta de monitoramento não deve simplesmente classificar qualquer processo frequente como malicioso, o contexto é fundamental.

Também foi realizada uma consulta relacionando o processo executado ao usuário responsável:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| stats count by User Image
| sort -count
```

Isso permitiu observar, por exemplo, processos executados por:

```text
NT AUTHORITY\SYSTEM
SOC-WIN10\vboxuser
NT AUTHORITY\LOCAL SERVICE
```

Essa relação entre usuário e processo é muito mais útil para uma análise de segurança do que simplesmente saber que determinado executável apareceu.

<div class="photo" id="ProcessbyUser">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/processes-by-user-query.png' | relative_url }}"
       alt="Query results showing User, Image and Account">
</div>

## Analisando autenticações

Outra parte importante do laboratório foi observar eventos de autenticação do Windows. Para logins bem-sucedidos:

```spl
index=main EventCode=4624
| stats count by host
```

Para logins com falha:

```spl
index=main EventCode=4625
| stats count by host
```

Durante a análise, foi encontrado um evento `4625` no `SOC-WIN10`.

Esse tipo de evento é particularmente interessante para um SOC porque múltiplas falhas de autenticação podem, dependendo do contexto, representar desde um usuário digitando uma senha incorreta até situações que merecem uma investigação mais detalhada.

Novamente, o evento isolado não determina que exista um ataque. O analista precisa considerar frequência, horário, usuário, origem e outros elementos do contexto.

<div class="photo" id="FailLogon">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/failed-logons-query.png' | relative_url }}"
       alt="event 4625">
</div>

## Transformando as pesquisas em um dashboard
  
Depois de explorar os dados através das pesquisas SPL, o próximo passo foi transformar algumas dessas consultas em uma visualização única. Foi criado o:

```text
SOC Monitoring Dashboard
```

O objetivo foi proporcionar uma visão rápida do ambiente sem que fosse necessário executar cada pesquisa individualmente.

O dashboard contém:

```text
Total Events
Successful Logons
Failed Logons
Events by Host
Top 10 Executed Processes
```

A organização foi pensada para apresentar primeiro os indicadores gerais, depois os eventos de autenticação e, por fim, informações sobre os hosts e processos.

<div class="photo" id="Dashboards">
  <img src="{{ '/assets/Images/Screenshots SOC Monitoring Lab/Dashboards.png' | relative_url }}"
       alt="Dashboards">
</div>


### Top 10 Executed Processes

Para melhorar a visualização dos processos no dashboard, foi utilizada uma pequena transformação no SPL para remover o caminho completo do executável. A consulta utilizada foi:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| eval Process=replace(Image,"^.*\\\\","")
| stats count by Process
| sort -count
| head 10
```

Em vez de apresentar algo como:

```text
C:\Windows\System32\svchost.exe
```

o dashboard pode apresentar:

```text
svchost.exe
```

Isso torna o gráfico mais legível e facilita a identificação visual dos processos.

## O que aprendi com o projeto

Embora o projeto tenha começado com o objetivo de aprender a utilizar o Splunk, ele acabou envolvendo muito mais do que a ferramenta em si.

A implementação mostrou como diferentes componentes de um ambiente de monitoramento precisam trabalhar juntos.

Um evento precisa ser gerado no endpoint, coletado pelo agente, encaminhado pela rede, recebido pelo SIEM, indexado e finalmente disponibilizado para análise.

Uma falha em qualquer uma dessas etapas pode impedir que o analista veja aquilo que deveria estar monitorando.

Também Pude perceber que possuir os dados não significa necessariamente que eles estarão prontos para análise e o problema encontrado com os campos do Sysmon demonstrou isso na prática. Os dados estavam presentes no evento, mas foi necessário compreender sua estrutura e realizar a extração dos campos antes de utilizá-los em determinadas consultas.

Essa foi uma das partes mais importantes do projeto para mim, pois transformou um problema de configuração em uma oportunidade de entender melhor como os dados são tratados dentro de um SIEM.

Além da parte técnica, o projeto também reforçou uma ideia que considero importante para alguém que assim como eu está começando na área: monitoramento não significa simplesmente procurar por algo “malicioso”.

Um evento precisa ser interpretado dentro de contexto.

Uma falha de login pode ser apenas uma senha digitada incorretamente. Um processo conhecido pode ser completamente legítimo. Ao mesmo tempo, uma sequência aparentemente comum de eventos pode se tornar interessante quando analisada em conjunto com outros indicadores.

Essa capacidade de observar os eventos, entender o contexto e decidir o que merece investigação é uma das habilidades que pretendo continuar desenvolvendo.

## Resultado final

Ao final do projeto, foi possível construir um laboratório funcional no qual uma máquina Windows virtualizada gera eventos de segurança, o Sysmon fornece telemetria adicional, o Splunk Universal Forwarder coleta e encaminha os dados e o Splunk Enterprise centraliza e disponibiliza essas informações para análise.

O ambiente também possui consultas SPL e um dashboard que permitem visualizar informações relacionadas à atividade dos hosts, autenticações e execução de processos.

Mais importante do que simplesmente conseguir fazer as ferramentas funcionarem foi documentar o processo e solucionar os problemas encontrados durante a implementação.

O resultado é um laboratório simples, mas que representa uma primeira experiência prática com algumas das atividades relacionadas ao monitoramento de segurança.

## Competências praticadas

Durante o desenvolvimento deste laboratório, trabalhei principalmente com:

* SIEM e centralização de logs;
* Splunk Enterprise;
* Splunk Universal Forwarder;
* Windows Event Logs;
* Sysmon;
* SPL;
* extração de campos com `rex`;
* análise de eventos;
* autenticação Windows;
* análise de processos;
* criação de dashboards;
* troubleshooting;
* documentação técnica.

## O que vem depois?

Este projeto foi pensado como a primeira parte de uma sequência de laboratórios voltados ao desenvolvimento de competências para atuação inicial em Cybersecurity, especialmente em funções relacionadas a SOC e Blue Team.

O próximo passo será utilizar parte dessa infraestrutura para construir um cenário diferente: uma investigação simulada de incidente.

Nesse segundo projeto, a ideia será sair do monitoramento e trabalhar mais diretamente com o raciocínio investigativo de um analista: gerar uma sequência de eventos, identificar o que aconteceu, construir uma timeline, analisar evidências e produzir um relatório de incidente.

Dessa forma, os projetos não serão apenas variações do mesmo laboratório. Cada um terá um objetivo diferente e servirá para desenvolver uma competência diferente dentro de Cybersecurity.
