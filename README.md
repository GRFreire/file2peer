# file2peer

Transferência de arquivos **peer to peer** sobre **UDP**, escrita em C sem bibliotecas externas. O programa descobre o endereço público de cada lado com STUN, usa um servidor de encontro próprio (ERS) e faz *UDP hole punching* para conectar dois computadores, mesmo atrás de NATs diferentes.

A descrição do protocolo, da arquitetura, das máquinas de estado, do escopo e das evoluções previstas está em [`DOCUMENTACAO.md`](DOCUMENTACAO.md).

## Grupo

| Nome | N USP |
|------|--------
| Diego Mori Rodrigues | 13782421 |
| Guilherme Rugai Freire | 6522087 |
| Matheus Soares Falango | 15479691 |
| Pedro Avelar Machado | 15497396 |

## Ambiente

| Item | Versão |
|------|--------|
| Sistema operacional | Linux — `Linux 6.1.0-49-amd64` |
| Compilador | gcc — `gcc 12.2.0` |

Qualquer Linux atual com gcc compatível com C11 (`-std=gnu11`) e glibc com `getrandom()` (2.25 ou superior) deve funcionar. O código usa `pthread`, semáforos POSIX e atomics C11.

## Compilação

```sh
make all
```

Gera os executáveis `file2peer` (transferência) e `ers` (servidor de encontro).

## Uso

```sh
./file2peer <send|receive> FILE
```

| Modo | O que `FILE` significa |
|------|------------------------|
| `send` | caminho do arquivo a ser **enviado** |
| `receive` | nome com que o arquivo recebido será **salvo** |

1. **Quem envia** executa:

   ```sh
   ./file2peer send foto.jpg
   ```

   O programa imprime um **ID de sessão** (`ERS id: 123456789`) e aguarda o outro lado.

2. **Quem recebe** executa:

   ```sh
   ./file2peer receive foto_recebida.jpg
   ```

   O programa pergunta `What is the ERS id?`. Basta digitar o ID mostrado pelo remetente.

3. Os dois lados se encontram, a conexão é estabelecida e a transferência começa sozinha. Ao final, cada lado informa que o arquivo foi enviado ou recebido e encerra.

Os dois processos podem estar na mesma máquina, na mesma rede local ou em redes diferentes.

## ERS e STUN

**Não é necessário configurar nada**: os valores padrão já funcionam, tanto para o STUN quanto para o ERS.

| Serviço | Padrão |
|---------|--------|
| STUN | `stun.l.google.com:19302` |
| ERS | `ers.grfreire.com:54321` |

Para usar outros servidores, há variáveis de ambiente (devem ter o mesmo valor nos dois peers):

| Variável | Efeito |
|----------|--------|
| `ERS_ADDR` | host ou IP do ERS |
| `ERS_PORT` | porta UDP do ERS |
| `STUN_ADDR` | host ou IP do servidor STUN |
| `STUN_PORT` | porta UDP do servidor STUN |

Exemplo:

```sh
ERS_ADDR=127.0.0.1 ./file2peer send foto.jpg
ERS_ADDR=127.0.0.1 ./file2peer receive foto_recebida.jpg
```

### Rodando o seu próprio ERS

```sh
./ers
```

O ERS escuta em UDP na porta `54321` (ou na indicada em `ERS_PORT`), em todas as interfaces. Se estiver atrás de um firewall ou em um servidor na nuvem, libere a porta **UDP** correspondente.

Se o STUN estiver inacessível, o programa segue com os endereços locais (loopback e LAN), o que basta para transferências na mesma máquina ou na mesma rede.

## Verificação de falhas

Toda chamada ao sistema que pode falhar tem o retorno verificado. A mensagem de erro (com `strerror(errno)`) vai para `stderr` e o programa encerra com código de saída diferente de zero quando a falha é irrecuperável.

| Situação | Comportamento |
|----------|---------------|
| Falha ao criar o socket, alocar memória, criar threads ou semáforos | Mensagem de erro e encerramento (`EXIT_FAILURE`) |
| Arquivo a enviar inexistente ou ilegível | Detectado antes de contatar o ERS |
| Erro de leitura do arquivo (`fread`/`ferror`) | Aborta, em vez de enviar o arquivo truncado |
| Erro ao gravar o arquivo recebido (`fseek`, `fwrite`, `fflush`, `fclose`) | Aborta com mensagem (ex.: disco cheio) |
| ID de sessão inválido ou entrada vazia | Mensagem de erro e encerramento |
| Falha ao resolver o ERS (`getaddrinfo`) ou resposta `ERROR` do ERS | Mensagem de erro e encerramento |
| STUN inacessível ou sem resposta (2 s) | Aviso; segue só com endereços locais (loopback e LAN) |
| Interface de LAN não encontrada | Aviso; segue sem o candidato de LAN |
| Erro fatal de `sendto`/`recvfrom` nas threads de rede | Registrado pela thread; a principal percebe, encerra com erro e libera os recursos |
| Erro passageiro de rede (`EINTR`, `ENOBUFS`, `EHOSTUNREACH` etc.) | Ignorado; a retransmissão do protocolo recupera o pacote |
| Pacote curto, `DATA` incompleto, endereço desconhecido ou linha inválida do ERS | Descartado |
| Perda, duplicação ou reordenação de pacotes UDP | Tratado pelo protocolo (ACKs, retransmissão e offsets absolutos) |

