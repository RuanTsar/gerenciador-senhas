#!/usr/bin/env bash

host="$1"
port="$2"
shift 2
cmd="$@"

# Aguarda até que a porta esteja aberta
until nc -z "$host" "$port"; do
  echo "Esperando $host:$port ficar disponível..."
  sleep 1
done

# Executa o comando após a porta ser liberada
exec $cmd
