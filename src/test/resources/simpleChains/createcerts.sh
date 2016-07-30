#! /bin/bash

root="roots/root"

sub="subs/sub"

certs="certs/cert"

if [ ! -d "roots" ]; then
  mkdir roots
fi

if [ ! -d "subs" ]; then
  mkdir subs
fi

if [ ! -d "certs" ]; then
  mkdir certs
fi

## create heterogenous pki
for i in "1" "2" "3"; do
	for type in "A" "B" "C"; do
		if [[ "$type" == "B"] && ["$i" == "2" ]]; then
			continue
		fi

		openssl req -batch -subj "/C=AU/ST=Some-State/O=BcTls/OU=TestRoot$i/CN=Sub$i$type" -out "csr$i$type.csr" -new -newkey rsa:1024 -nodes -keyout "$sub$i$type.key"
		openssl x509 -req -days 1825 -in "csr$i$type.csr" -CA "$root${i}.pem" -CAkey "$root${i}.key" -CAcreateserial -out "$sub$i$type.pem"
	done
done

openssl req -batch -subj "/C=AU/ST=Some-State/O=BcTls/OU=TestRoot3/CN=SubSub3C" -out "csrSub3C.csr" -new -newkey rsa:1024 -nodes -keyout "subs/subsub3C.key"
openssl x509 -req -days 1825 -in "csrSub3C.csr" -CA "${sub}3C.pem" -CAkey "${sub}3C.key" -CAcreateserial -out "subs/subsub3C.pem"

## create random number of user certificates for every sub
for key in $(ls $sub*.key); do 
	raw=$(basename $key .key)
	name="$(tr '[:lower:]' '[:upper:]' <<< ${raw:0:1})${raw:1}"
	dir=$(dirname $key)

	for i in $(seq 1 $(shuf -i 3-10 -n 1)); do
		openssl req -batch -subj "/C=AU/ST=Some-State/O=BcTls/OU=$name/CN=$name$i" -out "certCsr.csr" -new -newkey rsa:1024 -nodes -keyout "$certs$name$i.key"
		openssl x509 -req -days 1825 -in "certCsr.csr" -CA "$dir/$raw.pem" -CAkey "$key" -CAcreateserial -out "$certs$name$i.pem"
	done
done
