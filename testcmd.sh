#!/bin/bash
rm -rf testcmdout
mkdir testcmdout
cd testcmdout
PATH=$PATH:../target/debug/examples/
# generate fresh base
genbasestriples
STRIPLE_BASE=./base.data ; export STRIPLE_BASE
# check some of this base
striple check -i ./base.data -x 4 --fromfile ./base.data -x 1
striple check -i ./base.data -x 2 --fromfile ./base.data -x 2
striple check -i ./base.data -x 1 --fromfile ./base.data -x 1
# create self striple rsa
cont=$( echo "hello1" | base64 )
striple create --kindfile ./base.data -x 10 --content ${cont} -o ./test -c NoCipher
striple disp -i test
# create public ripem from prev
cont2=$( echo "hello2" | base64 )
striple create --kindfile ./base.data -x 7 --fromfile ./test -x 1 --content ${cont2} -o ./test
striple check -i ./test -x 2 --fromfile ./test -x 1
# create public sha512 from prev
cont3=$( echo "hello3" | base64 )
striple create --kindfile ./base.data -x 8 --fromfile ./test -x 2 --content ${cont3} -o ./testp -c PBKDF2 --outpass "pass"
striple disp -i test
# TODO remove need for inpass
striple check -i ./testp -x 1 --fromfile ./test -x 2 --inpass "pass"
striple cp -i ./test -x 2 -o ./testp --ox 1 --outpass "pass"
striple check -i ./testp -x 1 --fromfile ./test --inpass "pass"

