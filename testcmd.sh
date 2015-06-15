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
cont=$( echo "hello1" | base64 -w 0 )
striple create --kindfile ./base.data -x 10 --content ${cont} -o ./test -c NoCipher
striple disp -i test
# create public ripem from prev
cont2=$( echo "hello2" | base64 -w 0 )
striple create --kindfile ./base.data -x 7 --fromfile ./test -x 1 --content ${cont2} -o ./test
striple check -i ./test -x 2 --fromfile ./test -x 1
# create public sha512 from prev
cont3=$( echo "hello3" | base64 -w 0 )
striple create --kindfile ./base.data -x 8 --fromfile ./test -x 2 --content ${cont3} -o ./testp -c PBKDF2 --outpass "pass"
striple disp -i test
# TODO remove need for inpass
striple check -i ./testp -x 1 --fromfile ./test -x 2 --inpass "pass"
striple cp -i ./test -x 2 -o ./testp --ox 1 --outpass "pass"
striple check -i ./testp -x 1 --fromfile ./test --inpass "pass"
# test linked file
striple create --kindfile ./base.data -x 8 --fromfile ./test -x 2 --contentfile ./test -o ./testp -c PBKDF2 --outpass "pass" --relative
striple create --kindfile ./base.data -x 10 --fromfile ./test -x 2 --contentfile ./test -o ./testp -c PBKDF2 --outpass "pass" --absolute
# check striple with test unchanged
striple check -i ./testp -x 3 --fromfile ./test -x 2 --inpass "pass"
striple check -i ./testp -x 4 --fromfile ./test --inpass "pass"
# cp to test relative to absolute
cp ./test ./testbu
striple cp -i ./testp --inpass "pass" -x 3 -o ./testbu --absolute
# TODO check new
striple cp -i ./testp --inpass "pass" -x 4 -o ./testbu --relative
# TODO check new
# cp to test no file mode (--nofile) : content
striple cp -i ./testp --inpass "pass" -x 4 -o ./testnof --nofile
# check striple with test changed + same size : invalid
sed 's/hello/holle/' ./test > tmp
#ok
striple check -i ./test -x 2 --fromfile ./test -x 1
mv tmp ./test
echo "ko"
striple check -i ./test -x 2 --fromfile ./test -x 1
#ok
striple check -i ./testnof -x 1  --fromfile ./test -x 2 --inpass "pass"
sed 's/hello/holle/' ./testnof > tmp
mv tmp ./testnof
echo "ko"
striple check -i ./testnof -x 1  --fromfile ./test -x 2 --inpass "pass"
echo "ko"
striple check -i ./testp -x 4 --fromfile ./test -x 2 --inpass "pass"
