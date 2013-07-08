#!/usr/bin/env bash

echo '################ pep8 ################'
pep8 --show-source $1 # --show-pep8 # more details

echo '################ pyflakes ################'
pyflakes $1    

#echo '################ pylint ################'
#pylint $1
