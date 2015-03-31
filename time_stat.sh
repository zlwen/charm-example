#!/bin/sh
for i in `seq $2`
do 
	printf '************ round: %02d *************\n' $i
	for j in `seq 5 5 60`
	do 
		printf "[amount:%02d]\t" $j
		python3 $1 $j
		printf "\n"
	done
done
