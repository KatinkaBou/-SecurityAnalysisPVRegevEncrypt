#!/usr/bin/env sage
# -*- coding: utf-8 -*-

#-- Example in Sage --#
# ..: load("regev_encrypt.sage")
# ..: d,t,q=256,128,7681
# ..: attack(d,t,q,"light")

#-- Import --#
from sage.all import *
import sys
load("../framework/instance_gen.sage")
import random
#------------#

# get d-th roots of unity modulo q 
def GetUnits_pow2(d,q):
	list_of_units=[]
	for i in range(q):
		if ((i**(2*d))%q==1) and ((i**(d))%q==q-1):
			list_of_units.append(i)
	return list_of_units

# define partial Vandermonde transformation matrix of degree d with t rows modulo q
def partial_vandermonde_pow2(d,t,q):
	if t > d:
		return print("Error, t =",t,"is larger than d =",d,".")
	
	list_of_units=GetUnits_pow2(d,q)
	random_half_list_of_units=[]
	for i in range(t):
		tmp=random.choice(list_of_units)
		list_of_units.remove(tmp)
		random_half_list_of_units.append(tmp)
	D=matrix(ZZ,t,d)
	for i in range(t):
		for j in range(d):
			D[i,j]=((random_half_list_of_units[i])**j)%q
	return D

# == KEY RECOVERY ATTACK == 
def attack1(d,t,q,mode):
	# d = degree of the ring of integers
	# t = number of rows of the partial Vandermonde matrix
	# ternary secrets and errors (uniform distribution)
	D_e = {-1: 0.33, 0: 0.34, 1: 0.33}
	D_s = D_e
	
	# set n and m
	# verify that d is a power of 2 and that q=1 mod 2d
	if (frac(log(d,2))==0) and (q%(2*d)==1):
		n=t
		m=d
	else:
		return print("Error, this is not the power-of-2 case where the defining polynomial fully splits. Please check input parameter.")

	# initialize LWE instance	
	if mode=="full":
		A, b, dbdd = initialize_from_LWE_instance(DBDD,n,q,m,D_e,D_s)
		# integrate q vectors
		_ = dbdd.integrate_q_vectors(q,report_every=20)
		# estimation of attack
		beta,delta= dbdd.estimate_attack()
	
	elif mode=="light":
		A, b, dbdd = initialize_from_LWE_instance(DBDD_predict,n,q,m,D_e,D_s)
		# integrate q vectors
		_ = dbdd.integrate_q_vectors(q,report_every=20)
		# estimation of attack
		beta,delta= dbdd.estimate_attack()

	elif mode=="superlight":
		A, b, dbdd = initialize_from_LWE_instance(DBDD_predict_diag,n,q,m,D_e,D_s)
		# integrate q vectors
		_ = dbdd.integrate_q_vectors(q,report_every=20)
		# estimation of attack
		beta,delta= dbdd.estimate_attack()

	else:
		return "Error, unknown mode - choose between <full> or <light> or <superlight>."

	return print("KEY RECOVERY ATTACK completed.") 

# == RANDOMNESS RECOVERY ATTACK ==
def attack2(d,t,q,mode):
	# d = degree of the ring of integers
	# t = number of rows of the partial Vandermonde matrix
	# ternary secrets and errors (uniform distribution)
	D_e = {-1: 0.33, 0: 0.34, 1: 0.33}
	D_s = D_e
	
	# set n and m
	# verify that d is a power of 2 and that q=1 mod 2d
	if (frac(log(d,2))==0) and (q%(2*d)==1):
		n=d-t
		m=t
	else:
		return print("Error, this is not the power-of-2 case where the defining polynomial fully splits. Please check input parameter.")

	# initialize LWE instance	
	if mode=="full":
		A, b, dbdd = initialize_from_LWE_instance(DBDD,n,q,m,D_e,D_s)
		# integrate q vectors
		_ = dbdd.integrate_q_vectors(q,report_every=20)
		# estimation of attack
		beta,delta= dbdd.estimate_attack()
	
	elif mode=="light":
		A, b, dbdd = initialize_from_LWE_instance(DBDD_predict,n,q,m,D_e,D_s)
		# integrate q vectors
		_ = dbdd.integrate_q_vectors(q,report_every=20)
		# estimation of attack
		beta,delta= dbdd.estimate_attack()

	elif mode=="superlight":
		A, b, dbdd = initialize_from_LWE_instance(DBDD_predict_diag,n,q,m,D_e,D_s)
		# integrate q vectors
		_ = dbdd.integrate_q_vectors(q,report_every=20)
		# estimation of attack
		beta,delta= dbdd.estimate_attack()

	else:
		return "Error, unknown mode - choose between <full> or <light> or <superlight>."

	return print("RANDOMNESS RECOVERY ATTACK completed.") 

# == PLAINTEXT RECOVERY USING HINTS ATTACK == 
def attack3(d,t,q,mode):
	# d = degree of the ring of integers
	# t = number of rows of the partial Vandermonde matrix
	# ternary secrets and errors (uniform distribution)
	D_e = {-1: 0.33, 0: 0.34, 1: 0.33}
	D_s = D_e

	# set n and m
	# verify that d is a power of 2 and that q=1 mod 2d
	if (frac(log(d,2))==0) and (q%(2*d)==1):
		n=d
		m=d
	else:
		return print("Error, this is not the power-of-2 case where the defining polynomial fully splits. Please check input parameter.")

	# initialize LWE instance	
	if mode=="full":
		A, b, dbdd = initialize_from_LWE_instance(DBDD,n,q,m,D_e,D_s)
	
	elif mode=="light":
		A, b, dbdd = initialize_from_LWE_instance(DBDD_predict,n,q,m,D_e,D_s)

	elif mode=="superlight":
		A, b, dbdd = initialize_from_LWE_instance(DBDD_predict,n,q,m,D_e,D_s)

	else:
		return "Error, unknown mode - choose between <full> or <light> or <superlight>."

	F=partial_vandermonde_pow2(d,t,q)
	#for simplicity: the complement partial Vandermonde matrix is given by the first t rows
	#hints only on the LWE secret, not on the LWE noise
	for i in range(t):
		liste=F[i].list()
		liste=liste+[0 for k in range(d)]
		v=vec(liste)
		leak=dbdd.leak(v)%q
		_ = dbdd.integrate_modular_hint(v,leak,q)
		print("This was hint ",i+1," on the secret.")

	# integrate q vectors at the end
	_ = dbdd.integrate_q_vectors(q,report_every=20)
	# estimate attack
	beta,delta= dbdd.estimate_attack()

	return print("PLAINTEXT RECOVERY USING HINTS ATTACK completed.")
	
# = ATTACKS ON REGEV-LIKE PKE SCHEME =
def attack(d,t,q,mode):
	attack1(d,t,q,mode)
	attack2(d,t,q,mode)
	attack3(d,t,q,mode)
	return print("ATTACK completed.")


	
