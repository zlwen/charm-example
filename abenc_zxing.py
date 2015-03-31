'''
Brent Waters (Pairing-based)
 
* type:            ciphertext-policy attribute-based encryption (public key)
* setting:        Pairing

:Authors:		  zlwen
:Date:            03/2015
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
import time as T
import sys as S

debug = False
class Zxing(ABEnc):

	def __init__(self, groupObj):
		ABEnc.__init__(self)
		global util, group
		util = SecretUtil(groupObj, debug)
		group = groupObj
	
	def setup(self):
		# caculate run time
		begin = T.time()

		g1    = group.random(G1)
		g2    = group.random(G2)
		u     = group.random(G1)
		h     = group.random(G1)
		w     = group.random(G1)
		v     = group.random(G1)
		alpha = group.random()
		x     = group.random()
		y     = group.random()
		g_x   = g2 ** x
		g_y   = g2 ** y
		e_gg_alpha = pair(g1,g2) ** alpha
		msk = {'alpha':alpha, 'x':x, 'y':y}
		pk = {'g1':g1, 'g2':g2, 'u':u, 'h':h, 'w':w, 'v':v, 'g_x':g_x, 'g_y':g_y, 'e_gg_alpha':e_gg_alpha}
		
		end = T.time()
		print('%.3f\t' % (end - begin), end="")
		return (msk, pk)
	
	def keygen(self, pk, msk, attributes):
		# caculate run time
		begin = T.time()

		k_x = [group.hash(s) for s in attributes]
		r = group.random()
		c = group.random()
		ID = group.random()
		o = group.random()
		L_1 = pk['g2'] ** r
		L_2 = pk['g_x'] ** r
		L_3 = pk['g_y'] ** r

		internal = msk['x'] + ID + msk['y'] * c
		exp = msk['alpha'] / internal
		K_1 = (pk['g1'] ** exp) * (pk['w'] ** (o * r))
		
		K_x = {}
		for i in range(0, len(k_x)):
			K_2_3 = {} 
			r_i = group.random()
			i_2 = pk['g2'] ** r_i
			i_3 = ((pk['u'] ** k_x[i] * pk['h']) ** r_i) * (pk['v'] ** -(internal * r))
			K_2_3['i_2'] = i_2
			K_2_3['i_3'] = i_3
			K_x[attributes[i]] = K_2_3
		key = { 'K_1':K_1, 'N_1':ID, 'N_2':c, 'N_3':o, 'L_1':L_1, 'L_2':L_2, 'L_3':L_3, 'K_x':K_x, 'attributes':attributes }

		end = T.time()
		print('%.3f\t' % (end - begin), end="")
		return key
	
	def encrypt(self, pk, M, policy_str):
		# caculate run time
		begin = T.time()

		# Extract the attributes as a list
		policy = util.createPolicy(policy_str)        
		p_list = util.getAttributeList(policy)
		s = group.random()
		C = (pk['e_gg_alpha'] ** s) * M
		D_1 = pk['g2'] ** s
		D_2 = pk['g_x'] ** s
		D_3 = pk['g_y'] ** s
		C_t = {}
		secret = s
		shares = util.calculateSharesList(secret, policy)
		
		# ciphertext
		for i in range(len(p_list)):
			str_i = str(i)
			r = group.random()
			if shares[i][0] == p_list[i]:
				C_1_2_3 = {}
				t_i = group.random()
				attr = shares[i][0].getAttribute()
				i_1 = (pk['w'] ** shares[i][1]) * (pk['v'] ** t_i)
				i_2 = ((pk['u'] ** group.hash(attr)) * pk['h']) ** -t_i
				i_3 = pk['g2'] ** t_i
				C_1_2_3['i_1'] = i_1
				C_1_2_3['i_2'] = i_2
				C_1_2_3['i_3'] = i_3
				C_t[p_list[i]] = C_1_2_3

		end = T.time()
		print('%.3f\t' % (end - begin), end="")
		return { 'C':C, 'D_1':D_1, 'D_2':D_2, 'D_3':D_3, 'C_t':C_t , 'policy':policy_str, 'attribute':p_list }
	
	def decrypt(self, pk, sk, ct):
		# caculate run time
		begin = T.time()

		policy = util.createPolicy(ct['policy'])
		pruned = util.prune(policy, sk['attributes'])
		if pruned == False:
			return False
		coeffs = util.getCoefficients(policy)
		denominator= pair(sk['K_1'], (ct['D_1'] ** sk['N_1']) * ct['D_2'] * (ct['D_3'] ** sk['N_2']))
		
		# create list for attributes in order...
		k_x, w_i = {}, {}
		for i in pruned:
			j = i.getAttributeAndIndex()
			k = i.getAttribute()
			k_x[ j ] = sk['K_x'][k]
			w_i[ j ] = coeffs[j]
			#print('Attribute %s: coeff=%s, k_x=%s' % (j, w_i[j], k_x[j]))
		    
		C_t = ct['C_t']
		internal = (sk['L_1'] ** sk['N_1']) * sk['L_2'] * (sk['L_3'] ** sk['N_2'])
		
		D = 1
		for i in pruned:
			j = i.getAttributeAndIndex()
			D *= ( pair(C_t[j]['i_1'] ** w_i[j], internal) * pair(C_t[j]['i_2'] ** w_i[j], k_x[j]['i_2']) * pair(C_t[j]['i_3'] ** w_i[j], k_x[j]['i_3']))   

		end = T.time()
		print('%.3f\t' % (end - begin), end="")
		return (ct['C'] * (D ** sk['N_3'])) / denominator

def generatePolicy(num):
	n = int(num)
	prefix = 'A'
	array = []
	for i in range(0, n):
		array.append(prefix + str(i))
	return ' and '.join(array)

def generateAttrList(num):
	n = int(num)
	prefix = 'A'
	array = []
	for i in range(0, n):
		array.append(prefix + str(i))
	return array

def main(num=5):
	pol = generatePolicy(num)
	attr_list = generateAttrList(num)

	#Get the eliptic curve with the bilinear mapping feature needed.
	groupObj = PairingGroup('SS512')
	
	zxing = Zxing(groupObj)
	(msk, pk) = zxing.setup()
	
	if debug: print('Acces Policy: %s' % pol)
	if debug: print('User credential list: %s' % attr_list)
	m = groupObj.random(GT)
	
	cpkey = zxing.keygen(pk, msk, attr_list)
	if debug: print("\nSecret key: %s" % attr_list)
	if debug:groupObj.debug(cpkey)
	cipher = zxing.encrypt(pk, m, pol)
	
	if debug: print("\nCiphertext...")
	if debug:groupObj.debug(cipher)
	orig_m = zxing.decrypt(pk, cpkey, cipher)
	
	assert m == orig_m, 'FAILED Decryption!!!'
	if debug: print('Successful Decryption!')
	del groupObj

if __name__ == '__main__':
#debug = True
	debug = False
	main(S.argv[1])
