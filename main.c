#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <string.h>
#include	<unistd.h>

#include	"coRSAir.h"

int	free_ctx(BN_CTX	*ctx)
{
	BN_CTX_free(ctx);
	return (1);
}

int	free_get_n_e(BIO	*bioPub, X509 *cert, EVP_PKEY *pkey, RSA *rsa)
{
	if (bioPub != NULL)
		BIO_free(bioPub);
	if (cert != NULL)
		X509_free(cert);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (rsa != NULL)
		RSA_free(rsa);
	return (1);
}

int	free_breaking(int nb, mod_exp_t *n_e, rsa_data_t *rsa_d, char *msg)
{
	if (nb == 3)
	{
  	BN_clear_free(rsa_d->p1);
  	BN_clear_free(rsa_d->q1);
  	BN_clear_free(rsa_d->dmp1);
  	BN_clear_free(rsa_d->dmq1);
  	BN_clear_free(rsa_d->iqmp);
  	BN_clear_free(rsa_d->phi);
	}
	if (nb == 2)
	{
		RSA_free(rsa_d->key);
  	BN_clear_free(rsa_d->phi);
  	BN_clear_free(rsa_d->p1);
  	BN_clear_free(rsa_d->q1);
	}
	if (nb == 3)
  	BN_clear_free(rsa_d->d);
	if (msg != NULL)
		free(msg);

  BN_clear_free(n_e->n2);
  BN_clear_free(n_e->e2);
	return (1);
}



int	bn2dec_print(char *name, BIGNUM *bn)
{
	char	*value;

	value = BN_bn2dec(bn);
	if (value == NULL)
		return (1);	//ctr error
	printf("%s%s%s\n%s\n\n", MAG_I, name, WHITE, value);
	free(value);
	return (0);
}

BIGNUM	*ft_encrypt(BIGNUM *bn_msg, mod_exp_t *n_e, BN_CTX *ctx)
{
	BIGNUM	*encrypted = BN_new();

	if (!encrypted)
	{
		BN_free(bn_msg);
		return (NULL);
	}
	if (!BN_mod_exp(encrypted, bn_msg, n_e->e1, n_e->n1, ctx)) //ctr error
		return (NULL);
	if (bn2dec_print("\nencrypted", encrypted)) //ctr error
		return (NULL);
	return (encrypted);
}

BIGNUM	*ft_decrypt(BIGNUM *encrypted, mod_exp_t *n_e, rsa_data_t *rsa_d, BN_CTX *ctx)
{
	BIGNUM	*decrypted = BN_new();	//ctr error

	if (!decrypted)
	{
		BN_free(encrypted);
		return (NULL);
	}
	if (!BN_mod_exp(decrypted, encrypted, rsa_d->d, n_e->n1, ctx))	//ctr error
	{
		BN_free(encrypted);
		return (NULL);
	}
	bn2dec_print("\ndecrypted", decrypted); //ctr error
	return (decrypted);
}

int	encrypting(mod_exp_t *n_e, rsa_data_t *rsa_d, BN_CTX *ctx)
{
	int			len = BN_num_bytes(n_e->n1);
	char		*message = get_next_line(0);
	BIGNUM	*bn_msg = BN_new();	//ctr error

	//Error Handling
	if (message == NULL && write(2, "Couldn't read from stdin\n", 25))
		return (1);
	if (message && (strlen(message) > (size_t)len)
			&& write(2, "Your message is too long\n", 25))
		return (free_breaking(2, n_e, rsa_d, message));
	if (bn_msg == NULL && write(2, "Error getting your message\n", 27))
		return (free_breaking(2, n_e, rsa_d, message));

	//ASCII to BN
	if (!BN_bin2bn((unsigned char *)message, (int)strlen(message) * sizeof(char), bn_msg))	//ctr error
	{
		BN_free(bn_msg);
		return (1);
	}

	printf("\n%sYour message is \n%s%s\n", RED_B_U, WHITE, message);
	if (bn2dec_print("Your message passed to BN", bn_msg))	//ctr error
		return (free_breaking(2, n_e, rsa_d, message));

	//Encrypting
	BIGNUM *encrypted = ft_encrypt(bn_msg, n_e, ctx);
	if (!encrypted)
		return (free_breaking(2, n_e, rsa_d, message));

	//Decrypting
	BIGNUM *decrypted = ft_decrypt(encrypted, n_e, rsa_d, ctx);
	if (!decrypted)
		return (free_breaking(2, n_e, rsa_d, message));

	//Printing Original Message
	char	origin_msg[64] = {};
	if (len > 64)
		return (1);//ctr error
	if (!BN_bn2bin(decrypted, (unsigned char *)origin_msg)) //ctr error
	{
		return (1);
	}

	printf("\n%sOriginal message is%s\n%s\n", RED_B_U, WHITE, origin_msg);
	BN_free(encrypted);
	BN_free(decrypted);
	free_breaking(2, n_e, rsa_d, message);
	BN_free(bn_msg);
	free_ctx(ctx);
	return (0);
}

















int	calculate_rsa_param(rsa_data_t *rsa_d, mod_exp_t *n_e, BN_CTX *ctx)
{
  rsa_d->d = BN_new ();
	rsa_d->p1 = BN_new ();
  rsa_d->q1 = BN_new ();
  rsa_d->dmp1 = BN_new ();
  rsa_d->dmq1 = BN_new ();
  rsa_d->iqmp = BN_new ();
  rsa_d->phi = BN_new ();

  if (!BN_sub(rsa_d->p1, rsa_d->a, BN_value_one())) 					// p1 = p-1 
		return (1);
  if (!BN_sub(rsa_d->q1, rsa_d->b, BN_value_one()))						// q1 = q-1
		return (1);
	if (!BN_mul(rsa_d->phi, rsa_d->p1, rsa_d->q1, ctx))					// phi(pq) = (p-1)*(q-1)
		return (1);
  if (!BN_mod_inverse(rsa_d->d, n_e->e1, rsa_d->phi, ctx))		// d = e^-1 mod phi
		return (1);
  if (!BN_mod(rsa_d->dmp1, rsa_d->d, rsa_d->p1, ctx))					// dmp1 = d mod (p-1)
		return (1);
  if (!BN_mod(rsa_d->dmq1, rsa_d->d, rsa_d->q1, ctx))					// dmq1 = d mod (q-1)
		return (1);
  if (!BN_mod_inverse(rsa_d->iqmp, rsa_d->b, rsa_d->a, ctx))	// iqmp = q^-1 mod p
		return (1);
	return (0);
}




int	create_private_key(rsa_data_t	*rsa_d, mod_exp_t	*n_e, BN_CTX	*ctx)
{
	//Calculating Private Key
	if (calculate_rsa_param(rsa_d, n_e, ctx))
		return (free_breaking(0, n_e, rsa_d, NULL));
	bn2dec_print("d", rsa_d->d);	//ctr error

	//Setting RSA to create Public and Private Keys
  rsa_d->key = RSA_new();
	RSA_set0_key(rsa_d->key, n_e->n1, n_e->e1, rsa_d->d); 											//n, e and d
	RSA_set0_factors(rsa_d->key, rsa_d->a, rsa_d->b);														//p and q
  RSA_set0_crt_params(rsa_d->key, rsa_d->dmp1, rsa_d->dmq1, rsa_d->iqmp);			//dmp1, dmq1 and iqmp
	if (RSA_check_key(rsa_d->key) != 1)
		return (free_breaking(2, n_e, rsa_d, NULL));

	//Creating Public and Private Keys .pem
	BIO		*pub_key = NULL;
	BIO		*priv_key = NULL;
	pub_key = BIO_new_file("my_pub_key.pem", "w"); //crt error - close BIO
	priv_key = BIO_new_file("my_priv_key.pem", "w"); //crt error - close BIO
	if ((pub_key == NULL || priv_key == NULL) && write(2, "Couldn't create file for pub and priv keys\n", 43))
		return (free_breaking(2, n_e, rsa_d, NULL));
	if (!PEM_write_bio_RSAPublicKey(pub_key, rsa_d->key))	//ctr error
		return (free_breaking(2, n_e, rsa_d, NULL));
	if (!PEM_write_bio_RSAPrivateKey(priv_key, rsa_d->key, NULL, NULL, 0, NULL, NULL)) //ctr error
		return (free_breaking(2, n_e, rsa_d, NULL));

	BIO_free(pub_key);
	BIO_free(priv_key);

	return (0);
}






int	get_primes(rsa_data_t	*rsa_d, mod_exp_t	*n_e, BN_CTX	*ctx)
{
	rsa_d->b = BN_new();	//ctr error
	rsa_d->a = BN_new();	//ctr error
	const BIGNUM	*one = BN_value_one();

	if (!rsa_d->b && write(2, "Couldn't break RSA\n", 19))
		return (1);
	if (!rsa_d->a && write(2, "Couldn't break RSA\n", 19))
		return (1);
	if (one == NULL && write(2, "Couldn't break RSA\n", 19))
		return (1);
	
	bn2dec_print("n1", n_e->n1); //ctr error
	bn2dec_print("n2", n_e->n2);	//ctr error
	if (!BN_gcd(rsa_d->b, n_e->n1, n_e->n2, ctx) && write(2, "Couldn't calculate gcd\n", 23))
		return (1);
	if (!BN_cmp(rsa_d->b, one) && write(2, "Couldn't break RSA :(\n", 22))
		return (1);

	bn2dec_print("q", rsa_d->b); //ctr error
	BN_div(rsa_d->a, NULL, n_e->n1, rsa_d->b, ctx); //ctr de error
	bn2dec_print("p", rsa_d->a);	//ctr error
	return (0);
}




















int	ft_break_rsa(mod_exp_t	*n_e, BN_CTX *ctx)
{
	printf("----------------  %sBreaking RSA%s  ------------------\n", GREEN_B_U, WHITE);
	rsa_data_t	rsa_d;
	get_primes(&rsa_d, n_e, ctx);
	printf("----------------------------------\n\n\n");

	printf("----------------  %sGenerating Private Key%s  ------------------\n", GREEN_B_U, WHITE);
	if (create_private_key(&rsa_d, n_e, ctx) && write(2, "Couldn't create private key\n", 28))
		return (1);
	printf("----------------------------------\n\n\n");

	printf("----------------  %sEncrypting Message%s  ------------------\n", GREEN_B_U, WHITE);
	printf("Insert here your text (%d bits max.) to be encrypted:\n", BN_num_bits(n_e->n1));
	if (encrypting(n_e, &rsa_d, ctx))
		return (1);
	printf("----------------------------------\n\n\n");
	return (0);
}















































int	ft_get_module_exponent(char *file, BIGNUM	*n, BIGNUM *e)
{
	const BIGNUM	*tmp = NULL;

	printf("\n----------------  %s%s%s  ------------------\n", YEL_B_U, file, WHITE);

	//Basic Input Output
	BIO *bioPub = BIO_new_file(file, "r");
	if (bioPub == NULL && write(2, "Couldn't open that file\n", 24))
		return (1);

	//Read from x509 pem
	X509			*cert = PEM_read_bio_X509(bioPub, 0, 0, NULL);
	if (cert == NULL && write(2, "Couldn't read from file\n", 24))
		return free_get_n_e(bioPub, NULL, NULL, NULL);

	//Extracting Public Key
	EVP_PKEY	*pkey = X509_get_pubkey(cert);
	if (pkey == NULL && write(2, "Couldn't extract Public Key\n", 28))
		return free_get_n_e(bioPub, cert, NULL, NULL);

	//Extracting RSA
	RSA				*rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL && write(2, "Couldn't get RSA data\n", 22))
		return free_get_n_e(bioPub, cert, pkey, NULL);

	//Getting Exponent
	RSA_get0_key(rsa, NULL, &tmp,NULL);
	if (tmp == NULL && write(2, "Couldn't get exponent\n", 22))
		return free_get_n_e(bioPub, cert, pkey, rsa);
	bn2dec_print("exponent", (BIGNUM *)tmp); //ctr error
	if (BN_copy(e, tmp) == NULL && write(2, "Couldn't get exponent\n", 22))
		return free_get_n_e(bioPub, cert, pkey, rsa);

	//Getting Module
	RSA_get0_key(rsa, &tmp, NULL,NULL);
	if (tmp == NULL && write(2, "Couldn't get module\n", 20))
		return free_get_n_e(bioPub, cert, pkey, rsa);
	bn2dec_print("module", (BIGNUM *)tmp); //ctr error
	if (BN_copy(n, tmp) == NULL && write(2, "Couldn't get module\n", 20))
		return free_get_n_e(bioPub, cert, pkey, rsa); //freeRED_B_U, WHITE,  tmp

	RSA_free(rsa);
	EVP_PKEY_free(pkey);
	X509_free(cert);
	BIO_free(bioPub);
	printf("----------------------------------\n\n\n");
	return (0);
}


int	init_ctx(BN_CTX	*ctx, mod_exp_t	*n_e)
{
	if (ctx == NULL && write(2, "Couldn't break RSA\n", 19))
		return (1);
	n_e->n1 = BN_new ();
	n_e->n2 = BN_new ();
	n_e->e1 = BN_new ();
	n_e->e2 = BN_new ();
	if ((n_e->n1 == NULL || n_e->n2 == NULL || n_e->e1 == NULL || n_e->e2 == NULL)
			&& write(2, "Couldn't break RSA\n", 19))
		return	(1);
	return (0);
}

int	main(int argc, char **argv)
{
	mod_exp_t	n_e;

	n_e = (mod_exp_t){.n1 = NULL, .n2 = NULL, .e1 = NULL, .e2 = NULL};

	//Error Handling
	if (argc != 3 && write(2, "\nWrong Arguments\n", 17) 
		&& write(2, "sytax:	./coRSAir cert1.pem cert2.pem\n\n", 38))
		return (1);

	//Configure CTX
	BN_CTX	*ctx = NULL;
	ctx = BN_CTX_new();
	if (init_ctx(ctx, &n_e))
		return	free_ctx(ctx);

	//Getting module and exponent
	if (ft_get_module_exponent(argv[1], n_e.n1, n_e.e1))
		return	free_ctx(ctx);
	if (ft_get_module_exponent(argv[2], n_e.n2, n_e.e2))
		return	free_ctx(ctx);

	//Breaking RSA
	if (ft_break_rsa(&n_e, ctx))
		return	free_ctx(ctx);

	return 0;
}
