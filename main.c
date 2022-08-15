#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <string.h>
#include	<unistd.h>

#include	"coRSAir.h"






int	bn2dec_print(char *name, BIGNUM *bn)
{
	char	*value;

	value = NULL;
	value = BN_bn2dec(bn);
	if (value == NULL)
		return (1);
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
	if (!BN_mod_exp(encrypted, bn_msg, n_e->e1, n_e->n1, ctx))
	{
		BN_free(bn_msg);
		return (NULL);
	}
	if (bn2dec_print("\nencrypted", encrypted))
	{
		BN_free(bn_msg);
		BN_free(encrypted);
		return (NULL);
	}
	return (encrypted);
}

BIGNUM	*ft_decrypt(BIGNUM *encrypted, mod_exp_t *n_e, rsa_data_t *rsa_d, BN_CTX *ctx)
{
	BIGNUM	*decrypted = BN_new();

	if (!decrypted)
	{
		BN_free(encrypted);
		return (NULL);
	}
	if (!BN_mod_exp(decrypted, encrypted, rsa_d->d, n_e->n1, ctx))
	{
		BN_free(encrypted);
		BN_free(decrypted);
		return (NULL);
	}
	if (bn2dec_print("\ndecrypted", decrypted))
	{
		BN_free(encrypted);
		BN_free(decrypted);
		return (NULL);
	}
	return (decrypted);
}

int	encrypting(mod_exp_t *n_e, rsa_data_t *rsa_d, BN_CTX *ctx, int len)
{
	char		*message = get_next_line(0);
	BIGNUM	*bn_msg = BN_new();

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
	BN_free(bn_msg);

	//Decrypting
	BIGNUM *decrypted = ft_decrypt(encrypted, n_e, rsa_d, ctx);
	if (!decrypted)
		return (free_breaking(2, n_e, rsa_d, message));
	BN_free(encrypted);

	//Printing Original Message
	char	origin_msg[64] = {};
	if (len > 64 || !BN_bn2bin(decrypted, (unsigned char *)origin_msg)) //ctr error
	{
		BN_free(decrypted);
		free_breaking(2, n_e, rsa_d, message);
		return (1);
	}
	printf("\n%sOriginal message is%s\n%s\n", RED_B_U, WHITE, origin_msg);
	BN_free(decrypted);
	free_breaking(2, n_e, rsa_d, message);
	BN_CTX_free(ctx);
	return (0);
}








int calculate_rsa(rsa_data_t *rsa_d, mod_exp_t *n_e, BN_CTX *ctx)
{
  if (!BN_sub(rsa_d->p1, rsa_d->a, BN_value_one()) 						// p1 = p-1 
			&& wr_err("Math Error\n", "Can't calculate p1\n"))
		return (free_rsa(9, rsa_d));
  if (!BN_sub(rsa_d->q1, rsa_d->b, BN_value_one())						// q1 = q-1
			&& wr_err("Math Error\n", "Can't calculate q1\n"))
		return (free_rsa(9, rsa_d));
	if (!BN_mul(rsa_d->phi, rsa_d->p1, rsa_d->q1, ctx)					// phi(pq) = (p-1)*(q-1)
			&& wr_err("Math Error\n", "Can't calculate phi\n"))
		return (free_rsa(9, rsa_d));
  if (!BN_mod_inverse(rsa_d->d, n_e->e1, rsa_d->phi, ctx)			// d = e^-1 mod phi
			&& wr_err("Math Error\n", "Can't calculate d\n"))
		return (free_rsa(9, rsa_d));
  if (!BN_mod(rsa_d->dmp1, rsa_d->d, rsa_d->p1, ctx)					// dmp1 = d mod (p-1)
			&& wr_err("Math Error\n", "Can't calculate dmq1\n"))
		return (free_rsa(9, rsa_d));
  if (!BN_mod(rsa_d->dmq1, rsa_d->d, rsa_d->q1, ctx)					// dmq1 = d mod (q-1)
			&& wr_err("Math Error\n", "Can't calculate dmq1\n"))
		return (free_rsa(9, rsa_d));
  if (!BN_mod_inverse(rsa_d->iqmp, rsa_d->b, rsa_d->a, ctx)		// iqmp = q^-1 mod p
			&& wr_err("Math Error\n", "Can't calculate iqmp\n"))
		return (free_rsa(9, rsa_d));
	return (0);
}

int	init_rsa(rsa_data_t *rsa_d)
{
  rsa_d->d = BN_new ();
	if (!rsa_d->d && wr_err("Error\n", "d not alloc\n"))
		return (free_rsa(2, rsa_d));
	rsa_d->p1 = BN_new ();
	if (!rsa_d->p1 && wr_err("Error\n", "p1 not alloc\n"))
		return (free_rsa(3, rsa_d));
  rsa_d->q1 = BN_new ();
	if (!rsa_d->q1 && wr_err("Error\n", "q1 not alloc\n"))
		return (free_rsa(4, rsa_d));
  rsa_d->dmp1 = BN_new ();
	if (!rsa_d->dmp1 && wr_err("Error\n", "dmp1 not alloc\n"))
		return (free_rsa(5, rsa_d));
  rsa_d->dmq1 = BN_new ();
	if (!rsa_d->dmq1 && wr_err("Error\n", "dmpq1 not alloc\n"))
		return (free_rsa(6, rsa_d));
  rsa_d->iqmp = BN_new ();
	if (!rsa_d->iqmp && wr_err("Error\n", "iqmp not alloc\n"))
		return (free_rsa(7, rsa_d));
  rsa_d->phi = BN_new ();
	if (!rsa_d->phi && wr_err("Error\n", "phi not alloc\n"))
		return (free_rsa(8, rsa_d));
	return (0);
}

int	calculate_rsa_param(rsa_data_t *rsa_d, mod_exp_t *n_e, BN_CTX *ctx)
{
	if (init_rsa(rsa_d))
		return	free_ctx_ne(6, ctx, n_e);
	if (calculate_rsa(rsa_d, n_e, ctx))
		return	free_ctx_ne(6, ctx, n_e);
	return (0);
}


int set_new_key(rsa_data_t *rsa_d, mod_exp_t *n_e, BN_CTX *ctx)
{
  rsa_d->key = RSA_new();
  if (!rsa_d->key)
		return (free_rsa(9, rsa_d));
	if (!RSA_set0_key(rsa_d->key, n_e->n1, n_e->e1, rsa_d->d) 											//n, e and d
			&& wr_err("New Key Error\n", "n, e and d not set\n"))
	{
		free_ctx_ne(6, ctx, n_e);
		return (free_rsa(10, rsa_d));
	}
	if (!RSA_set0_factors(rsa_d->key, rsa_d->a, rsa_d->b)														//p and q
			&& wr_err("New Key Error\n", "p and q not set\n"))
	{
		free_ctx_ne(7, ctx, n_e);
		return (free_rsa(10, rsa_d));
	}
  if (!RSA_set0_crt_params(rsa_d->key, rsa_d->dmp1, rsa_d->dmq1, rsa_d->iqmp)			//dmp1, dmq1 and iqmp
			&& wr_err("New Key Error\n", "dmp1 and iqmp not set\n"))
	{
		free_ctx_ne(7, ctx, n_e);
		return (free_rsa(11, rsa_d));
	}
	if ((RSA_check_key(rsa_d->key) != 1)
			&& wr_err("New Key Error\n", "not a valid key generated\n"))
		return (free_breaking(2, n_e, rsa_d, NULL));
	return (0);
}

int create_pub_pkey(rsa_data_t *rsa_d, mod_exp_t *n_e)
{
	BIO		*pub_key;
	BIO		*priv_key;

	pub_key = NULL;
	priv_key = NULL;
	pub_key = BIO_new_file("my_pub_key.pem", "w");
	if (!pub_key && wr_err("Error\n", "can't create my_pub_key.pem\n"))
		return (free_breaking(2, n_e, rsa_d, NULL));
	priv_key = BIO_new_file("my_priv_key.pem", "w");
	if (!priv_key && wr_err("Error\n", "can't create my_priv_key.pem\n"))
	{
		BIO_free(pub_key);
		return (free_breaking(2, n_e, rsa_d, NULL));
	}
	if (!PEM_write_bio_RSAPublicKey(pub_key, rsa_d->key) && wr_err("Error\n", "can't write my_pub_key.pem\n"))
	{
		BIO_free(pub_key);
		BIO_free(priv_key);
		return (free_breaking(2, n_e, rsa_d, NULL));
	}
	if (!PEM_write_bio_RSAPrivateKey(priv_key, rsa_d->key, NULL, NULL, 0, NULL, NULL) && wr_err("Error\n", "can't write my_priv_key.pem\n"))
	{
		BIO_free(pub_key);
		BIO_free(priv_key);
		return (free_breaking(2, n_e, rsa_d, NULL));
	}
	BIO_free(pub_key);
	BIO_free(priv_key);
	return (0);
}

int	create_private_key(rsa_data_t	*rsa_d, mod_exp_t	*n_e, BN_CTX	*ctx)
{
	//Calculating Private Key
	if (calculate_rsa_param(rsa_d, n_e, ctx))
		return (1);
	if (bn2dec_print("d", rsa_d->d) && wr_err("Error\n", "n1 not printed\n")
			&& free_ctx_ne(6, ctx, n_e))
		return (free_rsa(9, rsa_d));
	//Setting RSA to create Public and Private Keys
	if (set_new_key(rsa_d, n_e, ctx))
		return (1);
	//Creating Public and Private Keys .pem
	if (create_pub_pkey(rsa_d, n_e))
		return (1);
	return (0);
}






int	get_primes(rsa_data_t	*rsa_d, mod_exp_t	*n_e, BN_CTX	*ctx)
{
	const BIGNUM	*one = BN_value_one();

	rsa_d->b = BN_new();
	if (!rsa_d->b && wr_err("Error\n", "q prime (b) not alloc\n"))
		return (1);
	rsa_d->a = BN_new();
	if (!rsa_d->a && wr_err("Error\n", "p prime (a) not alloc\n"))
		return (free_rsa(0, rsa_d));
	if (one == NULL && wr_err("Error\n", "one bn not created\n"))
		return (free_rsa(2, rsa_d));
	if (bn2dec_print("n1", n_e->n1) && wr_err("Error\n", "n1 not printed\n"))
		return (free_rsa(2, rsa_d));
	if (bn2dec_print("n2", n_e->n2) && wr_err("Error\n", "n2 not printed\n"))
		return (free_rsa(2, rsa_d));
	if (!BN_gcd(rsa_d->b, n_e->n1, n_e->n2, ctx) && wr_err("Error\n", "gcd not calculated\n"))
		return (free_rsa(2, rsa_d));
	if (!BN_cmp(rsa_d->b, one) && wr_err("Couldn't break RSA :(\n", "key's don't share primes\n"))
		return (free_rsa(2, rsa_d));
	if (bn2dec_print("q", rsa_d->b) && wr_err("Error\n", "q not printed\n"))
		return (free_rsa(2, rsa_d));
	if (!BN_div(rsa_d->a, NULL, n_e->n1, rsa_d->b, ctx) && wr_err("Error\n", "Impossible to calculate p\n"))
		return (free_rsa(2, rsa_d));
	if (bn2dec_print("p", rsa_d->a) && wr_err("Error\n", "p not printed\n"))
		return (free_rsa(2, rsa_d));
	return (0);
}


int	ft_break_rsa(mod_exp_t	*n_e, BN_CTX *ctx)
{
	int	bits;
	rsa_data_t	rsa_d;

	bits = 0;
	rsa_d = (rsa_data_t){.a = NULL, .b = NULL, .d = NULL, .p1 = NULL, .q1 = NULL,
		.dmp1 = NULL, .dmq1 = NULL, .iqmp = NULL, .phi = NULL, .key = NULL};
	printf("----------------  %sBreaking RSA%s  ------------------\n", GREEN_B_U, WHITE);
	if (get_primes(&rsa_d, n_e, ctx))
		return	free_ctx_ne(6, ctx, n_e);
	printf("----------------------------------\n\n\n");

	printf("----------------  %sGenerating Private Key%s  ------------------\n", GREEN_B_U, WHITE);
	if (create_private_key(&rsa_d, n_e, ctx))
		return (1);
	printf("----------------------------------\n\n\n");

	printf("----------------  %sEncrypting Message%s  ------------------\n", GREEN_B_U, WHITE);
	bits = BN_num_bits(n_e->n1);
	if (bits != 512 && wr_err("Size error\n", "RSA size must be 512\n"))
		return (free_breaking(2, n_e, &rsa_d, NULL));
	printf("Insert here your text (%d bits max.) to be encrypted:\n", bits);
//Estoy aquí
	if (encrypting(n_e, &rsa_d, ctx, bits))
		return (1);
	printf("----------------------------------\n\n\n");
	return (0);
}

int	init_ctx_and_ne(BN_CTX	*ctx, mod_exp_t	*n_e)
{
	//Init ctx
	if (ctx == NULL && wr_err("Error\n", "ctx not initialized\n"))
		return	free_ctx_ne(0, ctx, n_e);

	//Init n and e
	n_e->n1 = BN_new ();
	if (n_e->n1 == NULL && wr_err("Error\n", "n1 not initialized\n"))
		return	free_ctx_ne(1, ctx, n_e);
	n_e->n2 = BN_new ();
	if (n_e->n2 == NULL && wr_err("Error\n", "n2 not initialized\n"))
		return	free_ctx_ne(2, ctx, n_e);
	n_e->e1 = BN_new ();
	if (n_e->e1 == NULL && wr_err("Error\n", "e1 not initialized\n"))
		return	free_ctx_ne(3, ctx, n_e);
	n_e->e2 = BN_new ();
	if (n_e->e2 == NULL && wr_err("Error\n", "e2 not initialized\n"))
		return	free_ctx_ne(4, ctx, n_e);
	return (0);
}

int	main(int argc, char **argv)
{
	mod_exp_t	n_e;

	n_e = (mod_exp_t){.n1 = NULL, .n2 = NULL, .e1 = NULL, .e2 = NULL};

	//Error Handling
	if (error_handling(argc))
		return (1);

	//Configure CTX
	BN_CTX	*ctx = NULL;
	ctx = BN_CTX_new();
	if (init_ctx_and_ne(ctx, &n_e))
		return	(1);

	//Getting module and exponent
	if (ft_get_module_exponent(argv[1], n_e.n1, n_e.e1))
		return	(free_ctx_ne(5, ctx, &n_e));
	if (ft_get_module_exponent(argv[2], n_e.n2, n_e.e2))
		return	(free_ctx_ne(5, ctx, &n_e));


// TO DO COMPROBADO Y PERFECTO HASTA AQUÍ

	//Breaking RSA
	if (ft_break_rsa(&n_e, ctx))
	{
		BN_CTX_free(ctx);
		return	(1);
	}

	return 0;
}
